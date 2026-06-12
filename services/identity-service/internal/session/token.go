// Package session manages JWT access/refresh token issuance, rotation,
// revocation, and the AuthMiddleware that validates tokens on every request.
package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/jwtkey"
	"goauth/services/identity-service/internal/logout"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse detected")
)

// accessTokenUseSession marks tokens issued for browser/login sessions, as
// opposed to OAuth2 client_credentials or other token-use values.
const accessTokenUseSession = "session"

type Service struct {
	db                  *gorm.DB
	sessions            store.SessionRepository
	privateKey          *rsa.PrivateKey
	keyring             *jwtkey.Keyring
	keyID               string
	accessTokenTTL      time.Duration
	browserSessionTTL   time.Duration
	browserCookieSecure bool
	refreshTokenTTL     time.Duration
	audit               audit.Recorder
	logoutCoordinator   *logout.Coordinator
	now                 func() time.Time // overridable for tests
}

type IssueTokensInput struct {
	User     store.User
	TenantID int64
	ClientID string
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
}

// accessClaims is the JWT body for session access tokens. TokenVersion is
// stamped from store.User.TokenVersion at issue time; validators reject tokens
// whose version is below the user's current version, giving us O(1) global
// session invalidation (logout-all, password change) without a blocklist.
type accessClaims struct {
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Roles         []string `json:"roles,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	TokenUse      string   `json:"token_use"`
	TenantID      int64    `json:"tid"`
	SessionID     string   `json:"sid"`
	TokenVersion  int      `json:"ver"`
	jwt.RegisteredClaims
}

// Dependencies holds optional collaborators for session.Service.
// Zero values default to noop implementations where safe.
type Dependencies struct {
	Sessions          store.SessionRepository
	Audit             audit.Recorder
	LogoutCoordinator *logout.Coordinator
}

func NewService(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) *Service {
	var keyring *jwtkey.Keyring
	if privateKey != nil {
		keyring, _ = jwtkey.NewKeyring(cfg.JWTKeyID, map[string]*rsa.PrivateKey{cfg.JWTKeyID: privateKey})
	}
	return NewServiceWithKeyringAndDeps(db, cfg, keyring, Dependencies{})
}

func NewServiceWithKeyring(db *gorm.DB, cfg config.Config, keyring *jwtkey.Keyring) *Service {
	return NewServiceWithKeyringAndDeps(db, cfg, keyring, Dependencies{})
}

// NewServiceWithKeyringAndDeps creates a fully-wired session.Service.
func NewServiceWithKeyringAndDeps(db *gorm.DB, cfg config.Config, keyring *jwtkey.Keyring, deps Dependencies) *Service {
	privateKey := (*rsa.PrivateKey)(nil)
	keyID := cfg.JWTKeyID
	if keyring != nil {
		privateKey = keyring.ActivePrivateKey()
		keyID = keyring.ActiveKeyID()
	}
	auditRecorder := deps.Audit
	if auditRecorder == nil {
		auditRecorder = audit.NoopRecorder{}
	}
	return &Service{
		db:                  db,
		privateKey:          privateKey,
		keyring:             keyring,
		keyID:               keyID,
		accessTokenTTL:      cfg.AccessTokenTTL,
		browserSessionTTL:   cfg.BrowserSessionTTL,
		browserCookieSecure: cfg.BrowserCookieSecure,
		refreshTokenTTL:     cfg.RefreshTokenTTL,
		sessions:            deps.Sessions,
		audit:               auditRecorder,
		logoutCoordinator:   deps.LogoutCoordinator,
		now:                 time.Now,
	}
}

// SetSessionRepository injects the session persistence layer. Prefer constructor
// injection once Phase 2 (eliminate setters) is complete.
// DB exposes the underlying *gorm.DB for migration-compatible access.
func (s *Service) DB() *gorm.DB { return s.db }
func (s *Service) SetSessionRepository(repo store.SessionRepository) {
	s.sessions = repo
}

func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

func (s *Service) SetLogoutCoordinator(c *logout.Coordinator) {
	s.logoutCoordinator = c
}

// LoadRSAPrivateKey accepts either PKCS#1 ("RSA PRIVATE KEY") or PKCS#8
// ("PRIVATE KEY") PEM encodings — operators generate keys with different
// tools, so we try PKCS#1 first and fall back to PKCS#8.
func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("decode private key pem: no block found")
	}

	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return privateKey, nil
}

// IssueTokens starts a brand-new login: it creates a LoginSession row plus the
// first refresh token of a new family. Subsequent refreshes reuse the same
// session/family IDs so that reuse detection can revoke the entire chain.
func (s *Service) IssueTokens(ctx context.Context, input IssueTokensInput) (*TokenPair, error) {
	sessionID, err := randomID(16)
	if err != nil {
		return nil, err
	}
	familyID, err := randomID(16)
	if err != nil {
		return nil, err
	}

	var pair *TokenPair
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		loginSession := store.LoginSession{
			ID:       sessionID,
			UserID:   input.User.ID,
			TenantID: input.TenantID,
			ClientID: input.ClientID,
		}
		if err := tx.WithContext(ctx).Create(&loginSession).Error; err != nil {
			return err
		}

		nextPair, err := s.issueTokenPairWithDB(ctx, tx, input.User, input.TenantID, input.ClientID, sessionID, familyID)
		if err != nil {
			return err
		}
		pair = nextPair
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pair, nil
}

func (s *Service) signAccessToken(user store.User, tenantID int64, clientID, sessionID string) (string, error) {
	issuedAt := s.now()
	jti, err := randomID(16)
	if err != nil {
		return "", err
	}

	claims := accessClaims{
		Email:         user.Email,
		EmailVerified: user.EmailVerifiedAt != nil,
		TokenUse:      accessTokenUseSession,
		TenantID:      tenantID,
		SessionID:     sessionID,
		TokenVersion:  user.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(s.accessTokenTTL)),
			Subject:   strconv.FormatInt(user.ID, 10),
			Audience:  []string{clientID},
			ID:        jti,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	return token.SignedString(s.privateKey)
}

func randomID(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Service) RefreshTokenTTL() time.Duration {
	return s.refreshTokenTTL
}

// OIDCAuthorizeCookieTTL returns the lifetime of the browser SSO cookie. It
// falls through configured TTLs (browser > access > refresh) so deployments
// that only set one knob still get a sensible cookie lifetime; the 12h default
// matches the documented BROWSER_SESSION_TTL fallback in .env.example.
func (s *Service) OIDCAuthorizeCookieTTL() time.Duration {
	if s.browserSessionTTL > 0 {
		return s.browserSessionTTL
	}
	if s.accessTokenTTL > 0 {
		return s.accessTokenTTL
	}
	if s.refreshTokenTTL > 0 {
		return s.refreshTokenTTL
	}
	return 12 * time.Hour
}
