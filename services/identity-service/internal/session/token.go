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
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse detected")
)

const accessTokenUseSession = "session"

type Service struct {
	db                *gorm.DB
	privateKey        *rsa.PrivateKey
	keyID             string
	accessTokenTTL    time.Duration
	browserSessionTTL time.Duration
	refreshTokenTTL   time.Duration
	audit             audit.Recorder
	now               func() time.Time
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

func NewService(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) *Service {
	return &Service{
		db:                db,
		privateKey:        privateKey,
		keyID:             cfg.JWTKeyID,
		accessTokenTTL:    cfg.AccessTokenTTL,
		browserSessionTTL: cfg.BrowserSessionTTL,
		refreshTokenTTL:   cfg.RefreshTokenTTL,
		audit:             audit.NoopRecorder{},
		now:               time.Now,
	}
}

func (s *Service) SetAuditRecorder(recorder audit.Recorder) {
	if recorder == nil {
		s.audit = audit.NoopRecorder{}
		return
	}
	s.audit = recorder
}

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
