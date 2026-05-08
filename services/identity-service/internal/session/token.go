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

	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var (
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenReuse   = errors.New("refresh token reuse detected")
)

type Service struct {
	db              *gorm.DB
	privateKey      *rsa.PrivateKey
	keyID           string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	now             func() time.Time
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
	TenantID      int64    `json:"tid"`
	SessionID     string   `json:"sid"`
	TokenVersion  int      `json:"ver"`
	jwt.RegisteredClaims
}

func NewService(db *gorm.DB, cfg config.Config, privateKey *rsa.PrivateKey) *Service {
	return &Service{
		db:              db,
		privateKey:      privateKey,
		keyID:           cfg.JWTKeyID,
		accessTokenTTL:  cfg.AccessTokenTTL,
		refreshTokenTTL: cfg.RefreshTokenTTL,
		now:             time.Now,
	}
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

	return s.issueTokenPair(ctx, input.User, input.TenantID, input.ClientID, sessionID, familyID)
}

func (s *Service) issueTokenPair(ctx context.Context, user store.User, tenantID int64, clientID, sessionID, familyID string) (*TokenPair, error) {
	accessToken, err := s.signAccessToken(user, tenantID, clientID, sessionID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := randomID(32)
	if err != nil {
		return nil, err
	}

	record := store.RefreshToken{
		TokenHash: hashToken(refreshToken),
		FamilyID:  familyID,
		SessionID: sessionID,
		UserID:    user.ID,
		TenantID:  tenantID,
		ClientID:  clientID,
		ExpiresAt: s.now().Add(s.refreshTokenTTL),
	}
	if err := s.db.WithContext(ctx).Create(&record).Error; err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    sessionID,
	}, nil
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
