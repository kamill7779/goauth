package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"example.com/identity-service/internal/audit"
	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

func newTestService(t *testing.T) (*Service, *store.User) {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	service := NewService(db, config.Config{
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}, privateKey)

	user := &store.User{
		Email:        "user@example.com",
		DisplayName:  "user",
		PasswordHash: "hash",
		Status:       store.UserStatusActive,
		TokenVersion: 3,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("db.Create(user) error = %v", err)
	}

	return service, user
}

func TestIssueTokensIncludesExpectedAccessClaims(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 42,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	token, err := jwt.Parse(pair.AccessToken, func(token *jwt.Token) (any, error) {
		return &service.privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["sub"] != "1" {
		t.Fatalf("sub = %v, want 1", claims["sub"])
	}
	if claims["sid"] == "" {
		t.Fatal("sid is empty")
	}
	if claims["tid"] != float64(42) {
		t.Fatalf("tid = %v, want 42", claims["tid"])
	}
	if aud, ok := claims["aud"].([]any); !ok || len(aud) != 1 || aud[0] != "web-client" {
		t.Fatalf("aud = %#v, want [web-client]", claims["aud"])
	}
	if claims["jti"] == "" {
		t.Fatal("jti is empty")
	}
	if claims["ver"] != float64(3) {
		t.Fatalf("ver = %v, want 3", claims["ver"])
	}
}

func TestIssueTokensStoresRefreshTokenAsHashOnly(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	var refreshToken store.RefreshToken
	if err := service.db.First(&refreshToken).Error; err != nil {
		t.Fatalf("load refresh token: %v", err)
	}
	if refreshToken.TokenHash == pair.RefreshToken {
		t.Fatal("refresh token stored in plaintext")
	}
}

func TestIssueOIDCAuthorizeCookieUsesShortLivedExpiry(t *testing.T) {
	service, user := newTestService(t)

	value, err := service.IssueOIDCAuthorizeCookie(*user, 42, "browser-session")
	if err != nil {
		t.Fatalf("IssueOIDCAuthorizeCookie() error = %v", err)
	}

	claims, err := ParseOIDCAuthorizeCookie(value, &service.privateKey.PublicKey)
	if err != nil {
		t.Fatalf("ParseOIDCAuthorizeCookie() error = %v", err)
	}
	if claims.SessionID != "browser-session" {
		t.Fatalf("SessionID = %q, want browser-session", claims.SessionID)
	}
	if claims.ExpiresAt == nil || claims.IssuedAt == nil {
		t.Fatal("expected issued and expiry timestamps")
	}

	got := claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time)
	if got != service.accessTokenTTL {
		t.Fatalf("cookie ttl = %s, want %s", got, service.accessTokenTTL)
	}
}

func TestRefreshRotatesToken(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	rotated, err := service.Refresh(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if rotated.RefreshToken == pair.RefreshToken {
		t.Fatal("expected rotated refresh token to differ from original")
	}

	var tokens []store.RefreshToken
	if err := service.db.Order("id asc").Find(&tokens).Error; err != nil {
		t.Fatalf("load refresh tokens: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("refresh token count = %d, want 2", len(tokens))
	}
	if tokens[0].RevokedAt == nil {
		t.Fatal("expected original refresh token to be revoked")
	}
}

func TestReusingRotatedTokenRevokesFamily(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	rotated, err := service.Refresh(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, err := service.Refresh(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("expected reused refresh token to fail")
	}

	var current store.RefreshToken
	if err := service.db.Where("token_hash = ?", hashToken(rotated.RefreshToken)).First(&current).Error; err != nil {
		t.Fatalf("load current refresh token: %v", err)
	}
	if current.RevokedAt == nil {
		t.Fatal("expected token family to be revoked after reuse")
	}
}

func TestLogoutRevokesSingleSession(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	if err := service.Logout(context.Background(), pair.SessionID); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	var refreshToken store.RefreshToken
	if err := service.db.Where("session_id = ?", pair.SessionID).First(&refreshToken).Error; err != nil {
		t.Fatalf("load refresh token: %v", err)
	}
	if refreshToken.RevokedAt == nil {
		t.Fatal("expected session refresh token to be revoked")
	}
}

func TestLogoutAllIncrementsUserTokenVersion(t *testing.T) {
	service, user := newTestService(t)

	if _, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 42,
		ClientID: "web-client",
	}); err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	if err := service.LogoutAll(context.Background(), user.ID); err != nil {
		t.Fatalf("LogoutAll() error = %v", err)
	}

	var updated store.User
	if err := service.db.First(&updated, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if updated.TokenVersion != user.TokenVersion+1 {
		t.Fatalf("TokenVersion = %d, want %d", updated.TokenVersion, user.TokenVersion+1)
	}
}

func TestLogoutWritesAuditLog(t *testing.T) {
	service, user := newTestService(t)
	service.SetAuditRecorder(audit.NewService(service.db))

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 42,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	if err := service.Logout(context.Background(), pair.SessionID); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}

	var count int64
	if err := service.db.Model(&store.AuditLog{}).Where("action = ?", audit.ActionLogout).Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("logout audit log count = %d, want 1", count)
	}
}

func TestRefreshReuseWritesAuditLog(t *testing.T) {
	service, user := newTestService(t)
	service.SetAuditRecorder(audit.NewService(service.db))

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	if _, err := service.Refresh(context.Background(), pair.RefreshToken); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, err := service.Refresh(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("expected reused refresh token to fail")
	}

	var count int64
	if err := service.db.Model(&store.AuditLog{}).Where("action = ?", audit.ActionRefreshTokenReuseDetected).Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("refresh reuse audit log count = %d, want 1", count)
	}
}

func TestRefreshRejectsStaleTokenVersion(t *testing.T) {
	service, user := newTestService(t)
	tenantRecord := createTenantAndMember(t, service, user.ID)
	pair := issueSessionPair(t, service, *user, tenantRecord.ID)

	if err := service.db.Model(&store.User{}).Where("id = ?", user.ID).
		Update("token_version", gorm.Expr("token_version + 1")).Error; err != nil {
		t.Fatalf("bump token version: %v", err)
	}

	if _, err := service.Refresh(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("expected stale token version to fail")
	}
}

func TestRefreshRejectsDisabledMembership(t *testing.T) {
	service, user := newTestService(t)
	tenantRecord := createTenantAndMember(t, service, user.ID)
	pair := issueSessionPair(t, service, *user, tenantRecord.ID)

	if err := service.db.Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ?", tenantRecord.ID, user.ID).
		Update("status", store.MemberStatusDisabled).Error; err != nil {
		t.Fatalf("disable member: %v", err)
	}

	if _, err := service.Refresh(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("expected disabled membership to fail")
	}
}

func createTenantAndMember(t *testing.T, service *Service, userID int64) store.Tenant {
	t.Helper()

	tenantRecord := store.Tenant{
		Name:   "Acme",
		Slug:   "acme",
		Status: store.TenantStatusActive,
	}
	if err := service.db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	member := store.TenantMember{
		TenantID: tenantRecord.ID,
		UserID:   userID,
		Status:   store.MemberStatusActive,
	}
	if err := service.db.Create(&member).Error; err != nil {
		t.Fatalf("create member: %v", err)
	}
	return tenantRecord
}
