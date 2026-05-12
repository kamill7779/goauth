package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/store"
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
		JWTKeyID:            "test-key",
		AccessTokenTTL:      15 * time.Minute,
		BrowserSessionTTL:   12 * time.Hour,
		RefreshTokenTTL:     30 * 24 * time.Hour,
		BrowserCookieSecure: true,
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
	if claims["token_use"] != accessTokenUseSession {
		t.Fatalf("token_use = %v, want %q", claims["token_use"], accessTokenUseSession)
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

func TestIssueTokensCreatesActiveLoginSession(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 42,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	var loginSession store.LoginSession
	if err := service.db.First(&loginSession, "id = ?", pair.SessionID).Error; err != nil {
		t.Fatalf("load login session: %v", err)
	}
	if loginSession.UserID != user.ID || loginSession.TenantID != 42 || loginSession.ClientID != "web-client" {
		t.Fatalf("login session = %#v, want user/tenant/client metadata", loginSession)
	}
	if loginSession.RevokedAt != nil {
		t.Fatal("new login session should be active")
	}
}

func TestIssueOIDCAuthorizeCookieUsesBrowserSessionExpiry(t *testing.T) {
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
	if got != service.OIDCAuthorizeCookieTTL() {
		t.Fatalf("cookie ttl = %s, want %s", got, service.OIDCAuthorizeCookieTTL())
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

func TestConcurrentRefreshHasSingleWinnerAndRevokesFamilyOnReuse(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	const attempts = 8
	start := make(chan struct{})
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := service.Refresh(context.Background(), pair.RefreshToken)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	reuseFailures := 0
	for err := range results {
		if err == nil {
			successes++
			continue
		}
		if errors.Is(err, ErrRefreshTokenReuse) {
			reuseFailures++
			continue
		}
		t.Fatalf("Refresh() error = %v, want success or ErrRefreshTokenReuse", err)
	}
	if successes != 1 {
		t.Fatalf("successful refreshes = %d, want 1", successes)
	}
	if reuseFailures != attempts-1 {
		t.Fatalf("reuse failures = %d, want %d", reuseFailures, attempts-1)
	}

	var activeCount int64
	if err := service.db.Model(&store.RefreshToken{}).
		Where("family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = ?) AND revoked_at IS NULL", hashToken(pair.RefreshToken)).
		Count(&activeCount).Error; err != nil {
		t.Fatalf("count active family tokens: %v", err)
	}
	if activeCount != 0 {
		t.Fatalf("active family tokens = %d, want 0 after concurrent reuse", activeCount)
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

	var loginSession store.LoginSession
	if err := service.db.First(&loginSession, "id = ?", pair.SessionID).Error; err != nil {
		t.Fatalf("load login session: %v", err)
	}
	if loginSession.RevokedAt == nil {
		t.Fatal("expected login session to be revoked")
	}
}

func TestRefreshRejectsRevokedLoginSession(t *testing.T) {
	service, user := newTestService(t)

	pair, err := service.IssueTokens(context.Background(), IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "web-client",
	})
	if err != nil {
		t.Fatalf("IssueTokens() error = %v", err)
	}

	now := time.Now().UTC()
	if err := service.db.Model(&store.LoginSession{}).
		Where("id = ?", pair.SessionID).
		Update("revoked_at", now).Error; err != nil {
		t.Fatalf("revoke login session: %v", err)
	}

	if _, err := service.Refresh(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("expected revoked login session to reject refresh")
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

func TestLogoutAllWritesAuditLog(t *testing.T) {
	service, user := newTestService(t)
	service.SetAuditRecorder(audit.NewService(service.db))

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

	var log store.AuditLog
	if err := service.db.
		Where("action = ? AND target_type = ?", audit.ActionLogout, audit.TargetTypeUser).
		First(&log).Error; err != nil {
		t.Fatalf("load audit log: %v", err)
	}
	if log.TargetID != audit.UserTargetID(user.ID) {
		t.Fatalf("log.TargetID = %q, want %q", log.TargetID, audit.UserTargetID(user.ID))
	}

	var metadata map[string]any
	if err := auditMetadata(log, &metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if metadata["scope"] != "all_sessions" {
		t.Fatalf("metadata scope = %v, want all_sessions", metadata["scope"])
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

func TestRefreshRejectsDisabledTenant(t *testing.T) {
	service, user := newTestService(t)
	tenantRecord := createTenantAndMember(t, service, user.ID)
	pair := issueSessionPair(t, service, *user, tenantRecord.ID)

	if err := service.db.Model(&store.Tenant{}).
		Where("id = ?", tenantRecord.ID).
		Update("status", store.TenantStatusDisabled).Error; err != nil {
		t.Fatalf("disable tenant: %v", err)
	}

	if _, err := service.Refresh(context.Background(), pair.RefreshToken); err == nil {
		t.Fatal("expected disabled tenant to fail")
	}
}

func TestIsSystemUserRecognizesSystemRole(t *testing.T) {
	service, user := newTestService(t)
	tenantRecord := createTenantAndMember(t, service, user.ID)

	var member store.TenantMember
	if err := service.db.
		Where("tenant_id = ? AND user_id = ?", tenantRecord.ID, user.ID).
		First(&member).Error; err != nil {
		t.Fatalf("load member: %v", err)
	}
	role := store.Role{
		TenantID:  tenantRecord.ID,
		Name:      "System Admin",
		Code:      "system-admin",
		IsSystem:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := service.db.Create(&role).Error; err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := service.db.Create(&store.MemberRole{MemberID: member.ID, RoleID: role.ID}).Error; err != nil {
		t.Fatalf("create member role: %v", err)
	}

	ok, err := service.isSystemUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("isSystemUser() error = %v", err)
	}
	if !ok {
		t.Fatal("expected system role user to be recognized")
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

func auditMetadata(log store.AuditLog, target *map[string]any) error {
	return json.Unmarshal(log.Metadata, target)
}
