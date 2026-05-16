package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/provisioning"

	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/store"
)

type testMailer struct {
	sent []MailMessage
}

func (m *testMailer) Send(_ context.Context, message MailMessage) error {
	m.sent = append(m.sent, message)
	return nil
}

func newTestService(t *testing.T) (*Service, *miniredis.Miniredis, *testMailer) {
	t.Helper()

	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("store.OpenDB() error = %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("store.AutoMigrate() error = %v", err)
	}

	mini := miniredis.RunT(t)
	redisClient, err := cache.OpenRedis(config.Config{
		RedisURL: "redis://" + mini.Addr() + "/0",
	})
	if err != nil {
		t.Fatalf("cache.OpenRedis() error = %v", err)
	}
	t.Cleanup(func() {
		_ = redisClient.Close()
	})

	mailer := &testMailer{}
	service := NewService(db, redisClient, mailer)
	return service, mini, mailer
}

func TestSendEmailCodeStoresCodeWithTTL(t *testing.T) {
	service, mini, mailer := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "user@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}

	key := cache.EmailCodeKey(EmailCodePurposeRegister, "user@example.com")
	got, err := mini.Get(key)
	if err != nil {
		t.Fatalf("mini.Get() error = %v", err)
	}
	if got != code {
		t.Fatalf("stored code = %q, want %q", got, code)
	}
	if ttl := mini.TTL(key); ttl != 10*time.Minute {
		t.Fatalf("TTL = %v, want 10m", ttl)
	}
	if len(mailer.sent) != 1 {
		t.Fatalf("sent email count = %d, want 1", len(mailer.sent))
	}
}

func TestRegisterRequiresValidEmailCode(t *testing.T) {
	service, _, _ := newTestService(t)

	_, err := service.Register(context.Background(), RegisterInput{
		Email:       "user@example.com",
		DisplayName: "user",
		Password:    "p@ssw0rd!",
		EmailCode:   "123456",
		CodePurpose: EmailCodePurposeRegister,
	})
	if err == nil {
		t.Fatal("expected Register() without valid email code to fail")
	}
}

func TestRegisterRejectsDuplicateEmail(t *testing.T) {
	service, _, _ := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "dup@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}
	if _, err := service.Register(context.Background(), RegisterInput{
		Email:       "dup@example.com",
		DisplayName: "first",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	}); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	secondCode, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "dup@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() second error = %v", err)
	}
	if _, err := service.Register(context.Background(), RegisterInput{
		Email:       "dup@example.com",
		DisplayName: "second",
		Password:    "p@ssw0rd!",
		EmailCode:   secondCode,
		CodePurpose: EmailCodePurposeRegister,
	}); err == nil {
		t.Fatal("expected duplicate Register() to fail")
	}
}

func TestRegisterNormalizesBlankCodePurpose(t *testing.T) {
	service, mini, _ := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "normalized@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}

	user, err := service.Register(context.Background(), RegisterInput{
		Email:       "normalized@example.com",
		DisplayName: "normalized",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: "",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if user.Email != "normalized@example.com" {
		t.Fatalf("email = %q, want normalized@example.com", user.Email)
	}
	if mini.Exists(cache.EmailCodeKey(EmailCodePurposeRegister, "normalized@example.com")) {
		t.Fatal("expected normalized register code to be deleted after successful registration")
	}
}

func TestRegisterAppliesDefaultMembershipPolicy(t *testing.T) {
	service, _, _ := newTestService(t)
	service.SetAuditRecorder(audit.NewService(service.db))
	tenantRecord := store.Tenant{Name: "Public App", Slug: "public-app", Status: store.TenantStatusActive}
	if err := service.db.Create(&tenantRecord).Error; err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	service.SetDefaultMembershipPolicy(provisioning.NewDefaultMembershipPolicy([]string{"public-app"}))

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "member@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}

	user, err := service.Register(context.Background(), RegisterInput{
		Email:       "member@example.com",
		DisplayName: "member",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	var count int64
	if err := service.db.Model(&store.TenantMember{}).
		Where("tenant_id = ? AND user_id = ? AND status = ?", tenantRecord.ID, user.ID, store.MemberStatusActive).
		Count(&count).Error; err != nil {
		t.Fatalf("count tenant members: %v", err)
	}
	if count != 1 {
		t.Fatalf("active tenant member count = %d, want 1", count)
	}

	if err := service.db.Model(&store.AuditLog{}).
		Where("action = ? AND tenant_id = ?", audit.ActionTenantMembershipAdded, tenantRecord.ID).
		Count(&count).Error; err != nil {
		t.Fatalf("count membership audit logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("membership audit log count = %d, want 1", count)
	}
}

func TestLoginRejectsDisabledUser(t *testing.T) {
	service, _, _ := newTestService(t)

	hash, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	user := store.User{
		Email:        "disabled@example.com",
		DisplayName:  "disabled",
		PasswordHash: hash,
		Status:       store.UserStatusDisabled,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create disabled user: %v", err)
	}

	if _, err := service.Login(context.Background(), LoginInput{
		Email:    "disabled@example.com",
		Password: "p@ssw0rd!",
	}); err == nil {
		t.Fatal("expected disabled user login to fail")
	}
}

func TestLoginWritesAuditLog(t *testing.T) {
	service, _, _ := newTestService(t)
	service.SetAuditRecorder(audit.NewService(service.db))

	hash, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	user := store.User{
		Email:        "active@example.com",
		DisplayName:  "active",
		PasswordHash: hash,
		Status:       store.UserStatusActive,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	if _, err := service.Login(context.Background(), LoginInput{
		Email:    user.Email,
		Password: "p@ssw0rd!",
	}); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	var count int64
	if err := service.db.Model(&store.AuditLog{}).Where("action = ?", audit.ActionLogin).Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("login audit log count = %d, want 1", count)
	}
}

func TestRegisterRequiresUniqueUsername(t *testing.T) {
	service, _, _ := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "user1@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}
	if _, err := service.Register(context.Background(), RegisterInput{
		Username:    "kamuii",
		Nickname:    "卡密",
		Email:       "user1@example.com",
		DisplayName: "卡密",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	}); err != nil {
		t.Fatalf("first Register() error = %v", err)
	}

	code2, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "user2@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() second error = %v", err)
	}
	_, err = service.Register(context.Background(), RegisterInput{
		Username:    "kamuii",
		Nickname:    "卡密2",
		Email:       "user2@example.com",
		DisplayName: "卡密2",
		Password:    "p@ssw0rd!",
		EmailCode:   code2,
		CodePurpose: EmailCodePurposeRegister,
	})
	if err == nil {
		t.Fatal("expected duplicate username Register() to fail")
	}
}

func TestRegisterTreatsDisplayNameAsNicknameAlias(t *testing.T) {
	service, _, _ := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "named@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}
	user, err := service.Register(context.Background(), RegisterInput{
		Username:    "named-user",
		Nickname:    "张三",
		Email:       "named@example.com",
		DisplayName: "张三Display",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if user.Username != "named-user" {
		t.Fatalf("username = %q, want %q", user.Username, "named-user")
	}
	if user.Nickname != "张三" {
		t.Fatalf("nickname = %q, want %q", user.Nickname, "张三")
	}
	if user.DisplayName != user.Nickname {
		t.Fatalf("display_name = %q, want alias of nickname %q", user.DisplayName, user.Nickname)
	}
}

func TestLoginAcceptsUsernameIdentifier(t *testing.T) {
	service, _, _ := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "ident@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}
	if _, err := service.Register(context.Background(), RegisterInput{
		Username:    "identifier-test",
		Nickname:    "Ident Test",
		Email:       "ident@example.com",
		DisplayName: "Ident Test",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	user, err := service.Login(context.Background(), LoginInput{
		Identifier: "identifier-test",
		Password:   "p@ssw0rd!",
	})
	if err != nil {
		t.Fatalf("Login() with username identifier error = %v", err)
	}
	if user == nil {
		t.Fatal("expected user from login")
	}
}

func TestLoginAcceptsEmailIdentifier(t *testing.T) {
	service, _, _ := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "ident2@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}
	if _, err := service.Register(context.Background(), RegisterInput{
		Username:    "ident2-user",
		Nickname:    "Ident2",
		Email:       "ident2@example.com",
		DisplayName: "Ident2",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	user, err := service.Login(context.Background(), LoginInput{
		Identifier: "ident2@example.com",
		Password:   "p@ssw0rd!",
	})
	if err != nil {
		t.Fatalf("Login() with email identifier error = %v", err)
	}
	if user == nil {
		t.Fatal("expected user from login")
	}
}

func TestLoginAcceptsLegacyEmailField(t *testing.T) {
	service, _, _ := newTestService(t)

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "legacy@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}
	if _, err := service.Register(context.Background(), RegisterInput{
		Username:    "legacy-user",
		Nickname:    "Legacy",
		Email:       "legacy@example.com",
		DisplayName: "Legacy",
		Password:    "p@ssw0rd!",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	user, err := service.Login(context.Background(), LoginInput{
		Email:    "legacy@example.com",
		Password: "p@ssw0rd!",
	})
	if err != nil {
		t.Fatalf("Login() with legacy email field error = %v", err)
	}
	if user == nil {
		t.Fatal("expected user from legacy login")
	}
}

func TestResetPasswordWritesAuditLog(t *testing.T) {
	service, _, _ := newTestService(t)
	service.SetAuditRecorder(audit.NewService(service.db))

	code, err := service.SendEmailCode(context.Background(), EmailCodePurposeRegister, "reset@example.com")
	if err != nil {
		t.Fatalf("SendEmailCode() error = %v", err)
	}
	user, err := service.Register(context.Background(), RegisterInput{
		Email:       "reset@example.com",
		DisplayName: "reset",
		Password:    "old-password",
		EmailCode:   code,
		CodePurpose: EmailCodePurposeRegister,
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	resetCode, err := service.SendEmailCode(context.Background(), EmailCodePurposePasswordReset, user.Email)
	if err != nil {
		t.Fatalf("SendEmailCode(reset) error = %v", err)
	}
	if err := service.ResetPassword(context.Background(), ResetPasswordInput{
		Email:       user.Email,
		NewPassword: "new-password",
		EmailCode:   resetCode,
	}); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}

	var count int64
	if err := service.db.Model(&store.AuditLog{}).Where("action = ?", audit.ActionPasswordReset).Count(&count).Error; err != nil {
		t.Fatalf("count audit logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("password reset audit log count = %d, want 1", count)
	}
}
