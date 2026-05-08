package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"example.com/identity-service/internal/cache"
	"example.com/identity-service/internal/config"
	"example.com/identity-service/internal/store"
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
