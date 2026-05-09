package store

import (
	"context"
	"os"
	"testing"
	"time"

	"goauth/services/identity-service/internal/config"
)

func TestOpenDBFallsBackToSQLiteAndMigratesTables(t *testing.T) {
	cfg := config.Config{}

	db, err := OpenDB(cfg)
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	for _, model := range []any{
		&User{},
		&Tenant{},
		&TenantMember{},
		&Role{},
		&OAuthClient{},
		&LoginSession{},
		&RefreshToken{},
		&AuditLog{},
	} {
		if !db.Migrator().HasTable(model) {
			t.Fatalf("expected table for %T to exist", model)
		}
	}
	if !db.Migrator().HasColumn(&TenantMember{}, "permission_version") {
		t.Fatal("expected tenant_members.permission_version column to exist")
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB() error = %v", err)
	}
	defer func() {
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("sqlDB.Close() error = %v", err)
		}
	}()
}

func TestAutoMigrateBackfillsLoginSessionsFromExistingRefreshTokens(t *testing.T) {
	db, err := OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	if err := db.AutoMigrate(&User{}, &RefreshToken{}); err != nil {
		t.Fatalf("legacy AutoMigrate() error = %v", err)
	}

	user := User{
		Email:        "legacy-session@example.com",
		DisplayName:  "legacy",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	createdAt := time.Now().UTC().Add(-time.Hour)
	token := RefreshToken{
		TokenHash:    "legacy-token-hash",
		FamilyID:     "legacy-family",
		SessionID:    "legacy-session",
		UserID:       user.ID,
		TenantID:     42,
		TokenVersion: user.TokenVersion,
		ClientID:     "web-client",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		CreatedAt:    createdAt,
	}
	if err := db.Create(&token).Error; err != nil {
		t.Fatalf("create legacy refresh token: %v", err)
	}
	if db.Migrator().HasTable(&LoginSession{}) {
		t.Fatal("legacy setup should not have login_sessions table yet")
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	var loginSession LoginSession
	if err := db.First(&loginSession, "id = ?", "legacy-session").Error; err != nil {
		t.Fatalf("load backfilled login session: %v", err)
	}
	if loginSession.UserID != user.ID || loginSession.TenantID != 42 || loginSession.ClientID != "web-client" {
		t.Fatalf("loginSession = %#v, want backfilled metadata", loginSession)
	}
}

func TestAutoMigrateBackfillsLoginSessionsOnConfiguredMySQL(t *testing.T) {
	dsn := os.Getenv("MYSQL_DSN_TEST")
	if dsn == "" {
		t.Skip("MYSQL_DSN_TEST not set")
	}

	db, err := OpenDB(config.Config{MySQLDSN: dsn})
	if err != nil {
		t.Fatalf("OpenDB(mysql) error = %v", err)
	}
	if err := db.Migrator().DropTable(
		&AuditLog{},
		&ExternalProviderConfig{},
		&RefreshToken{},
		&LoginSession{},
		&OAuthAuthorizationCode{},
		&OAuthClient{},
		&MemberRole{},
		&RolePermission{},
		&Permission{},
		&Role{},
		&TenantMember{},
		&Tenant{},
		&UserIdentity{},
		&User{},
	); err != nil {
		t.Fatalf("drop legacy tables: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &RefreshToken{}); err != nil {
		t.Fatalf("legacy AutoMigrate(mysql) error = %v", err)
	}

	user := User{
		Email:        "legacy-mysql-session@example.com",
		DisplayName:  "legacy mysql",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create mysql user: %v", err)
	}
	token := RefreshToken{
		TokenHash:    "legacy-mysql-token-hash",
		FamilyID:     "legacy-mysql-family",
		SessionID:    "legacy-mysql-session",
		UserID:       user.ID,
		TenantID:     7,
		TokenVersion: user.TokenVersion,
		ClientID:     "mysql-client",
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
		CreatedAt:    time.Now().UTC().Add(-time.Hour),
	}
	if err := db.Create(&token).Error; err != nil {
		t.Fatalf("create mysql legacy refresh token: %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate(mysql) error = %v", err)
	}
	if !db.Migrator().HasColumn(&TenantMember{}, "permission_version") {
		t.Fatal("expected mysql tenant_members.permission_version column to exist")
	}

	var loginSession LoginSession
	if err := db.First(&loginSession, "id = ?", "legacy-mysql-session").Error; err != nil {
		t.Fatalf("load mysql backfilled login session: %v", err)
	}
	if loginSession.UserID != user.ID || loginSession.TenantID != 7 || loginSession.ClientID != "mysql-client" {
		t.Fatalf("mysql loginSession = %#v, want backfilled metadata", loginSession)
	}
}

func TestUserEmailUniqueIndexRejectsDuplicates(t *testing.T) {
	cfg := config.Config{}

	db, err := OpenDB(cfg)
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	first := User{
		Email:        "dup@example.com",
		DisplayName:  "first",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.WithContext(context.Background()).Create(&first).Error; err != nil {
		t.Fatalf("create first user: %v", err)
	}

	second := User{
		Email:        "dup@example.com",
		DisplayName:  "second",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.WithContext(context.Background()).Create(&second).Error; err == nil {
		t.Fatal("expected duplicate user email insert to fail")
	}
}
