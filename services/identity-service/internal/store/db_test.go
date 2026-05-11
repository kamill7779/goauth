package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	mysqlcfg "github.com/go-sql-driver/mysql"
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
	parsed, err := mysqlcfg.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse MYSQL_DSN_TEST: %v", err)
	}
	dbName := strings.ToLower(parsed.DBName)
	if os.Getenv("MYSQL_DSN_TEST_ALLOW_DESTRUCTIVE") != "1" || dbName == "" || !strings.HasSuffix(dbName, "_test") {
		t.Skip("MYSQL_DSN_TEST requires MYSQL_DSN_TEST_ALLOW_DESTRUCTIVE=1 and a test database name")
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
		Username:     "dup-first",
		Nickname:     "first",
		DisplayName:  "first",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.WithContext(context.Background()).Create(&first).Error; err != nil {
		t.Fatalf("create first user: %v", err)
	}

	second := User{
		Email:        "dup@example.com",
		Username:     "dup-second",
		Nickname:     "second",
		DisplayName:  "second",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.WithContext(context.Background()).Create(&second).Error; err == nil {
		t.Fatal("expected duplicate user email insert to fail")
	}
}

func TestUserUsernameUniqueIndexRejectsDuplicates(t *testing.T) {
	db, err := OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	first := User{
		Email:        "first@example.com",
		Username:     "duplicate",
		Nickname:     "First",
		DisplayName:  "First",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.WithContext(context.Background()).Create(&first).Error; err != nil {
		t.Fatalf("create first user: %v", err)
	}

	second := User{
		Email:        "second@example.com",
		Username:     "duplicate",
		Nickname:     "Second",
		DisplayName:  "Second",
		PasswordHash: "hash",
		Status:       UserStatusActive,
	}
	if err := db.WithContext(context.Background()).Create(&second).Error; err == nil {
		t.Fatal("expected duplicate username insert to fail")
	}
}

func TestAutoMigrateBackfillsUserIdentityFields(t *testing.T) {
	db, err := OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}

	if err := db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email VARCHAR(255) NOT NULL,
		email_verified_at DATETIME,
		password_hash VARCHAR(255) NOT NULL,
		display_name VARCHAR(255) NOT NULL DEFAULT '',
		avatar_url VARCHAR(1024) NOT NULL DEFAULT '',
		status VARCHAR(32) NOT NULL,
		token_version INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		deleted_at DATETIME
	)`).Error; err != nil {
		t.Fatalf("create legacy users table: %v", err)
	}
	if err := db.Exec(`CREATE UNIQUE INDEX idx_legacy_users_email ON users(email)`).Error; err != nil {
		t.Fatalf("create legacy email index: %v", err)
	}

	now := time.Now().UTC()
	type legacyRow struct {
		email       string
		displayName string
	}
	rows := []legacyRow{
		{"alice@example.com", "Alice"},
		{"alice@other.com", ""},
		{"ALICE@third.com", ""},
		{"+invalid@example.com", ""},
		{"bob@example.com", "Robert"},
	}
	for _, r := range rows {
		if err := db.Exec(
			`INSERT INTO users (email, password_hash, display_name, status, token_version, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			r.email, "hash", r.displayName, UserStatusActive, 0, now, now,
		).Error; err != nil {
			t.Fatalf("insert legacy row %q: %v", r.email, err)
		}
	}

	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate() error = %v", err)
	}

	if !db.Migrator().HasColumn(&User{}, "username") {
		t.Fatal("expected users.username column to exist after migration")
	}
	if !db.Migrator().HasColumn(&User{}, "nickname") {
		t.Fatal("expected users.nickname column to exist after migration")
	}

	usernameIndexFound := false
	if indexes, err := db.Migrator().GetIndexes(&User{}); err == nil {
		for _, idx := range indexes {
			cols := idx.Columns()
			if len(cols) != 1 || cols[0] != "username" {
				continue
			}
			if unique, ok := idx.Unique(); ok && unique {
				usernameIndexFound = true
				break
			}
		}
	}
	if !usernameIndexFound {
		t.Fatal("expected a unique index on users.username after migration")
	}

	var users []User
	if err := db.Order("id ASC").Find(&users).Error; err != nil {
		t.Fatalf("load users: %v", err)
	}
	if len(users) != len(rows) {
		t.Fatalf("expected %d users after migration, got %d", len(rows), len(users))
	}

	usernames := map[string]int{}
	for i, u := range users {
		if u.Username == "" {
			t.Fatalf("user %d (email=%s) has empty username", u.ID, u.Email)
		}
		if u.Nickname == "" {
			t.Fatalf("user %d (email=%s) has empty nickname", u.ID, u.Email)
		}
		usernames[u.Username]++
		_ = i
	}
	for name, count := range usernames {
		if count > 1 {
			t.Fatalf("expected unique usernames, %q appeared %d times", name, count)
		}
	}

	if users[0].Username != "alice" {
		t.Fatalf("first alice should keep username='alice', got %q", users[0].Username)
	}
	if users[1].Username == users[0].Username {
		t.Fatalf("second alice should be deconflicted, got %q", users[1].Username)
	}
	if users[2].Username == users[0].Username || users[2].Username == users[1].Username {
		t.Fatalf("third alice should be deconflicted further, got %q", users[2].Username)
	}

	if users[3].Username == "" || users[3].Username == "alice" {
		t.Fatalf("fourth user with leading + should get a sanitized username, got %q", users[3].Username)
	}

	if users[0].Nickname != "Alice" {
		t.Fatalf("first user should keep display_name as nickname, got %q", users[0].Nickname)
	}
	if users[1].Nickname != "alice" {
		t.Fatalf("blank display_name should fall back to email local-part, got %q", users[1].Nickname)
	}
	if users[4].Nickname != "Robert" {
		t.Fatalf("preserved display_name should become nickname, got %q", users[4].Nickname)
	}
}
