package store

import (
	"fmt"
	"time"

	"goauth/services/identity-service/internal/config"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func OpenDB(cfg config.Config) (*gorm.DB, error) {
	if cfg.MySQLDSN != "" {
		return gorm.Open(mysql.Open(cfg.MySQLDSN), &gorm.Config{})
	}

	dsn := fmt.Sprintf("file:goauth-%d?mode=memory&cache=shared", time.Now().UnixNano())
	return gorm.Open(sqlite.Open(dsn), &gorm.Config{})
}

func AutoMigrate(db *gorm.DB) error {
	// For pre-existing tables, add the new columns with a safe default so
	// GORM can run its own migration without constraint violations.
	if err := setupUserIdentityColumns(db); err != nil {
		return err
	}
	if err := db.AutoMigrate(
		&User{},
		&UserIdentity{},
		&Tenant{},
		&TenantMember{},
		&Role{},
		&Permission{},
		&RolePermission{},
		&MemberRole{},
		&OAuthClient{},
		&OAuthAuthorizationCode{},
		&LoginSession{},
		&RefreshToken{},
		&ExternalProviderConfig{},
		&AuditLog{},
		&PasswordHistory{},
		&Invite{},
	); err != nil {
		return err
	}
	// Backfill happens after GORM has stabilised the schema so that table
	// rebuilds inside the driver cannot undo our updates.
	if err := backfillUserIdentityFields(db); err != nil {
		return err
	}
	if err := ensureUsernameUniqueIndex(db); err != nil {
		return err
	}
	return backfillLoginSessions(db)
}

// setupUserIdentityColumns adds the new username and nickname columns to
// pre-existing user tables. GORM may rebuild the table during its own
// AutoMigrate pass so we defer the backfill and unique index to later.
func setupUserIdentityColumns(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	migrator := db.Migrator()
	if !migrator.HasTable(&User{}) {
		return nil
	}
	if !migrator.HasColumn(&User{}, "username") {
		if err := db.Exec(`ALTER TABLE users ADD COLUMN username VARCHAR(64) NOT NULL DEFAULT ''`).Error; err != nil {
			return fmt.Errorf("add users.username column: %w", err)
		}
	}
	if !migrator.HasColumn(&User{}, "nickname") {
		if err := db.Exec(`ALTER TABLE users ADD COLUMN nickname VARCHAR(255) NOT NULL DEFAULT ''`).Error; err != nil {
			return fmt.Errorf("add users.nickname column: %w", err)
		}
	}
	return nil
}

func ensureUsernameUniqueIndex(db *gorm.DB) error {
	indexName := "idx_users_username"
	if hasIndex(db.Migrator(), "users", indexName) {
		return nil
	}
	if !db.Migrator().HasColumn(&User{}, "username") {
		return nil
	}
	query := fmt.Sprintf(`CREATE UNIQUE INDEX %s ON users(username)`, indexName)
	if db.Dialector.Name() == "sqlite" {
		query = fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS %s ON users(username)`, indexName)
	}
	return db.Exec(query).Error
}

func hasIndex(migrator gorm.Migrator, table, indexName string) bool {
	if migrator == nil {
		return false
	}
	indexes, err := migrator.GetIndexes(table)
	if err != nil {
		return false
	}
	for _, idx := range indexes {
		if idx.Name() == indexName {
			return true
		}
	}
	return false
}

func backfillLoginSessions(db *gorm.DB) error {
	query := `
		INSERT INTO login_sessions (id, user_id, tenant_id, client_id, created_at, updated_at)
		SELECT session_id, MIN(user_id), MIN(tenant_id), MIN(client_id), MIN(created_at), CURRENT_TIMESTAMP
		FROM refresh_tokens
		WHERE session_id IS NOT NULL AND session_id <> ''
		GROUP BY session_id
		ON CONFLICT(id) DO NOTHING
	`
	if db.Dialector.Name() == "mysql" {
		query = `
			INSERT IGNORE INTO login_sessions (id, user_id, tenant_id, client_id, created_at, updated_at)
			SELECT session_id, MIN(user_id), MIN(tenant_id), MIN(client_id), MIN(created_at), CURRENT_TIMESTAMP
			FROM refresh_tokens
			WHERE session_id IS NOT NULL AND session_id <> ''
			GROUP BY session_id
		`
	}
	return db.Exec(query).Error
}
