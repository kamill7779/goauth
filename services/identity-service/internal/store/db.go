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
	); err != nil {
		return err
	}
	return backfillLoginSessions(db)
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
