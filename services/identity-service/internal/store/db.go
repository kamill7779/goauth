package store

import (
	"fmt"
	"time"

	"example.com/identity-service/internal/config"
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
	return db.AutoMigrate(
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
		&RefreshToken{},
		&ExternalProviderConfig{},
		&AuditLog{},
	)
}
