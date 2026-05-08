package store

import (
	"context"
	"testing"

	"example.com/identity-service/internal/config"
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
		&Role{},
		&OAuthClient{},
		&RefreshToken{},
		&AuditLog{},
	} {
		if !db.Migrator().HasTable(model) {
			t.Fatalf("expected table for %T to exist", model)
		}
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB() error = %v", err)
	}
	defer sqlDB.Close()
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
