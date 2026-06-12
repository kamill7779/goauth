package store

import (
	"testing"

	"goauth/services/identity-service/internal/config"
)

// Compile-time check: ensure GORM implementations satisfy the interfaces.
func TestRepositoryInterfacesSatisfied(t *testing.T) {
	var _ UserRepository = (*userRepo)(nil)
	var _ SessionRepository = (*sessionRepo)(nil)
}

func TestNewRepositoryConstructors(t *testing.T) {
	db, err := OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("OpenDB() error = %v", err)
	}
	if ur := NewUserRepository(db); ur == nil {
		t.Fatal("NewUserRepository returned nil")
	}
	if sr := NewSessionRepository(db); sr == nil {
		t.Fatal("NewSessionRepository returned nil")
	}
}
