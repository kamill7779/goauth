package auth

import "testing"

func TestHashPasswordMatchesOriginalPassword(t *testing.T) {
	hash, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if err := CheckPassword(hash, "p@ssw0rd!"); err != nil {
		t.Fatalf("CheckPassword() error = %v", err)
	}
}

func TestCheckPasswordRejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	if err := CheckPassword(hash, "wrong-password"); err == nil {
		t.Fatal("expected wrong password to fail validation")
	}
}
