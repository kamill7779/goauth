package password_test

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"goauth/services/identity-service/internal/password"
)

func TestValidate_MinLength(t *testing.T) {
	p := password.Policy{MinLength: 8, RequireDigit: true}

	if err := p.Validate("short1"); err == nil {
		t.Error("expected error for too-short password")
	}
	if err := p.Validate("longenough1"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RequireUppercase(t *testing.T) {
	p := password.Policy{MinLength: 4, RequireUppercase: true}
	if err := p.Validate("alllower"); err == nil {
		t.Error("expected error for missing uppercase")
	}
	if err := p.Validate("HasUpper"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RequireDigit(t *testing.T) {
	p := password.Policy{MinLength: 4, RequireDigit: true}
	if err := p.Validate("nodigits"); err == nil {
		t.Error("expected error for missing digit")
	}
	if err := p.Validate("has1digit"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_RequireSpecial(t *testing.T) {
	p := password.Policy{MinLength: 4, RequireSpecial: true}
	if err := p.Validate("nospecial"); err == nil {
		t.Error("expected error for missing special char")
	}
	if err := p.Validate("has!special"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_MultipleViolations(t *testing.T) {
	p := password.Policy{MinLength: 10, RequireUppercase: true, RequireDigit: true}
	err := p.Validate("short")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "minimum length") {
		t.Errorf("expected length violation in: %s", msg)
	}
	if !strings.Contains(msg, "uppercase") {
		t.Errorf("expected uppercase violation in: %s", msg)
	}
	if !strings.Contains(msg, "digit") {
		t.Errorf("expected digit violation in: %s", msg)
	}
}

func TestCheckHistory_RejectsRecentPassword(t *testing.T) {
	p := password.Policy{HistoryCount: 3}

	hash, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.MinCost)
	hashes := []string{string(hash)}

	if err := p.CheckHistory("oldpassword", hashes); err == nil {
		t.Error("expected error for reused password")
	}
}

func TestCheckHistory_AllowsNewPassword(t *testing.T) {
	p := password.Policy{HistoryCount: 3}

	hash, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.MinCost)
	hashes := []string{string(hash)}

	if err := p.CheckHistory("newpassword", hashes); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCheckHistory_RespectsHistoryCount(t *testing.T) {
	p := password.Policy{HistoryCount: 2}

	h1, _ := bcrypt.GenerateFromPassword([]byte("pass1"), bcrypt.MinCost)
	h2, _ := bcrypt.GenerateFromPassword([]byte("pass2"), bcrypt.MinCost)
	h3, _ := bcrypt.GenerateFromPassword([]byte("pass3"), bcrypt.MinCost)
	// hashes ordered most-recent first
	hashes := []string{string(h1), string(h2), string(h3)}

	// pass3 is outside the history window of 2, so it should be allowed
	if err := p.CheckHistory("pass3", hashes); err != nil {
		t.Errorf("pass3 should be allowed (outside history window): %v", err)
	}
	// pass1 and pass2 are within the window
	if err := p.CheckHistory("pass1", hashes); err == nil {
		t.Error("pass1 should be rejected (in history)")
	}
}

func TestCheckHistory_ZeroCount_AllowsAll(t *testing.T) {
	p := password.Policy{HistoryCount: 0}
	hash, _ := bcrypt.GenerateFromPassword([]byte("same"), bcrypt.MinCost)
	if err := p.CheckHistory("same", []string{string(hash)}); err != nil {
		t.Errorf("zero history count should allow all: %v", err)
	}
}
