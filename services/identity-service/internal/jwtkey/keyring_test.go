package jwtkey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/config"
)

func TestLoadKeyringFromDirectoryUsesActiveKeyAndVerifiesOldKid(t *testing.T) {
	dir := t.TempDir()
	previous := writeTestKey(t, dir, "2026-05-previous")
	active := writeTestKey(t, dir, "2026-06-active")

	keyring, err := Load(config.Config{
		JWTKeysetDir:   dir,
		JWTActiveKeyID: "2026-06-active",
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := keyring.ActiveKeyID(); got != "2026-06-active" {
		t.Fatalf("ActiveKeyID() = %q, want 2026-06-active", got)
	}
	if got := keyring.ActivePrivateKey().N; got.Cmp(active.N) != 0 {
		t.Fatalf("active private key modulus mismatch")
	}
	if len(keyring.PublicKeys()) != 2 {
		t.Fatalf("PublicKeys() length = %d, want 2", len(keyring.PublicKeys()))
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"sub": "user-1"})
	token.Header["kid"] = "2026-05-previous"
	signed, err := token.SignedString(previous)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	parsed, err := jwt.Parse(signed, keyring.Keyfunc)
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}
	if !parsed.Valid {
		t.Fatal("parsed token is invalid")
	}
}

func TestLoadKeyringPreservesLegacySingleKeyMode(t *testing.T) {
	dir := t.TempDir()
	key := writeTestKey(t, dir, "legacy")
	keyPath := filepath.Join(dir, "legacy.pem")

	keyring, err := Load(config.Config{
		JWTPrivateKeyPath: keyPath,
		JWTKeyID:          "legacy-kid",
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := keyring.ActiveKeyID(); got != "legacy-kid" {
		t.Fatalf("ActiveKeyID() = %q, want legacy-kid", got)
	}
	if got := keyring.ActivePrivateKey().N; got.Cmp(key.N) != 0 {
		t.Fatalf("legacy private key modulus mismatch")
	}
}

func writeTestKey(t *testing.T, dir, id string) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := os.WriteFile(filepath.Join(dir, id+".pem"), pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return key
}
