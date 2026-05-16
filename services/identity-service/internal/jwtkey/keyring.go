package jwtkey

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/config"
)

type PublicKey struct {
	ID  string
	Key *rsa.PublicKey
}

type Keyring struct {
	activeID string
	active   *rsa.PrivateKey
	keys     map[string]*rsa.PrivateKey
	order    []string
}

func Load(cfg config.Config) (*Keyring, error) {
	if dir := strings.TrimSpace(cfg.JWTKeysetDir); dir != "" {
		return loadDirectory(dir, strings.TrimSpace(cfg.JWTActiveKeyID))
	}
	if path := strings.TrimSpace(cfg.JWTPrivateKeyPath); path != "" {
		key, err := LoadRSAPrivateKey(path)
		if err != nil {
			return nil, err
		}
		return NewKeyring(strings.TrimSpace(cfg.JWTKeyID), map[string]*rsa.PrivateKey{
			strings.TrimSpace(cfg.JWTKeyID): key,
		})
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return NewKeyring(strings.TrimSpace(cfg.JWTKeyID), map[string]*rsa.PrivateKey{
		strings.TrimSpace(cfg.JWTKeyID): key,
	})
}

func NewKeyring(activeID string, keys map[string]*rsa.PrivateKey) (*Keyring, error) {
	activeID = strings.TrimSpace(activeID)
	if len(keys) == 0 {
		return nil, errors.New("jwt keyring has no keys")
	}

	normalized := make(map[string]*rsa.PrivateKey, len(keys))
	for id, key := range keys {
		id = strings.TrimSpace(id)
		if key == nil {
			return nil, fmt.Errorf("jwt key %q is nil", id)
		}
		normalized[id] = key
	}
	if activeID == "" && len(normalized) == 1 {
		for id := range normalized {
			activeID = id
		}
	}

	active, ok := normalized[activeID]
	if !ok {
		return nil, fmt.Errorf("active jwt key %q not found", activeID)
	}

	order := make([]string, 0, len(normalized))
	for id := range normalized {
		if id == activeID {
			continue
		}
		order = append(order, id)
	}
	sort.Strings(order)
	order = append([]string{activeID}, order...)

	return &Keyring{
		activeID: activeID,
		active:   active,
		keys:     normalized,
		order:    order,
	}, nil
}

func (k *Keyring) ActiveKeyID() string {
	if k == nil {
		return ""
	}
	return k.activeID
}

func (k *Keyring) ActivePrivateKey() *rsa.PrivateKey {
	if k == nil {
		return nil
	}
	return k.active
}

func (k *Keyring) ActivePublicKey() *rsa.PublicKey {
	if k == nil || k.active == nil {
		return nil
	}
	return &k.active.PublicKey
}

func (k *Keyring) PublicKeys() []PublicKey {
	if k == nil {
		return nil
	}
	result := make([]PublicKey, 0, len(k.order))
	for _, id := range k.order {
		key := k.keys[id]
		if key == nil {
			continue
		}
		result = append(result, PublicKey{ID: id, Key: &key.PublicKey})
	}
	return result
}

func (k *Keyring) Keyfunc(token *jwt.Token) (any, error) {
	if k == nil {
		return nil, errors.New("jwt keyring is not configured")
	}
	if token.Method != jwt.SigningMethodRS256 {
		return nil, errors.New("unexpected signing method")
	}

	kid, _ := token.Header["kid"].(string)
	kid = strings.TrimSpace(kid)
	if kid == "" {
		if len(k.keys) != 1 {
			return nil, errors.New("missing kid")
		}
		return k.ActivePublicKey(), nil
	}

	key, ok := k.keys[kid]
	if !ok || key == nil {
		return nil, fmt.Errorf("unknown kid %q", kid)
	}
	return &key.PublicKey, nil
}

func loadDirectory(dir, activeID string) (*Keyring, error) {
	if activeID == "" {
		return nil, errors.New("JWT_ACTIVE_KEY_ID is required when JWT_KEYSET_DIR is configured")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read jwt keyset dir: %w", err)
	}

	keys := map[string]*rsa.PrivateKey{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.EqualFold(filepath.Ext(name), ".pem") {
			continue
		}
		id := strings.TrimSuffix(name, filepath.Ext(name))
		key, err := LoadRSAPrivateKey(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("load jwt key %s: %w", name, err)
		}
		keys[id] = key
	}
	return NewKeyring(activeID, keys)
}

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("decode private key pem: no block found")
	}

	if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return privateKey, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return privateKey, nil
}
