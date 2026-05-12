package logout_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"goauth/services/identity-service/internal/logout"
	"goauth/services/identity-service/internal/store"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.AutoMigrate(&store.OAuthClient{}, &store.RefreshToken{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestNotifyClients_SendsToConfiguredClients(t *testing.T) {
	var called int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&called, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	db := newTestDB(t)
	key := newTestKey(t)

	// Create a client with backchannel_logout_uri.
	client := store.OAuthClient{
		ClientID:             "client1",
		ClientSecretHash:     "hash",
		Name:                 "Test Client",
		TenantID:             1,
		RedirectURIs:         datatypes.JSON(`["https://app.example.com/callback"]`),
		AllowedScopes:        datatypes.JSON(`["openid"]`),
		GrantTypes:           datatypes.JSON(`["authorization_code"]`),
		TokenEndpointAuthMethod: "client_secret_post",
		BackchannelLogoutURI: srv.URL + "/logout",
		Status:               store.TenantStatusActive,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	db.Create(&client)

	// Create an active refresh token for user 42.
	db.Create(&store.RefreshToken{
		TokenHash: "hash1",
		FamilyID:  "fam1",
		SessionID: "sess1",
		UserID:    42,
		TenantID:  1,
		ClientID:  "client1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	coord := logout.NewCoordinator(db, key, "https://auth.example.com", "key1")
	if err := coord.NotifyClients(context.Background(), 42, "sess1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("expected 1 notification, got %d", called)
	}
}

func TestNotifyClients_SkipsClientsWithoutURI(t *testing.T) {
	db := newTestDB(t)
	key := newTestKey(t)

	// Client without backchannel_logout_uri.
	db.Create(&store.OAuthClient{
		ClientID:             "client-no-uri",
		ClientSecretHash:     "hash",
		Name:                 "No URI Client",
		TenantID:             1,
		RedirectURIs:         datatypes.JSON(`[]`),
		AllowedScopes:        datatypes.JSON(`[]`),
		GrantTypes:           datatypes.JSON(`[]`),
		TokenEndpointAuthMethod: "client_secret_post",
		BackchannelLogoutURI: "",
		Status:               store.TenantStatusActive,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	})
	db.Create(&store.RefreshToken{
		TokenHash: "hash2",
		FamilyID:  "fam2",
		SessionID: "sess2",
		UserID:    43,
		TenantID:  1,
		ClientID:  "client-no-uri",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	coord := logout.NewCoordinator(db, key, "https://auth.example.com", "key1")
	// Should not error even though no notifications are sent.
	if err := coord.NotifyClients(context.Background(), 43, "sess2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNotifyClients_ContinuesOnFailure(t *testing.T) {
	// Server that always returns 500.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	db := newTestDB(t)
	key := newTestKey(t)

	db.Create(&store.OAuthClient{
		ClientID:             "failing-client",
		ClientSecretHash:     "hash",
		Name:                 "Failing Client",
		TenantID:             1,
		RedirectURIs:         datatypes.JSON(`[]`),
		AllowedScopes:        datatypes.JSON(`[]`),
		GrantTypes:           datatypes.JSON(`[]`),
		TokenEndpointAuthMethod: "client_secret_post",
		BackchannelLogoutURI: srv.URL + "/logout",
		Status:               store.TenantStatusActive,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	})
	db.Create(&store.RefreshToken{
		TokenHash: "hash3",
		FamilyID:  "fam3",
		SessionID: "sess3",
		UserID:    44,
		TenantID:  1,
		ClientID:  "failing-client",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	})

	coord := logout.NewCoordinator(db, key, "https://auth.example.com", "key1")
	// Should not return error even when notification fails.
	if err := coord.NotifyClients(context.Background(), 44, "sess3"); err != nil {
		t.Fatalf("coordinator should not return error on notification failure: %v", err)
	}
}
