package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
)

type testRegistrar struct {
	registered bool
}

func (r *testRegistrar) RegisterRoutes(router gin.IRouter) {
	r.registered = true
	router.GET("/registered", func(c *gin.Context) {
		Success(c, http.StatusOK, gin.H{"ok": true})
	})
}

func TestHealthzReturnsStructuredSuccessResponse(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	router := NewRouter(cfg)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload struct {
		Success bool `json:"success"`
		Data    struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if !payload.Success {
		t.Fatal("success = false, want true")
	}
	if payload.Data.Status != "ok" {
		t.Fatalf("data.status = %q, want ok", payload.Data.Status)
	}
}

func TestNewRouterInvokesRegistrars(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	registrar := &testRegistrar{}
	router := NewRouter(cfg, registrar)
	if !registrar.registered {
		t.Fatal("registrar.registered = false, want true")
	}

	request := httptest.NewRequest(http.MethodGet, "/registered", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestCORSPreflightUsesConfiguredAllowlist(t *testing.T) {
	router := NewRouter(config.Config{
		CORSAllowedOrigins:   []string{"https://app.example.com"},
		CORSAllowedMethods:   []string{"GET", "POST"},
		CORSAllowedHeaders:   []string{"Authorization", "Content-Type"},
		CORSAllowCredentials: true,
	})

	request := httptest.NewRequest(http.MethodOptions, "/v1/auth/login", nil)
	request.Header.Set("Origin", "https://app.example.com")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %q", got)
	}
}
