package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/identity-service/internal/config"
	"github.com/gin-gonic/gin"
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
