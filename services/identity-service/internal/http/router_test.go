package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

type registrarFunc func(gin.IRouter)

func (f registrarFunc) RegisterRoutes(router gin.IRouter) {
	f(router)
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

func TestReadyzReturnsStructuredSuccessWhenChecksPass(t *testing.T) {
	router := NewRouter(config.Config{}, NewReadinessRegistrar(ReadinessCheck{
		Name: "db",
		Check: func(ctx context.Context) error {
			return nil
		},
	}))
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
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
	if payload.Data.Status != "ready" {
		t.Fatalf("data.status = %q, want ready", payload.Data.Status)
	}
}

func TestReadyzReturnsServiceUnavailableWhenCheckFails(t *testing.T) {
	router := NewRouter(config.Config{}, NewReadinessRegistrar(ReadinessCheck{
		Name: "redis",
		Check: func(ctx context.Context) error {
			return errors.New("ping redis: connection refused")
		},
	}))
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, "not_ready") || !strings.Contains(body, "redis") {
		t.Fatalf("body = %s, want readiness failure details", body)
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

func TestNewRouterUsesRemoteAddrWhenTrustedProxiesUnset(t *testing.T) {
	router := NewRouter(config.Config{}, registrarFunc(func(r gin.IRouter) {
		r.GET("/client-ip", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"client_ip": c.ClientIP()})
		})
	}))

	request := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	var payload map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["client_ip"] != "10.0.0.8" {
		t.Fatalf("client_ip = %q, want remote address", payload["client_ip"])
	}
}

func TestNewRouterUsesForwardedClientIPForTrustedProxy(t *testing.T) {
	router := NewRouter(config.Config{
		TrustedProxies: []string{"10.0.0.0/8"},
	}, registrarFunc(func(r gin.IRouter) {
		r.GET("/client-ip", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"client_ip": c.ClientIP()})
		})
	}))

	request := httptest.NewRequest(http.MethodGet, "/client-ip", nil)
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	var payload map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if payload["client_ip"] != "203.0.113.99" {
		t.Fatalf("client_ip = %q, want forwarded client IP", payload["client_ip"])
	}
}
