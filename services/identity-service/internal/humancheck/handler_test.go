package humancheck

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func newHandlerTestService(t *testing.T) *Service {
	t.Helper()
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewService(client, Config{Provider: ProviderSlider, Actions: []string{ActionRegister}, ChallengeTTL: 2 * time.Minute, TokenTTL: 3 * time.Minute, TolerancePX: 4})
}

func TestHandlerIssuesChallengeWithoutLeakingAnswer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := newHandlerTestService(t)
	router := gin.New()
	NewHandler(service).RegisterRoutes(router.Group("/v1/auth"))

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/auth/human-check/slider", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", recorder.Code, recorder.Body.String())
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("target_x")) {
		t.Fatalf("challenge response must not leak target_x: %s", recorder.Body.String())
	}
	var body struct {
		Data struct {
			ID    string `json:"id"`
			Nonce string `json:"nonce"`
			Image string `json:"image"`
			Thumb string `json:"thumb"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Data.ID == "" || body.Data.Nonce == "" || body.Data.Image == "" || body.Data.Thumb == "" {
		t.Fatalf("challenge response missing fields: %+v", body.Data)
	}
}

func TestHandlerVerifyRejectsBadPoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := newHandlerTestService(t)
	router := gin.New()
	NewHandler(service).RegisterRoutes(router.Group("/v1/auth"))

	challenge, err := service.CreateSliderChallenge(t.Context())
	if err != nil {
		t.Fatalf("CreateSliderChallenge() error = %v", err)
	}
	payload := []byte(`{"challenge_id":"` + challenge.ID + `","nonce":"` + challenge.Nonce + `","x":0,"elapsed_ms":1200,"track":[{"x":0,"t":0},{"x":1,"t":1200}]}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/human-check/slider/verify", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 body=%s", recorder.Code, recorder.Body.String())
	}
}
