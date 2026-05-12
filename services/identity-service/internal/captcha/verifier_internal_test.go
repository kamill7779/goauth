package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerify_RejectsNon200ProviderResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))
	defer srv.Close()

	originalURL := verifyURLs[ProviderTurnstile]
	verifyURLs[ProviderTurnstile] = srv.URL
	t.Cleanup(func() {
		verifyURLs[ProviderTurnstile] = originalURL
	})

	v := NewVerifier(ProviderTurnstile, "secret")
	if err := v.verify(context.Background(), "token", ""); err == nil {
		t.Fatal("expected verify to reject non-200 provider responses")
	}
}

func TestVerify_RejectsUnknownProvider(t *testing.T) {
	v := NewVerifier(Provider("bogus"), "secret")
	if err := v.verify(context.Background(), "token", ""); err == nil {
		t.Fatal("expected verify to reject unknown providers")
	}
}
