package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"goauth/services/identity-service/internal/metrics"
)

func TestRegister_MetricsAvailable(t *testing.T) {
	metrics.Register()

	loginSuccessBefore := testutil.ToFloat64(metrics.LoginSuccess)
	loginFailureBefore := testutil.ToFloat64(metrics.LoginFailure)
	lockoutBefore := testutil.ToFloat64(metrics.AccountLockout)

	metrics.IncLoginSuccess()
	metrics.IncLoginSuccess()
	metrics.IncLoginFailure()
	metrics.IncAccountLockout()
	metrics.IncTokenIssued("password")
	metrics.IncTokenIssued("refresh_token")

	count := testutil.ToFloat64(metrics.LoginSuccess) - loginSuccessBefore
	if count != 2 {
		t.Errorf("expected LoginSuccess delta=2, got %v", count)
	}

	count = testutil.ToFloat64(metrics.LoginFailure) - loginFailureBefore
	if count != 1 {
		t.Errorf("expected LoginFailure delta=1, got %v", count)
	}

	count = testutil.ToFloat64(metrics.AccountLockout) - lockoutBefore
	if count != 1 {
		t.Errorf("expected AccountLockout delta=1, got %v", count)
	}
}

func TestRegister_IsIdempotent(t *testing.T) {
	metrics.Register()
	firstCounter := metrics.LoginSuccess
	before := testutil.ToFloat64(metrics.LoginSuccess)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			metrics.Register()
		}()
	}
	wg.Wait()

	if metrics.LoginSuccess != firstCounter {
		t.Fatal("expected Register to preserve existing collector instances")
	}

	metrics.IncLoginSuccess()
	if got := testutil.ToFloat64(metrics.LoginSuccess) - before; got != 1 {
		t.Fatalf("expected LoginSuccess delta=1 after repeated Register, got %v", got)
	}
}

func TestHandler_ServesPrometheusFormat(t *testing.T) {
	metrics.Register()
	metrics.IncLoginSuccess()

	h := metrics.Handler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "goauth_login_success_total") {
		t.Fatalf("expected login success metric in response body: %s", rec.Body.String())
	}
}
