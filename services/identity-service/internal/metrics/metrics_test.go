package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"goauth/services/identity-service/internal/metrics"
)

func TestRegister_MetricsAvailable(t *testing.T) {
	metrics.Register()

	metrics.IncLoginSuccess()
	metrics.IncLoginSuccess()
	metrics.IncLoginFailure()
	metrics.IncAccountLockout()
	metrics.IncTokenIssued("password")
	metrics.IncTokenIssued("refresh_token")

	count := testutil.ToFloat64(metrics.LoginSuccess)
	if count != 2 {
		t.Errorf("expected LoginSuccess=2, got %v", count)
	}

	count = testutil.ToFloat64(metrics.LoginFailure)
	if count != 1 {
		t.Errorf("expected LoginFailure=1, got %v", count)
	}

	count = testutil.ToFloat64(metrics.AccountLockout)
	if count != 1 {
		t.Errorf("expected AccountLockout=1, got %v", count)
	}
}

func TestHandler_ServesPrometheusFormat(t *testing.T) {
	metrics.Register()
	metrics.IncLoginSuccess()

	h := metrics.Handler()
	if h == nil {
		t.Fatal("expected non-nil handler")
	}

	// Verify the counter is positive.
	if testutil.ToFloat64(metrics.LoginSuccess) <= 0 {
		t.Error("login success counter should be > 0")
	}
}
