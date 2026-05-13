// Package metrics exposes Prometheus counters and histograms for key
// authentication events (logins, lockouts, token issuance, HTTP latency).
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	registerOnce sync.Once
	registry     *prometheus.Registry
	handler      http.Handler

	HTTPRequestDuration *prometheus.HistogramVec
	LoginSuccess        prometheus.Counter
	LoginFailure        prometheus.Counter
	TokenIssued         *prometheus.CounterVec
	AccountLockout      prometheus.Counter
)

// Register initialises and registers all metrics into a dedicated registry.
// Safe to call multiple times (idempotent via sync.Once pattern).
func Register() {
	registerOnce.Do(func() {
		registry = prometheus.NewRegistry()

		HTTPRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "goauth_http_request_duration_seconds",
			Help:    "HTTP request latency histogram.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path", "status"})

		LoginSuccess = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "goauth_login_success_total",
			Help: "Total number of successful logins.",
		})

		LoginFailure = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "goauth_login_failure_total",
			Help: "Total number of failed login attempts.",
		})

		TokenIssued = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "goauth_token_issued_total",
			Help: "Total number of tokens issued, by grant type.",
		}, []string{"grant_type"})

		AccountLockout = prometheus.NewCounter(prometheus.CounterOpts{
			Name: "goauth_account_lockout_total",
			Help: "Total number of account lockout events.",
		})

		registry.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
			HTTPRequestDuration,
			LoginSuccess,
			LoginFailure,
			TokenIssued,
			AccountLockout,
		)

		handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	})
}

// Handler returns an HTTP handler that serves Prometheus metrics.
func Handler() http.Handler {
	Register()
	return handler
}

// IncLoginSuccess increments the login success counter (noop if not registered).
func IncLoginSuccess() {
	if LoginSuccess != nil {
		LoginSuccess.Inc()
	}
}

// IncLoginFailure increments the login failure counter (noop if not registered).
func IncLoginFailure() {
	if LoginFailure != nil {
		LoginFailure.Inc()
	}
}

// IncAccountLockout increments the account lockout counter (noop if not registered).
func IncAccountLockout() {
	if AccountLockout != nil {
		AccountLockout.Inc()
	}
}

// IncTokenIssued increments the token issued counter for the given grant type.
func IncTokenIssued(grantType string) {
	if TokenIssued != nil {
		TokenIssued.WithLabelValues(grantType).Inc()
	}
}
