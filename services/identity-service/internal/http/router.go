package http

import (
	"context"
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
)

type Registrar interface {
	RegisterRoutes(router gin.IRouter)
}

type EngineRegistrar interface {
	RegisterRoutes(*gin.Engine)
}

type ReadinessCheck struct {
	Name  string
	Check func(context.Context) error
}

type readinessRegistrar struct {
	checks []ReadinessCheck
}

type readinessFailureResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Data    any    `json:"data"`
}

// NewReadinessRegistrar creates a Registrar that serves GET /readyz, running
// each supplied ReadinessCheck with a 2 s timeout. Any failure returns 503.
//
// Call chain: main.buildRouterWithServices → http.NewReadinessRegistrar → (no downstream)
func NewReadinessRegistrar(checks ...ReadinessCheck) Registrar {
	return readinessRegistrar{checks: checks}
}

// RegisterRoutes mounts the /readyz endpoint that runs all configured health
// checks and returns 503 with per-check error details on failure.
//
// Call chain: http.NewRouter → readinessRegistrar.RegisterRoutes → ReadinessCheck.Check
func (r readinessRegistrar) RegisterRoutes(router gin.IRouter) {
	router.GET("/readyz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		failures := make(map[string]string)
		for _, check := range r.checks {
			name := strings.TrimSpace(check.Name)
			if name == "" {
				name = "dependency"
			}
			if check.Check == nil {
				failures[name] = "check not configured"
				continue
			}
			if err := check.Check(ctx); err != nil {
				failures[name] = err.Error()
			}
		}

		if len(failures) > 0 {
			c.JSON(stdhttp.StatusServiceUnavailable, readinessFailureResponse{
				Success: false,
				Error:   "service not ready",
				Data: gin.H{
					"status": "not_ready",
					"checks": failures,
				},
			})
			return
		}

		Success(c, stdhttp.StatusOK, gin.H{
			"status": "ready",
		})
	})
}

// NewRouter creates a Gin engine with trusted-proxy, CORS, /healthz, and a
// catch-all OPTIONS handler, then registers every supplied Registrar.
//
// Call chain: main.buildRouterWithServices → http.NewRouter → corsMiddleware / Registrar.RegisterRoutes
func NewRouter(cfg config.Config, registrars ...Registrar) *gin.Engine {
	router := gin.New()
	trustedProxies := cfg.TrustedProxies
	if len(trustedProxies) == 0 {
		trustedProxies = nil
	}
	if err := router.SetTrustedProxies(trustedProxies); err != nil {
		panic(err)
	}
	router.Use(gin.Logger(), gin.Recovery())
	router.Use(corsMiddleware(cfg))

	router.GET("/healthz", func(c *gin.Context) {
		Success(c, stdhttp.StatusOK, gin.H{
			"status": "ok",
		})
	})
	router.OPTIONS("/*path", func(c *gin.Context) {
		c.Status(stdhttp.StatusNoContent)
	})

	for _, registrar := range registrars {
		if registrar == nil {
			continue
		}
		registrar.RegisterRoutes(router)
	}

	return router
}

// corsMiddleware returns a Gin middleware that sets Access-Control-Allow-Origin
// (wildcard or explicit match), Methods, Headers, and optionally Credentials.
// It aborts OPTIONS preflight requests with 204.
//
// Call chain: http.NewRouter → corsMiddleware → (no downstream)
func corsMiddleware(cfg config.Config) gin.HandlerFunc {
	allowedOrigins := make(map[string]struct{}, len(cfg.CORSAllowedOrigins))
	allowWildcard := false
	for _, origin := range cfg.CORSAllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		if origin == "*" && !cfg.CORSAllowCredentials {
			allowWildcard = true
			continue
		}
		allowedOrigins[origin] = struct{}{}
	}

	allowedMethods := strings.Join(cfg.CORSAllowedMethods, ",")
	if allowedMethods == "" {
		allowedMethods = "GET,POST,PUT,PATCH,DELETE"
	}
	allowedHeaders := strings.Join(cfg.CORSAllowedHeaders, ",")
	if allowedHeaders == "" {
		allowedHeaders = "Authorization,Content-Type"
	}

	return func(c *gin.Context) {
		origin := strings.TrimSpace(c.GetHeader("Origin"))
		if origin != "" {
			if allowWildcard {
				c.Header("Access-Control-Allow-Origin", "*")
			} else if _, ok := allowedOrigins[origin]; ok {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
			}
			if c.Writer.Header().Get("Access-Control-Allow-Origin") != "" {
				c.Header("Access-Control-Allow-Methods", allowedMethods)
				c.Header("Access-Control-Allow-Headers", allowedHeaders)
				if cfg.CORSAllowCredentials {
					c.Header("Access-Control-Allow-Credentials", "true")
				}
			}
		}

		if c.Request.Method == stdhttp.MethodOptions {
			c.AbortWithStatus(stdhttp.StatusNoContent)
			return
		}
		c.Next()
	}
}

// RegisterRoutes calls RegisterRoutes on every non-nil EngineRegistrar, wiring
// handlers that need the concrete *gin.Engine (e.g. for group-less mounts).
//
// Call chain: main.registerRoutes → http.RegisterRoutes → EngineRegistrar.RegisterRoutes
func RegisterRoutes(router *gin.Engine, registrars ...EngineRegistrar) {
	for _, registrar := range registrars {
		if registrar == nil {
			continue
		}
		registrar.RegisterRoutes(router)
	}
}
