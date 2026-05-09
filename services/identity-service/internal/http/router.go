package http

import (
	stdhttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
)

type Registrar interface {
	RegisterRoutes(router gin.IRouter)
}

type EngineRegistrar interface {
	RegisterRoutes(*gin.Engine)
}

func NewRouter(cfg config.Config, registrars ...Registrar) *gin.Engine {
	router := gin.New()
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

func RegisterRoutes(router *gin.Engine, registrars ...EngineRegistrar) {
	for _, registrar := range registrars {
		if registrar == nil {
			continue
		}
		registrar.RegisterRoutes(router)
	}
}
