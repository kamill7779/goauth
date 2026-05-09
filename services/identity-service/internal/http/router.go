package http

import (
	stdhttp "net/http"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
)

type Registrar interface {
	RegisterRoutes(router gin.IRouter)
}

type EngineRegistrar interface {
	RegisterRoutes(*gin.Engine)
}

func NewRouter(_ config.Config, registrars ...Registrar) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		Success(c, stdhttp.StatusOK, gin.H{
			"status": "ok",
		})
	})

	for _, registrar := range registrars {
		if registrar == nil {
			continue
		}
		registrar.RegisterRoutes(router)
	}

	return router
}

func RegisterRoutes(router *gin.Engine, registrars ...EngineRegistrar) {
	for _, registrar := range registrars {
		if registrar == nil {
			continue
		}
		registrar.RegisterRoutes(router)
	}
}
