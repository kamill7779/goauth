package http

import (
	stdhttp "net/http"

	"example.com/identity-service/internal/config"
	"github.com/gin-gonic/gin"
)

type Registrar interface {
	RegisterRoutes(router gin.IRouter)
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
