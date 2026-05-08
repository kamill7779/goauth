package http

import (
	stdhttp "net/http"

	"example.com/identity-service/internal/config"
	"github.com/gin-gonic/gin"
)

func NewRouter(_ config.Config) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		Success(c, stdhttp.StatusOK, gin.H{
			"status": "ok",
		})
	})

	return router
}
