// Package http provides the Gin router factory, CORS middleware, health/readiness
// endpoints, and a unified JSON response envelope ({success, data}).
package http

import "github.com/gin-gonic/gin"

type successResponse struct {
	Success bool `json:"success"`
	Data    any  `json:"data"`
}

func Success(c *gin.Context, status int, data any) {
	c.JSON(status, successResponse{
		Success: true,
		Data:    data,
	})
}
