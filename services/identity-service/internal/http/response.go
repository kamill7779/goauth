// Package http provides the Gin router factory, CORS middleware, health/readiness
// endpoints, and a unified JSON response envelope ({success, data}).
package http

import "github.com/gin-gonic/gin"

type successResponse struct {
	Success bool `json:"success"`
	Data    any  `json:"data"`
}

// Success writes a JSON envelope {"success":true,"data":...} with the given HTTP status.
//
// Call chain: any handler → http.Success → gin.Context.JSON
func Success(c *gin.Context, status int, data any) {
	c.JSON(status, successResponse{
		Success: true,
		Data:    data,
	})
}

// Error writes a JSON envelope {"error":"..."} with the given HTTP status.
//
// Call chain: any handler → http.Error → gin.Context.JSON
func Error(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
}
