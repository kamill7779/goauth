package rbac

import (
	stdhttp "net/http"
	"strconv"

	httpserver "example.com/identity-service/internal/http"
	"example.com/identity-service/internal/session"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	service          *Service
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

func NewHandler(service *Service, authMiddleware, systemMiddleware gin.HandlerFunc) *Handler {
	return &Handler{
		service:          service,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	v1 := router.Group("/v1")
	if h.authMiddleware != nil {
		v1.Use(h.authMiddleware)
	}

	authz := v1.Group("/authz")
	if h.systemMiddleware != nil {
		authz.Use(h.systemMiddleware)
	}
	authz.POST("/check", h.check)
	authz.POST("/check-batch", h.checkBatch)

	v1.GET("/tenants/:tenant_id/my-permissions", h.myPermissions)
}

func (h *Handler) check(c *gin.Context) {
	var request struct {
		UserID     int64  `json:"user_id"`
		TenantID   int64  `json:"tenant_id"`
		Permission string `json:"permission"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	allowed, err := h.service.Can(c.Request.Context(), request.UserID, request.TenantID, request.Permission)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"allowed": allowed})
}

func (h *Handler) checkBatch(c *gin.Context) {
	var request struct {
		UserID      int64    `json:"user_id"`
		TenantID    int64    `json:"tenant_id"`
		Permissions []string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	results := make(map[string]bool, len(request.Permissions))
	for _, permission := range request.Permissions {
		allowed, err := h.service.Can(c.Request.Context(), request.UserID, request.TenantID, permission)
		if err != nil {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		results[permission] = allowed
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"results": results})
}

func (h *Handler) myPermissions(c *gin.Context) {
	claims, ok := session.ClaimsFromContext(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	tenantID, err := strconv.ParseInt(c.Param("tenant_id"), 10, 64)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
		return
	}
	if claims.TenantID == 0 {
		c.JSON(stdhttp.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if claims.TenantID != tenantID {
		c.JSON(stdhttp.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	permissions, err := h.service.ListPermissions(c.Request.Context(), userID, tenantID)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"permissions": permissions})
}
