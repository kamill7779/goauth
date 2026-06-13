// Package rbac serves HTTP endpoints for permission checks and retrieving
// the current user's permissions within a tenant.
//
// The /v1/authz/check and /v1/authz/check-batch endpoints are internal
// (system middleware) used by other services for authorization decisions.
package rbac

import (
	stdhttp "net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/session"
)

// Handler serves RBAC HTTP endpoints for permission checks.
type Handler struct {
	service          *Service
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

// NewHandler creates an RBAC Handler with injected service and middleware.
//
// Call chain: main → NewHandler → Handler
func NewHandler(service *Service, authMiddleware, systemMiddleware gin.HandlerFunc) *Handler {
	return &Handler{
		service:          service,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
	}
}

// RegisterRoutes mounts RBAC endpoints: /v1/authz/check and /v1/authz/check-batch
// (system-gated) and /v1/tenants/:tenant_id/my-permissions (auth-gated).
//
// Call chain: main → router setup → RegisterRoutes → gin router
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

// check performs a single permission check for a (user, tenant, permission) tuple.
//
// NOTE: This endpoint trusts the caller (internal service behind systemMiddleware).
// No tenant-scope validation is performed on the request body.
//
// Call chain: HTTP POST /v1/authz/check → check → service.Can
func (h *Handler) check(c *gin.Context) {
	var request struct {
		UserID     int64  `json:"user_id"`
		TenantID   int64  `json:"tenant_id"`
		Permission string `json:"permission"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	allowed, err := h.service.Can(c.Request.Context(), request.UserID, request.TenantID, request.Permission)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"allowed": allowed})
}

// checkBatch performs multiple permission checks in a single request.
// Stops on the first error from the service.
//
// NOTE: This endpoint trusts the caller (internal service behind systemMiddleware).
// No tenant-scope validation is performed on the request body.
//
// Call chain: HTTP POST /v1/authz/check-batch → checkBatch → service.Can
func (h *Handler) checkBatch(c *gin.Context) {
	var request struct {
		UserID      int64    `json:"user_id"`
		TenantID    int64    `json:"tenant_id"`
		Permissions []string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	results := make(map[string]bool, len(request.Permissions))
	for _, permission := range request.Permissions {
		allowed, err := h.service.Can(c.Request.Context(), request.UserID, request.TenantID, permission)
		if err != nil {
			httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
			return
		}
		results[permission] = allowed
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"results": results})
}

// myPermissions returns the authenticated user's effective permissions for a
// tenant, enforcing that the JWT tenant matches the requested tenant.
//
// Call chain: HTTP GET /v1/tenants/:tenant_id/my-permissions → myPermissions → session.ClaimsFromContext + service.ListPermissions
func (h *Handler) myPermissions(c *gin.Context) {
	claims, ok := session.ClaimsFromContext(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
		return
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "invalid token")
		return
	}

	tenantID, err := strconv.ParseInt(c.Param("tenant_id"), 10, 64)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, "invalid tenant_id")
		return
	}
	if claims.TenantID == 0 {
		httpserver.Error(c, stdhttp.StatusForbidden, "forbidden")
		return
	}
	if claims.TenantID != tenantID {
		httpserver.Error(c, stdhttp.StatusForbidden, "forbidden")
		return
	}

	permissions, err := h.service.ListPermissions(c.Request.Context(), userID, tenantID)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"permissions": permissions})
}
