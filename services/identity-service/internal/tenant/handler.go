// Package tenant manages multi-tenant lifecycle via HTTP: tenant CRUD, membership,
// role CRUD, permission grant/revoke, and role assignment/removal.
//
// All admin routes are mounted under /v1/admin and are gated behind auth
// and system middleware.
package tenant

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// Handler serves admin HTTP endpoints for tenant and role management.
type Handler struct {
	service          *Service
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

// NewHandler creates a tenant Handler with injected service and middleware.
//
// Call chain: main → NewHandler → Handler
func NewHandler(service *Service, authMiddleware, systemMiddleware gin.HandlerFunc) *Handler {
	return &Handler{
		service:          service,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
	}
}

// RegisterRoutes mounts tenant and role admin endpoints under /v1/admin with
// auth and system middleware when configured.
//
// Call chain: main → router setup → RegisterRoutes → gin router
func (h *Handler) RegisterRoutes(router *gin.Engine) {
	admin := router.Group("/v1/admin")
	if h.authMiddleware != nil {
		admin.Use(h.authMiddleware)
	}
	if h.systemMiddleware != nil {
		admin.Use(h.systemMiddleware)
	}

	admin.GET("/tenants", h.listTenants)
	admin.POST("/tenants", h.createTenant)
	admin.PATCH("/tenants/:id", h.updateTenant)
	admin.POST("/tenants/:id/members", h.addMember)
	admin.DELETE("/tenants/:id/members/:user_id", h.removeMember)

	admin.GET("/roles", h.listRoles)
	admin.POST("/roles", h.createRole)
	admin.PATCH("/roles/:id", h.updateRole)
	admin.DELETE("/roles/:id", h.deleteRole)
	admin.POST("/roles/:id/permissions", h.grantPermissions)
	admin.DELETE("/roles/:id/permissions/:permission_id", h.revokePermission)
	admin.POST("/members/:member_id/roles", h.assignRoles)
	admin.DELETE("/members/:member_id/roles/:role_id", h.removeRole)
}

// tenantListOrder returns an ORDER BY clause for tenant listing, defaulting to name ASC.
func tenantListOrder(sort string) string {
	switch strings.TrimSpace(sort) {
	case "name_desc":
		return "name DESC, id DESC"
	case "slug_asc":
		return "slug ASC, id ASC"
	case "slug_desc":
		return "slug DESC, id DESC"
	case "created_at_asc":
		return "created_at ASC, id ASC"
	case "created_at_desc":
		return "created_at DESC, id DESC"
	default:
		return "name ASC, id ASC"
	}
}

// roleListOrder returns an ORDER BY clause for role listing, defaulting to name ASC.
func roleListOrder(sort string) string {
	switch strings.TrimSpace(sort) {
	case "name_desc":
		return "name DESC, id DESC"
	case "code_asc":
		return "code ASC, id ASC"
	case "code_desc":
		return "code DESC, id DESC"
	case "created_at_desc":
		return "created_at DESC, id DESC"
	case "created_at_asc":
		return "created_at ASC, id ASC"
	default:
		return "name ASC, id ASC"
	}
}

// uniqueInt64s returns a deduplicated copy of the input slice, preserving order.
func uniqueInt64s(values []int64) []int64 {
	seen := map[int64]struct{}{}
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
