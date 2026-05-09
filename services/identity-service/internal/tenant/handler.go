package tenant

import (
	stdhttp "net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
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

func (h *Handler) listTenants(c *gin.Context) {
	tenants, err := h.service.ListTenants(c.Request.Context())
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"tenants": tenants})
}

func (h *Handler) createTenant(c *gin.Context) {
	var request CreateTenantInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	record, err := h.service.CreateTenant(c.Request.Context(), request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusCreated, record)
}

func (h *Handler) updateTenant(c *gin.Context) {
	id, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request UpdateTenantInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	record, err := h.service.UpdateTenant(c.Request.Context(), id, request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, record)
}

func (h *Handler) addMember(c *gin.Context) {
	tenantID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request struct {
		UserID int64  `json:"user_id"`
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	member, err := h.service.AddMember(c.Request.Context(), AddMemberInput{
		TenantID: tenantID,
		UserID:   request.UserID,
		Status:   request.Status,
	})
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusCreated, member)
}

func (h *Handler) removeMember(c *gin.Context) {
	tenantID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}
	userID, err := parseInt64Param(c, "user_id")
	if err != nil {
		return
	}

	if err := h.service.RemoveMember(c.Request.Context(), tenantID, userID); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"removed": true})
}

func (h *Handler) listRoles(c *gin.Context) {
	tenantID := int64(0)
	if raw := c.Query("tenant_id"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid tenant_id"})
			return
		}
		tenantID = parsed
	}

	roles, err := h.service.ListRoles(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"roles": roles})
}

func (h *Handler) createRole(c *gin.Context) {
	var request CreateRoleInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role, err := h.service.CreateRole(c.Request.Context(), request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusCreated, role)
}

func (h *Handler) updateRole(c *gin.Context) {
	roleID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request UpdateRoleInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	role, err := h.service.UpdateRole(c.Request.Context(), roleID, request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, role)
}

func (h *Handler) deleteRole(c *gin.Context) {
	roleID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}

	if err := h.service.DeleteRole(c.Request.Context(), roleID); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"deleted": true})
}

func (h *Handler) grantPermissions(c *gin.Context) {
	roleID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request struct {
		PermissionIDs []int64 `json:"permission_ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.GrantPermissions(c.Request.Context(), roleID, request.PermissionIDs); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

func (h *Handler) revokePermission(c *gin.Context) {
	roleID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}
	permissionID, err := parseInt64Param(c, "permission_id")
	if err != nil {
		return
	}

	if err := h.service.RevokePermission(c.Request.Context(), roleID, permissionID); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

func (h *Handler) assignRoles(c *gin.Context) {
	memberID, err := parseInt64Param(c, "member_id")
	if err != nil {
		return
	}

	var request struct {
		RoleIDs []int64 `json:"role_ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.AssignRoles(c.Request.Context(), memberID, request.RoleIDs); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

func (h *Handler) removeRole(c *gin.Context) {
	memberID, err := parseInt64Param(c, "member_id")
	if err != nil {
		return
	}
	roleID, err := parseInt64Param(c, "role_id")
	if err != nil {
		return
	}

	if err := h.service.RemoveRole(c.Request.Context(), memberID, roleID); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

func parseInt64Param(c *gin.Context, name string) (int64, error) {
	value, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid " + name})
		return 0, err
	}
	return value, nil
}
