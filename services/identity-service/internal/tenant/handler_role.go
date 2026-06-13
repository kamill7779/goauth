package tenant

import (
	stdhttp "net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/util"
)

type roleCountRow struct {
	RoleID int64
	Count  int64
}

type rolePermissionIDsRow struct {
	RoleID       int64
	PermissionID int64
}

// listRoles returns a paginated, searchable list of roles optionally filtered
// by tenant, enriched with permissions and user counts.
//
// Call chain: HTTP GET /v1/admin/roles → listRoles → db + rolePayloads
func (h *Handler) listRoles(c *gin.Context) {
	tenantID := int64(0)
	if raw := c.Query("tenant_id"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			httpserver.Error(c, stdhttp.StatusBadRequest, "invalid tenant_id")
			return
		}
		tenantID = parsed
	}

	page, pageSize := util.Pagination(c)
	query := h.service.DB().WithContext(c.Request.Context()).Model(&store.Role{})
	if tenantID != 0 {
		query = query.Where("tenant_id = ?", tenantID)
	}
	if search := strings.ToLower(strings.TrimSpace(c.Query("search"))); search != "" {
		like := "%" + search + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(code) LIKE ? OR LOWER(description) LIKE ?", like, like, like)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	var roles []store.Role
	if err := query.
		Order(roleListOrder(c.Query("sort"))).
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&roles).Error; err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	items, err := h.rolePayloads(c, roles)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"roles":     items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// createRole creates a role from JSON body.
//
// Call chain: HTTP POST /v1/admin/roles → createRole → service.CreateRole + singleRolePayload
func (h *Handler) createRole(c *gin.Context) {
	var request CreateRoleInput
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	role, err := h.service.CreateRole(c.Request.Context(), request)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	item, err := h.singleRolePayload(c, *role)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusCreated, item)
}

// updateRole patch-updates a role by ID.
//
// Call chain: HTTP PATCH /v1/admin/roles/:id → updateRole → service.UpdateRole + singleRolePayload
func (h *Handler) updateRole(c *gin.Context) {
	roleID, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request UpdateRoleInput
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	role, err := h.service.UpdateRole(c.Request.Context(), roleID, request)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	item, err := h.singleRolePayload(c, *role)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, item)
}

// deleteRole deletes a role by ID.
//
// Call chain: HTTP DELETE /v1/admin/roles/:id → deleteRole → service.DeleteRole
func (h *Handler) deleteRole(c *gin.Context) {
	roleID, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}

	if err := h.service.DeleteRole(c.Request.Context(), roleID); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"deleted": true})
}

// grantPermissions assigns permissions to a role.
//
// Call chain: HTTP POST /v1/admin/roles/:id/permissions → grantPermissions → service.GrantPermissions
func (h *Handler) grantPermissions(c *gin.Context) {
	roleID, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request struct {
		PermissionIDs []int64 `json:"permission_ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.GrantPermissions(c.Request.Context(), roleID, request.PermissionIDs); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

// revokePermission removes a single permission from a role.
//
// Call chain: HTTP DELETE /v1/admin/roles/:id/permissions/:permission_id → revokePermission → service.RevokePermission
func (h *Handler) revokePermission(c *gin.Context) {
	roleID, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}
	permissionID, err := util.ParseInt64Param(c, "permission_id")
	if err != nil {
		return
	}

	if err := h.service.RevokePermission(c.Request.Context(), roleID, permissionID); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

// singleRolePayload wraps rolePayloads for a single role record.
func (h *Handler) singleRolePayload(c *gin.Context, role store.Role) (gin.H, error) {
	items, err := h.rolePayloads(c, []store.Role{role})
	if err != nil {
		return nil, err
	}
	return items[0], nil
}

// rolePayloads enriches role records with tenant name, permission IDs, and user counts.
//
// Call chain: listRoles → rolePayloads → tenantLookup + rolePermissionIDs + roleUserCounts
func (h *Handler) rolePayloads(c *gin.Context, roles []store.Role) ([]gin.H, error) {
	if len(roles) == 0 {
		return []gin.H{}, nil
	}
	roleIDs := make([]int64, 0, len(roles))
	tenantIDs := make([]int64, 0, len(roles))
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
		tenantIDs = append(tenantIDs, role.TenantID)
	}

	tenants, err := h.tenantLookup(c, tenantIDs)
	if err != nil {
		return nil, err
	}
	permissionIDs, err := h.rolePermissionIDs(c, roleIDs)
	if err != nil {
		return nil, err
	}
	userCounts, err := h.roleUserCounts(c, roleIDs)
	if err != nil {
		return nil, err
	}

	items := make([]gin.H, 0, len(roles))
	for _, role := range roles {
		tenantRecord := tenants[role.TenantID]
		permissions := permissionIDs[role.ID]
		items = append(items, gin.H{
			"id":                role.ID,
			"tenant_id":         role.TenantID,
			"tenant_name":       tenantRecord.Name,
			"tenant_slug":       tenantRecord.Slug,
			"tenant_scope":      "tenant:" + tenantRecord.Slug,
			"code":              role.Code,
			"name":              role.Name,
			"description":       role.Description,
			"is_system":         role.IsSystem,
			"permission_ids":    permissions,
			"permissions_count": len(permissions),
			"users_count":       userCounts[role.ID],
			"created_at":        role.CreatedAt,
			"updated_at":        role.UpdatedAt,
		})
	}
	return items, nil
}

// rolePermissionIDs returns permission IDs grouped by role ID.
//
// Call chain: rolePayloads → rolePermissionIDs → db query role_permissions
func (h *Handler) rolePermissionIDs(c *gin.Context, roleIDs []int64) (map[int64][]int64, error) {
	var rows []rolePermissionIDsRow
	if err := h.service.DB().WithContext(c.Request.Context()).
		Table("role_permissions").
		Select("role_id, permission_id").
		Where("role_id IN ?", roleIDs).
		Order("permission_id ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	result := map[int64][]int64{}
	for _, row := range rows {
		result[row.RoleID] = append(result[row.RoleID], row.PermissionID)
	}
	for _, roleID := range roleIDs {
		if result[roleID] == nil {
			result[roleID] = []int64{}
		}
	}
	return result, nil
}

// roleUserCounts returns distinct user counts per role via member_roles join.
//
// Call chain: rolePayloads → roleUserCounts → db query member_roles + tenant_members
func (h *Handler) roleUserCounts(c *gin.Context, roleIDs []int64) (map[int64]int64, error) {
	var rows []roleCountRow
	if err := h.service.DB().WithContext(c.Request.Context()).
		Table("member_roles AS mr").
		Select("mr.role_id AS role_id, COUNT(DISTINCT tm.user_id) AS count").
		Joins("JOIN tenant_members AS tm ON tm.id = mr.member_id AND tm.deleted_at IS NULL").
		Where("mr.role_id IN ?", roleIDs).
		Group("mr.role_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	result := map[int64]int64{}
	for _, row := range rows {
		result[row.RoleID] = row.Count
	}
	return result, nil
}
