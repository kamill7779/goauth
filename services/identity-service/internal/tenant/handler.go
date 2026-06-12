package tenant

import (
	stdhttp "net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
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
	page, pageSize := pagination(c)
	query := h.service.DB().WithContext(c.Request.Context()).Model(&store.Tenant{})
	if search := strings.ToLower(strings.TrimSpace(c.Query("search"))); search != "" {
		like := "%" + search + "%"
		query = query.Where("LOWER(name) LIKE ? OR LOWER(slug) LIKE ?", like, like)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	var tenants []store.Tenant
	if err := query.
		Order(tenantListOrder(c.Query("sort"))).
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&tenants).Error; err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	items, err := h.tenantPayloads(c, tenants)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"tenants":   items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (h *Handler) createTenant(c *gin.Context) {
	var request CreateTenantInput
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	record, err := h.service.CreateTenant(c.Request.Context(), request)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	item, err := h.singleTenantPayload(c, *record)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusCreated, item)
}

func (h *Handler) updateTenant(c *gin.Context) {
	id, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request UpdateTenantInput
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	record, err := h.service.UpdateTenant(c.Request.Context(), id, request)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	item, err := h.singleTenantPayload(c, *record)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, item)
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	member, err := h.service.AddMember(c.Request.Context(), AddMemberInput{
		TenantID: tenantID,
		UserID:   request.UserID,
		Status:   request.Status,
	})
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"removed": true})
}

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

	page, pageSize := pagination(c)
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

func (h *Handler) updateRole(c *gin.Context) {
	roleID, err := parseInt64Param(c, "id")
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

func (h *Handler) deleteRole(c *gin.Context) {
	roleID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}

	if err := h.service.DeleteRole(c.Request.Context(), roleID); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.GrantPermissions(c.Request.Context(), roleID, request.PermissionIDs); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.AssignRoles(c.Request.Context(), memberID, request.RoleIDs); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

func parseInt64Param(c *gin.Context, name string) (int64, error) {
	value, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, "invalid " + name)
		return 0, err
	}
	return value, nil
}

type tenantCountRow struct {
	TenantID int64
	Count    int64
}

type roleCountRow struct {
	RoleID int64
	Count  int64
}

type rolePermissionIDsRow struct {
	RoleID       int64
	PermissionID int64
}

func (h *Handler) singleTenantPayload(c *gin.Context, tenantRecord store.Tenant) (gin.H, error) {
	items, err := h.tenantPayloads(c, []store.Tenant{tenantRecord})
	if err != nil {
		return nil, err
	}
	return items[0], nil
}

func (h *Handler) tenantPayloads(c *gin.Context, tenants []store.Tenant) ([]gin.H, error) {
	if len(tenants) == 0 {
		return []gin.H{}, nil
	}
	tenantIDs := make([]int64, 0, len(tenants))
	for _, tenantRecord := range tenants {
		tenantIDs = append(tenantIDs, tenantRecord.ID)
	}
	memberCounts, err := h.groupCounts(c, "tenant_members", "tenant_id", "tenant_id IN ? AND deleted_at IS NULL", tenantIDs)
	if err != nil {
		return nil, err
	}
	roleCounts, err := h.groupCounts(c, "roles", "tenant_id", "tenant_id IN ?", tenantIDs)
	if err != nil {
		return nil, err
	}
	clientCounts, err := h.oauthClientCounts(c, tenantIDs)
	if err != nil {
		return nil, err
	}

	items := make([]gin.H, 0, len(tenants))
	for _, tenantRecord := range tenants {
		items = append(items, gin.H{
			"id":                  tenantRecord.ID,
			"name":                tenantRecord.Name,
			"slug":                tenantRecord.Slug,
			"status":              tenantRecord.Status,
			"members_count":       memberCounts[tenantRecord.ID],
			"roles_count":         roleCounts[tenantRecord.ID],
			"oauth_clients_count": clientCounts[tenantRecord.ID],
			"default_policy":      "manual_review",
			"created_at":          tenantRecord.CreatedAt,
			"updated_at":          tenantRecord.UpdatedAt,
		})
	}
	return items, nil
}

func (h *Handler) singleRolePayload(c *gin.Context, role store.Role) (gin.H, error) {
	items, err := h.rolePayloads(c, []store.Role{role})
	if err != nil {
		return nil, err
	}
	return items[0], nil
}

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

func (h *Handler) tenantLookup(c *gin.Context, tenantIDs []int64) (map[int64]store.Tenant, error) {
	var tenants []store.Tenant
	if err := h.service.DB().WithContext(c.Request.Context()).Where("id IN ?", uniqueInt64s(tenantIDs)).Find(&tenants).Error; err != nil {
		return nil, err
	}
	result := make(map[int64]store.Tenant, len(tenants))
	for _, tenantRecord := range tenants {
		result[tenantRecord.ID] = tenantRecord
	}
	return result, nil
}

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

func (h *Handler) groupCounts(c *gin.Context, table, groupColumn, where string, ids []int64) (map[int64]int64, error) {
	var rows []tenantCountRow
	if err := h.service.DB().WithContext(c.Request.Context()).
		Table(table).
		Select(groupColumn+" AS tenant_id, COUNT(*) AS count").
		Where(where, ids).
		Group(groupColumn).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	result := map[int64]int64{}
	for _, row := range rows {
		result[row.TenantID] = row.Count
	}
	return result, nil
}

func (h *Handler) oauthClientCounts(c *gin.Context, tenantIDs []int64) (map[int64]int64, error) {
	var rows []tenantCountRow
	if err := h.service.DB().WithContext(c.Request.Context()).
		Model(&store.OAuthClient{}).
		Select("tenant_id AS tenant_id, COUNT(*) AS count").
		Where("tenant_id IN ?", tenantIDs).
		Group("tenant_id").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	result := map[int64]int64{}
	for _, row := range rows {
		result[row.TenantID] = row.Count
	}
	return result, nil
}

func pagination(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.Query("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

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
