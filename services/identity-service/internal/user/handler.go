package user

import (
	stdhttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/lockout"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
)

type Handler struct {
	service          *Service
	tenantService    *tenant.Service
	sessionService   *session.Service
	lockoutManager   *lockout.Manager
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

func NewHandler(service *Service, tenantService *tenant.Service, sessionService *session.Service, authMiddleware, systemMiddleware gin.HandlerFunc) *Handler {
	return &Handler{
		service:          service,
		tenantService:    tenantService,
		sessionService:   sessionService,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
	}
}

func (h *Handler) SetLockoutManager(m *lockout.Manager) {
	h.lockoutManager = m
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	admin := router.Group("/v1/admin")
	if h.authMiddleware != nil {
		admin.Use(h.authMiddleware)
	}
	if h.systemMiddleware != nil {
		admin.Use(h.systemMiddleware)
	}

	admin.GET("/users", h.listUsers)
	admin.POST("/users", h.createUser)
	admin.POST("/users/bulk-disable", h.bulkDisableUsers)
	admin.POST("/users/bulk-enable", h.bulkEnableUsers)
	admin.POST("/users/bulk-logout", h.bulkLogoutUsers)
	admin.POST("/users/bulk-add-to-tenant", h.bulkAddUsersToTenant)
	admin.POST("/users/bulk-remove-from-tenant", h.bulkRemoveUsersFromTenant)
	admin.PATCH("/users/:id", h.updateUser)
	admin.POST("/users/:id/disable", h.disableUser)
	admin.POST("/users/:id/enable", h.enableUser)
	admin.POST("/users/:id/reset-password", h.resetPassword)
	admin.POST("/users/:id/unlock", h.unlockUser)
}

func (h *Handler) listUsers(c *gin.Context) {
	tenantID, err := optionalInt64Query(c, "tenant_id")
	if err != nil {
		return
	}
	roleID, err := optionalInt64Query(c, "role_id")
	if err != nil {
		return
	}
	page, pageSize := pagination(c)
	result, err := h.service.ListUsersPage(c.Request.Context(), ListUsersInput{
		Search:   c.Query("search"),
		Status:   c.Query("status"),
		Sort:     c.Query("sort"),
		TenantID: tenantID,
		RoleID:   roleID,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	items, err := h.userListPayloads(c, result.Users)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"users":     items,
		"total":     result.Total,
		"page":      result.Page,
		"page_size": result.PageSize,
	})
}

func (h *Handler) createUser(c *gin.Context) {
	var request CreateUserInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.service.CreateUser(c.Request.Context(), request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusCreated, userPayload(*user))
}

func (h *Handler) updateUser(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	var request UpdateUserInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.service.UpdateUser(c.Request.Context(), id, request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, userPayload(*user))
}

func (h *Handler) disableUser(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	if err := h.service.DisableUser(c.Request.Context(), id); err != nil {
		status := stdhttp.StatusBadRequest
		if err == ErrProtectedUser {
			status = stdhttp.StatusForbidden
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"disabled": true})
}

func (h *Handler) enableUser(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	if err := h.service.EnableUser(c.Request.Context(), id); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"enabled": true})
}

func (h *Handler) resetPassword(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	var request struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.ResetPassword(c.Request.Context(), id, request.NewPassword); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"reset": true})
}

func (h *Handler) unlockUser(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}
	if h.lockoutManager == nil {
		httpserver.Success(c, stdhttp.StatusOK, gin.H{"unlocked": true})
		return
	}
	if err := h.lockoutManager.Unlock(c.Request.Context(), id); err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"unlocked": true})
}

func (h *Handler) bulkDisableUsers(c *gin.Context) {
	userIDs, ok := h.bulkUserIDs(c)
	if !ok {
		return
	}
	for _, userID := range userIDs {
		protected, err := h.service.isProtectedUser(c.Request.Context(), userID)
		if err != nil {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error(), "user_id": userID})
			return
		}
		if protected {
			c.JSON(stdhttp.StatusForbidden, gin.H{"error": ErrProtectedUser.Error(), "user_id": userID})
			return
		}
	}
	for _, userID := range userIDs {
		if err := h.service.DisableUser(c.Request.Context(), userID); err != nil {
			status := stdhttp.StatusBadRequest
			if err == ErrProtectedUser {
				status = stdhttp.StatusForbidden
			}
			c.JSON(status, gin.H{"error": err.Error(), "user_id": userID})
			return
		}
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated_count": len(userIDs)})
}

func (h *Handler) bulkEnableUsers(c *gin.Context) {
	userIDs, ok := h.bulkUserIDs(c)
	if !ok {
		return
	}
	for _, userID := range userIDs {
		if err := h.service.EnableUser(c.Request.Context(), userID); err != nil {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error(), "user_id": userID})
			return
		}
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated_count": len(userIDs)})
}

func (h *Handler) bulkLogoutUsers(c *gin.Context) {
	userIDs, ok := h.bulkUserIDs(c)
	if !ok {
		return
	}
	if h.sessionService == nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": "session service not configured"})
		return
	}
	for _, userID := range userIDs {
		if err := h.sessionService.LogoutAll(c.Request.Context(), userID); err != nil {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error(), "user_id": userID})
			return
		}
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"revoked_count": len(userIDs)})
}

func (h *Handler) bulkAddUsersToTenant(c *gin.Context) {
	request, ok := h.bulkTenantRequest(c)
	if !ok {
		return
	}
	if h.tenantService == nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": "tenant service not configured"})
		return
	}
	status := strings.TrimSpace(request.Status)
	if status == "" {
		status = store.MemberStatusActive
	}
	for _, userID := range request.UserIDs {
		if _, err := h.tenantService.AddMember(c.Request.Context(), tenant.AddMemberInput{
			TenantID: request.TenantID,
			UserID:   userID,
			Status:   status,
		}); err != nil {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error(), "user_id": userID})
			return
		}
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated_count": len(request.UserIDs)})
}

func (h *Handler) bulkRemoveUsersFromTenant(c *gin.Context) {
	request, ok := h.bulkTenantRequest(c)
	if !ok {
		return
	}
	if h.tenantService == nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": "tenant service not configured"})
		return
	}
	for _, userID := range request.UserIDs {
		if err := h.tenantService.RemoveMember(c.Request.Context(), request.TenantID, userID); err != nil {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error(), "user_id": userID})
			return
		}
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated_count": len(request.UserIDs)})
}

func parseUserID(c *gin.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, err
	}
	return id, nil
}

func userPayload(user store.User) gin.H {
	return gin.H{
		"id":             user.ID,
		"username":       user.Username,
		"nickname":       user.Nickname,
		"email":          user.Email,
		"display_name":   user.Nickname,
		"avatar_url":     user.AvatarURL,
		"status":         user.Status,
		"email_verified": user.EmailVerifiedAt != nil,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	}
}

type bulkUserRequest struct {
	UserIDs []int64 `json:"user_ids"`
}

type bulkTenantUserRequest struct {
	TenantID int64   `json:"tenant_id"`
	UserIDs  []int64 `json:"user_ids"`
	Status   string  `json:"status"`
}

type membershipRow struct {
	UserID       int64
	MemberID     int64
	TenantID     int64
	TenantName   string
	TenantSlug   string
	MemberStatus string
	RoleID       int64
	RoleName     string
	RoleCode     string
}

func (h *Handler) userListPayloads(c *gin.Context, users []store.User) ([]gin.H, error) {
	if len(users) == 0 {
		return []gin.H{}, nil
	}

	userIDs := make([]int64, 0, len(users))
	for _, user := range users {
		userIDs = append(userIDs, user.ID)
	}

	memberships, err := h.userMemberships(c, userIDs)
	if err != nil {
		return nil, err
	}
	lastLogins, err := h.userLastLogins(c, userIDs)
	if err != nil {
		return nil, err
	}

	items := make([]gin.H, 0, len(users))
	for _, userRecord := range users {
		item := userPayload(userRecord)
		tenantDetails := memberships[userRecord.ID]
		tenantLabels := make([]string, 0, len(tenantDetails))
		roleLabels := make([]string, 0)
		seenRoles := map[string]struct{}{}
		for _, tenantItem := range tenantDetails {
			tenantLabels = append(tenantLabels, stringFromGinH(tenantItem, "name"))
			for _, roleItem := range tenantItem["roles"].([]gin.H) {
				roleName := stringFromGinH(roleItem, "name")
				if _, ok := seenRoles[roleName]; ok {
					continue
				}
				seenRoles[roleName] = struct{}{}
				roleLabels = append(roleLabels, roleName)
			}
		}
		item["tenants"] = tenantDetails
		item["tenant"] = joinedOrDash(tenantLabels)
		item["role"] = joinedOrDash(roleLabels)
		if lastLogin, ok := lastLogins[userRecord.ID]; ok {
			item["last_login"] = lastLogin
		} else {
			item["last_login"] = ""
		}
		items = append(items, item)
	}
	return items, nil
}

func (h *Handler) userMemberships(c *gin.Context, userIDs []int64) (map[int64][]gin.H, error) {
	var rows []membershipRow
	if err := h.service.db.WithContext(c.Request.Context()).
		Table("tenant_members AS tm").
		Select(`
			tm.user_id AS user_id,
			tm.id AS member_id,
			t.id AS tenant_id,
			t.name AS tenant_name,
			t.slug AS tenant_slug,
			tm.status AS member_status,
			COALESCE(r.id, 0) AS role_id,
			COALESCE(r.name, '') AS role_name,
			COALESCE(r.code, '') AS role_code
		`).
		Joins("JOIN tenants AS t ON t.id = tm.tenant_id AND t.deleted_at IS NULL").
		Joins("LEFT JOIN member_roles AS mr ON mr.member_id = tm.id").
		Joins("LEFT JOIN roles AS r ON r.id = mr.role_id").
		Where("tm.user_id IN ? AND tm.deleted_at IS NULL", userIDs).
		Order("t.name ASC, r.name ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	result := make(map[int64][]gin.H, len(userIDs))
	tenantIndex := map[int64]map[int64]gin.H{}
	roleSeen := map[int64]map[int64]struct{}{}
	for _, row := range rows {
		if tenantIndex[row.UserID] == nil {
			tenantIndex[row.UserID] = map[int64]gin.H{}
		}
		tenantItem, ok := tenantIndex[row.UserID][row.TenantID]
		if !ok {
			tenantItem = gin.H{
				"member_id": row.MemberID,
				"id":        row.TenantID,
				"name":      row.TenantName,
				"slug":      row.TenantSlug,
				"status":    row.MemberStatus,
				"roles":     []gin.H{},
			}
			tenantIndex[row.UserID][row.TenantID] = tenantItem
			result[row.UserID] = append(result[row.UserID], tenantItem)
		}
		if row.RoleID == 0 {
			continue
		}
		if roleSeen[row.MemberID] == nil {
			roleSeen[row.MemberID] = map[int64]struct{}{}
		}
		if _, ok := roleSeen[row.MemberID][row.RoleID]; ok {
			continue
		}
		roleSeen[row.MemberID][row.RoleID] = struct{}{}
		roles := tenantItem["roles"].([]gin.H)
		tenantItem["roles"] = append(roles, gin.H{
			"id":   row.RoleID,
			"name": row.RoleName,
			"code": row.RoleCode,
		})
	}
	for _, userID := range userIDs {
		if result[userID] == nil {
			result[userID] = []gin.H{}
		}
	}
	return result, nil
}

func (h *Handler) userLastLogins(c *gin.Context, userIDs []int64) (map[int64]string, error) {
	rows, err := h.service.db.WithContext(c.Request.Context()).
		Raw("SELECT user_id, MAX(created_at) AS last_login FROM refresh_tokens WHERE user_id IN ? GROUP BY user_id", userIDs).
		Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[int64]string{}
	for rows.Next() {
		var userID int64
		var raw any
		if err := rows.Scan(&userID, &raw); err != nil {
			return nil, err
		}
		result[userID] = formatSQLTime(raw)
	}
	return result, rows.Err()
}

func (h *Handler) bulkUserIDs(c *gin.Context) ([]int64, bool) {
	var request bulkUserRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, false
	}
	userIDs, ok := normalizeUserIDs(c, request.UserIDs)
	return userIDs, ok
}

func (h *Handler) bulkTenantRequest(c *gin.Context) (bulkTenantUserRequest, bool) {
	var request bulkTenantUserRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return request, false
	}
	if request.TenantID <= 0 {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "tenant_id is required"})
		return request, false
	}
	userIDs, ok := normalizeUserIDs(c, request.UserIDs)
	if !ok {
		return request, false
	}
	request.UserIDs = userIDs
	return request, true
}

func normalizeUserIDs(c *gin.Context, raw []int64) ([]int64, bool) {
	seen := map[int64]struct{}{}
	userIDs := make([]int64, 0, len(raw))
	for _, userID := range raw {
		if userID <= 0 {
			c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "user_ids must be positive"})
			return nil, false
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		userIDs = append(userIDs, userID)
	}
	if len(userIDs) == 0 {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "user_ids is required"})
		return nil, false
	}
	if len(userIDs) > 100 {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "user_ids cannot exceed 100"})
		return nil, false
	}
	return userIDs, true
}

func optionalInt64Query(c *gin.Context, name string) (int64, error) {
	raw := strings.TrimSpace(c.Query(name))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid " + name})
		return 0, err
	}
	return value, nil
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

func joinedOrDash(values []string) string {
	clean := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			clean = append(clean, value)
		}
	}
	if len(clean) == 0 {
		return "-"
	}
	return strings.Join(clean, ", ")
}

func stringFromGinH(item gin.H, key string) string {
	value, _ := item[key].(string)
	return value
}

func formatSQLTime(value any) string {
	switch typed := value.(type) {
	case time.Time:
		return typed.Format(time.RFC3339)
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}
