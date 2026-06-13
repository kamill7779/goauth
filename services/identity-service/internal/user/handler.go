package user

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/lockout"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
)

// Handler serves admin user management HTTP endpoints: CRUD, bulk operations,
// password reset, lockout control, and enable/disable.
type Handler struct {
	service          *Service
	tenantService    *tenant.Service
	sessionService   *session.Service
	lockoutManager   *lockout.Manager
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

// NewHandler creates a user Handler with constructor-injected collaborators.
//
// Call chain: main → NewHandler → Handler
func NewHandler(service *Service, tenantService *tenant.Service, sessionService *session.Service, authMiddleware, systemMiddleware gin.HandlerFunc, lockoutManager *lockout.Manager) *Handler {
	return &Handler{
		service:          service,
		tenantService:    tenantService,
		sessionService:   sessionService,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
		lockoutManager:   lockoutManager,
	}
}

// SetLockoutManager is deprecated; inject the lockout manager via NewHandler instead.
func (h *Handler) SetLockoutManager(m *lockout.Manager) {
	h.lockoutManager = m
}

// RegisterRoutes mounts user admin endpoints under /v1/admin with auth and
// system middleware when configured.
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

// parseUserID parses the :id path parameter as int64 and writes a 400 error on failure.

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

// userListPayloads enriches a list of users with membership, tenant, role, and
// last-login data for the list endpoint.
//
// Call chain: listUsers → userListPayloads → userMemberships + userLastLogins
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

// userMemberships returns tenant memberships with roles for a set of user IDs.
//
// Call chain: userListPayloads → userMemberships → db raw SQL join
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

// userLastLogins returns the most recent login timestamp for each user ID.
//
// Call chain: userListPayloads → userLastLogins → db raw SQL
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

// joinedOrDash joins non-empty strings with ", ", returning "-" when none are present.
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

// formatSQLTime converts a time.Time, string, or []byte to RFC3339 format.
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
