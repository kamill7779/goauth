package user

import (
	stdhttp "net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/util"
)

// listUsers returns a paginated, filtered user list with tenant/role enrichment.
//
// Call chain: HTTP GET /v1/admin/users → listUsers → service.ListUsersPage + userListPayloads
func (h *Handler) listUsers(c *gin.Context) {
	tenantID, err := optionalInt64Query(c, "tenant_id")
	if err != nil {
		return
	}
	roleID, err := optionalInt64Query(c, "role_id")
	if err != nil {
		return
	}
	page, pageSize := util.Pagination(c)
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	items, err := h.userListPayloads(c, result.Users)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"users":     items,
		"total":     result.Total,
		"page":      result.Page,
		"page_size": result.PageSize,
	})
}

// createUser creates a user from JSON body.
//
// Call chain: HTTP POST /v1/admin/users → createUser → service.CreateUser
func (h *Handler) createUser(c *gin.Context) {
	var request CreateUserInput
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	user, err := h.service.CreateUser(c.Request.Context(), request)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusCreated, userPayload(*user))
}

// updateUser patch-updates a user by ID from JSON body.
//
// Call chain: HTTP PATCH /v1/admin/users/:id → updateUser → service.UpdateUser
func (h *Handler) updateUser(c *gin.Context) {
	id, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request UpdateUserInput
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	user, err := h.service.UpdateUser(c.Request.Context(), id, request)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, userPayload(*user))
}

// disableUser sets a user's status to disabled. Protected users are rejected.
//
// Call chain: HTTP POST /v1/admin/users/:id/disable → disableUser → service.DisableUser
func (h *Handler) disableUser(c *gin.Context) {
	id, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}

	if err := h.service.DisableUser(c.Request.Context(), id); err != nil {
		status := stdhttp.StatusBadRequest
		if err == ErrProtectedUser {
			status = stdhttp.StatusForbidden
		}
		httpserver.Error(c, status, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"disabled": true})
}

// enableUser sets a user's status back to active.
//
// Call chain: HTTP POST /v1/admin/users/:id/enable → enableUser → service.EnableUser
func (h *Handler) enableUser(c *gin.Context) {
	id, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}

	if err := h.service.EnableUser(c.Request.Context(), id); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"enabled": true})
}

// resetPassword sets a new password for a user (admin-initiated).
//
// Call chain: HTTP POST /v1/admin/users/:id/reset-password → resetPassword → service.ResetPassword
func (h *Handler) resetPassword(c *gin.Context) {
	id, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}

	var request struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	if err := h.service.ResetPassword(c.Request.Context(), id, request.NewPassword); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"reset": true})
}

// unlockUser clears lockout state for a user. No-op when lockout manager is nil.
//
// Call chain: HTTP POST /v1/admin/users/:id/unlock → unlockUser → lockoutManager.Unlock
func (h *Handler) unlockUser(c *gin.Context) {
	id, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}
	if h.lockoutManager == nil {
		httpserver.Success(c, stdhttp.StatusOK, gin.H{"unlocked": true})
		return
	}
	if err := h.lockoutManager.Unlock(c.Request.Context(), id); err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"unlocked": true})
}

// userPayload maps a store.User to the standard API response shape.
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

// optionalInt64Query parses a query parameter as int64; returns 0 if empty.
func optionalInt64Query(c *gin.Context, name string) (int64, error) {
	raw := strings.TrimSpace(c.Query(name))
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, "invalid "+name)
		return 0, err
	}
	return value, nil
}
