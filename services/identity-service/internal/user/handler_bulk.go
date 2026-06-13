package user

import (
	stdhttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
)

type bulkUserRequest struct {
	UserIDs []int64 `json:"user_ids"`
}

type bulkTenantUserRequest struct {
	TenantID int64   `json:"tenant_id"`
	UserIDs  []int64 `json:"user_ids"`
	Status   string  `json:"status"`
}

// bulkDisableUsers disables multiple users, checking each for protected status first.
//
// Call chain: HTTP POST /v1/admin/users/bulk-disable → bulkDisableUsers → service.isProtectedUser + service.DisableUser
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

// bulkEnableUsers enables multiple users.
//
// Call chain: HTTP POST /v1/admin/users/bulk-enable → bulkEnableUsers → service.EnableUser
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

// bulkLogoutUsers revokes all sessions for multiple users.
//
// Call chain: HTTP POST /v1/admin/users/bulk-logout → bulkLogoutUsers → sessionService.LogoutAll
func (h *Handler) bulkLogoutUsers(c *gin.Context) {
	userIDs, ok := h.bulkUserIDs(c)
	if !ok {
		return
	}
	if h.sessionService == nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, "session service not configured")
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

// bulkAddUsersToTenant adds multiple users as members of a tenant.
//
// Call chain: HTTP POST /v1/admin/users/bulk-add-to-tenant → bulkAddUsersToTenant → tenantService.AddMember
func (h *Handler) bulkAddUsersToTenant(c *gin.Context) {
	request, ok := h.bulkTenantRequest(c)
	if !ok {
		return
	}
	if h.tenantService == nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, "tenant service not configured")
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

// bulkRemoveUsersFromTenant removes multiple users from a tenant.
//
// Call chain: HTTP POST /v1/admin/users/bulk-remove-from-tenant → bulkRemoveUsersFromTenant → tenantService.RemoveMember
func (h *Handler) bulkRemoveUsersFromTenant(c *gin.Context) {
	request, ok := h.bulkTenantRequest(c)
	if !ok {
		return
	}
	if h.tenantService == nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, "tenant service not configured")
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

// bulkUserIDs decodes and validates a bulkUserRequest body, returning deduplicated user IDs.
//
// Call chain: bulk* handlers → bulkUserIDs → normalizeUserIDs
func (h *Handler) bulkUserIDs(c *gin.Context) ([]int64, bool) {
	var request bulkUserRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return nil, false
	}
	userIDs, ok := normalizeUserIDs(c, request.UserIDs)
	return userIDs, ok
}

// bulkTenantRequest decodes and validates a bulkTenantUserRequest body.
//
// Call chain: bulkAddUsersToTenant/bulkRemoveUsersFromTenant → bulkTenantRequest → normalizeUserIDs
func (h *Handler) bulkTenantRequest(c *gin.Context) (bulkTenantUserRequest, bool) {
	var request bulkTenantUserRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return request, false
	}
	if request.TenantID <= 0 {
		httpserver.Error(c, stdhttp.StatusBadRequest, "tenant_id is required")
		return request, false
	}
	userIDs, ok := normalizeUserIDs(c, request.UserIDs)
	if !ok {
		return request, false
	}
	request.UserIDs = userIDs
	return request, true
}

// normalizeUserIDs deduplicates and validates a list of user IDs (positive, ≤100, non-empty).
func normalizeUserIDs(c *gin.Context, raw []int64) ([]int64, bool) {
	seen := map[int64]struct{}{}
	userIDs := make([]int64, 0, len(raw))
	for _, userID := range raw {
		if userID <= 0 {
			httpserver.Error(c, stdhttp.StatusBadRequest, "user_ids must be positive")
			return nil, false
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		userIDs = append(userIDs, userID)
	}
	if len(userIDs) == 0 {
		httpserver.Error(c, stdhttp.StatusBadRequest, "user_ids is required")
		return nil, false
	}
	if len(userIDs) > 100 {
		httpserver.Error(c, stdhttp.StatusBadRequest, "user_ids cannot exceed 100")
		return nil, false
	}
	return userIDs, true
}

// stringFromGinH extracts a string value from a gin.H map, defaulting to "".
func stringFromGinH(item gin.H, key string) string {
	value, _ := item[key].(string)
	return value
}
