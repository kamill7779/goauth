package tenant

import (
	stdhttp "net/http"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/util"
)

type tenantCountRow struct {
	TenantID int64
	Count    int64
}

// addMember adds a user as a member of a tenant.
//
// Call chain: HTTP POST /v1/admin/tenants/:id/members → addMember → service.AddMember
func (h *Handler) addMember(c *gin.Context) {
	tenantID, err := util.ParseInt64Param(c, "id")
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

// removeMember removes a user from a tenant by tenant ID and user ID.
//
// Call chain: HTTP DELETE /v1/admin/tenants/:id/members/:user_id → removeMember → service.RemoveMember
func (h *Handler) removeMember(c *gin.Context) {
	tenantID, err := util.ParseInt64Param(c, "id")
	if err != nil {
		return
	}
	userID, err := util.ParseInt64Param(c, "user_id")
	if err != nil {
		return
	}

	if err := h.service.RemoveMember(c.Request.Context(), tenantID, userID); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"removed": true})
}

// assignRoles assigns roles to a tenant member.
//
// Call chain: HTTP POST /v1/admin/members/:member_id/roles → assignRoles → service.AssignRoles
func (h *Handler) assignRoles(c *gin.Context) {
	memberID, err := util.ParseInt64Param(c, "member_id")
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

// removeRole removes a single role from a tenant member.
//
// Call chain: HTTP DELETE /v1/admin/members/:member_id/roles/:role_id → removeRole → service.RemoveRole
func (h *Handler) removeRole(c *gin.Context) {
	memberID, err := util.ParseInt64Param(c, "member_id")
	if err != nil {
		return
	}
	roleID, err := util.ParseInt64Param(c, "role_id")
	if err != nil {
		return
	}

	if err := h.service.RemoveRole(c.Request.Context(), memberID, roleID); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"updated": true})
}

// groupCounts runs a generic COUNT(*) … GROUP BY query and returns results keyed by tenant_id.
//
// Call chain: tenantPayloads → groupCounts → db query
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

// oauthClientCounts returns OAuth client counts grouped by tenant ID.
//
// Call chain: tenantPayloads → oauthClientCounts → db query OAuthClient
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
