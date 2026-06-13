package tenant

import (
	stdhttp "net/http"
	"strings"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/util"
)

// listTenants returns a paginated, searchable, filterable list of tenants
// enriched with member, role, and OAuth client counts.
//
// Call chain: HTTP GET /v1/admin/tenants → listTenants → db + tenantPayloads
func (h *Handler) listTenants(c *gin.Context) {
	page, pageSize := util.Pagination(c)
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

// createTenant creates a tenant from JSON body.
//
// Call chain: HTTP POST /v1/admin/tenants → createTenant → service.CreateTenant + singleTenantPayload
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

// updateTenant patch-updates a tenant by ID.
//
// Call chain: HTTP PATCH /v1/admin/tenants/:id → updateTenant → service.UpdateTenant + singleTenantPayload
func (h *Handler) updateTenant(c *gin.Context) {
	id, err := util.ParseInt64Param(c, "id")
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

// singleTenantPayload wraps tenantPayloads for a single tenant record.
func (h *Handler) singleTenantPayload(c *gin.Context, tenantRecord store.Tenant) (gin.H, error) {
	items, err := h.tenantPayloads(c, []store.Tenant{tenantRecord})
	if err != nil {
		return nil, err
	}
	return items[0], nil
}

// tenantPayloads enriches tenant records with member, role, and OAuth client counts.
//
// Call chain: listTenants → tenantPayloads → groupCounts + oauthClientCounts
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

// tenantLookup returns a map of tenant ID → tenant record for deduplicated IDs.
//
// Call chain: rolePayloads → tenantLookup → db.Find
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
