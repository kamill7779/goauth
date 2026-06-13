package admin

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
)

type accessOverviewSummary struct {
	TotalTenants           int `json:"total_tenants"`
	ActiveTenants          int `json:"active_tenants"`
	ActiveMembers          int `json:"active_members"`
	Roles                  int `json:"roles"`
	Permissions            int `json:"permissions"`
	OAuthClients           int `json:"oauth_clients"`
	AutoProvisionClients   int `json:"auto_provision_clients"`
	DefaultMembershipSlugs int `json:"default_membership_slugs"`
}

type accessOverviewDefaultMembership struct {
	Slug   string `json:"slug"`
	Found  bool   `json:"found"`
	Status string `json:"status"`
}

type accessOverviewTenant struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	Slug              string `json:"slug"`
	Status            string `json:"status"`
	MembersCount      int    `json:"members_count"`
	RolesCount        int    `json:"roles_count"`
	PermissionsCount  int    `json:"permissions_count"`
	OAuthClientsCount int    `json:"oauth_clients_count"`
}

type accessOverviewOAuthClient struct {
	ClientID             string   `json:"client_id"`
	Name                 string   `json:"name"`
	TenantSlug           string   `json:"tenant_slug"`
	TenantStatus         string   `json:"tenant_status"`
	Status               string   `json:"status"`
	AutoProvisionMembers bool     `json:"auto_provision_members"`
	AllowedScopes        []string `json:"allowed_scopes"`
}

type accessOverviewRisk struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Target   string `json:"target"`
}

// accessOverview returns a comprehensive summary of tenants, roles, permissions,
// OAuth clients, default memberships, and detected risks.
//
// Call chain: HTTP GET /v1/admin/access-overview → accessOverview → db queries + buildAccessOverview + buildDefaultMemberships
func (h *Handler) accessOverview(c *gin.Context) {
	ctx := c.Request.Context()
	var tenants []store.Tenant
	if err := h.db.WithContext(ctx).Order("id ASC").Find(&tenants).Error; err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	var members []store.TenantMember
	if err := h.db.WithContext(ctx).Where("status = ?", store.MemberStatusActive).Find(&members).Error; err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	var roles []store.Role
	if err := h.db.WithContext(ctx).Order("id ASC").Find(&roles).Error; err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	var rolePermissions []store.RolePermission
	if err := h.db.WithContext(ctx).Find(&rolePermissions).Error; err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err.Error())
		return
	}
	var clients []store.OAuthClient
	if err := h.db.WithContext(ctx).Order("id ASC").Find(&clients).Error; err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err.Error())
		return
	}

	var permissions int64
	if err := h.db.WithContext(ctx).Model(&store.Permission{}).Count(&permissions).Error; err != nil {
		httpserver.Error(c, http.StatusInternalServerError, err.Error())
		return
	}

	summary, tenantRows, clientRows, risks := buildAccessOverview(h.cfg.DefaultMemberTenantSlugs, tenants, members, roles, rolePermissions, clients, int(permissions))
	defaultMemberships := buildDefaultMemberships(h.cfg.DefaultMemberTenantSlugs, tenants, &risks)
	httpserver.Success(c, http.StatusOK, gin.H{
		"summary":             summary,
		"default_memberships": defaultMemberships,
		"tenants":             tenantRows,
		"oauth_clients":       clientRows,
		"risks":               risks,
	})
}

// buildAccessOverview aggregates pre-fetched data into summary, tenant rows,
// OAuth client rows, and a risk list (roles without permissions, auto-provision
// on inactive tenants, active tenants without roles).
//
// Call chain: accessOverview → buildAccessOverview (pure data transformation)
func buildAccessOverview(defaultSlugs []string, tenants []store.Tenant, members []store.TenantMember, roles []store.Role, rolePermissions []store.RolePermission, clients []store.OAuthClient, permissions int) (accessOverviewSummary, []accessOverviewTenant, []accessOverviewOAuthClient, []accessOverviewRisk) {
	tenantsByID := make(map[int64]store.Tenant, len(tenants))
	tenantRowsByID := make(map[int64]*accessOverviewTenant, len(tenants))
	roleTenantByID := make(map[int64]int64, len(roles))
	rolePermissionCounts := map[int64]int{}
	tenantPermissions := map[int64]map[int64]struct{}{}
	risks := []accessOverviewRisk{}
	summary := accessOverviewSummary{
		TotalTenants:           len(tenants),
		Roles:                  len(roles),
		Permissions:            permissions,
		OAuthClients:           len(clients),
		DefaultMembershipSlugs: len(defaultSlugs),
	}

	tenantRows := make([]accessOverviewTenant, 0, len(tenants))
	for _, tenant := range tenants {
		tenantsByID[tenant.ID] = tenant
		if tenant.Status == store.TenantStatusActive {
			summary.ActiveTenants++
		}
		row := accessOverviewTenant{
			ID:     tenant.ID,
			Name:   tenant.Name,
			Slug:   tenant.Slug,
			Status: tenant.Status,
		}
		tenantRows = append(tenantRows, row)
		tenantRowsByID[tenant.ID] = &tenantRows[len(tenantRows)-1]
	}

	for _, member := range members {
		summary.ActiveMembers++
		if row, ok := tenantRowsByID[member.TenantID]; ok {
			row.MembersCount++
		}
	}

	for _, role := range roles {
		roleTenantByID[role.ID] = role.TenantID
		if row, ok := tenantRowsByID[role.TenantID]; ok {
			row.RolesCount++
		}
	}

	for _, rolePermission := range rolePermissions {
		rolePermissionCounts[rolePermission.RoleID]++
		tenantID, ok := roleTenantByID[rolePermission.RoleID]
		if !ok {
			continue
		}
		if _, ok := tenantPermissions[tenantID]; !ok {
			tenantPermissions[tenantID] = map[int64]struct{}{}
		}
		tenantPermissions[tenantID][rolePermission.PermissionID] = struct{}{}
	}
	for tenantID, permissionSet := range tenantPermissions {
		if row, ok := tenantRowsByID[tenantID]; ok {
			row.PermissionsCount = len(permissionSet)
		}
	}

	for _, role := range roles {
		if rolePermissionCounts[role.ID] > 0 {
			continue
		}
		tenant := tenantsByID[role.TenantID]
		risks = append(risks, accessOverviewRisk{
			Code:     "role_without_permissions",
			Severity: "warning",
			Message:  "role has no permissions",
			Target:   tenant.Slug + ":" + role.Code,
		})
	}

	clientRows := make([]accessOverviewOAuthClient, 0, len(clients))
	for _, client := range clients {
		tenant := tenantsByID[client.TenantID]
		if row, ok := tenantRowsByID[client.TenantID]; ok {
			row.OAuthClientsCount++
		}
		if client.AutoProvisionMembers {
			summary.AutoProvisionClients++
		}
		if client.AutoProvisionMembers && tenant.Status != store.TenantStatusActive {
			risks = append(risks, accessOverviewRisk{
				Code:     "auto_provision_tenant_unavailable",
				Severity: "warning",
				Message:  "auto provisioning targets a non-active tenant",
				Target:   client.ClientID,
			})
		}
		clientRows = append(clientRows, accessOverviewOAuthClient{
			ClientID:             client.ClientID,
			Name:                 client.Name,
			TenantSlug:           tenant.Slug,
			TenantStatus:         tenant.Status,
			Status:               client.Status,
			AutoProvisionMembers: client.AutoProvisionMembers,
			AllowedScopes:        parseJSONStrings(client.AllowedScopes),
		})
	}

	for _, row := range tenantRows {
		if row.Status == store.TenantStatusActive && row.RolesCount == 0 {
			risks = append(risks, accessOverviewRisk{
				Code:     "active_tenant_without_roles",
				Severity: "warning",
				Message:  "active tenant has no roles",
				Target:   row.Slug,
			})
		}
	}

	return summary, tenantRows, clientRows, risks
}

// buildDefaultMemberships checks each configured default-membership slug against
// the existing tenants and appends risks for missing or inactive tenants.
//
// Call chain: accessOverview → buildDefaultMemberships (pure data transformation)
func buildDefaultMemberships(defaultSlugs []string, tenants []store.Tenant, risks *[]accessOverviewRisk) []accessOverviewDefaultMembership {
	tenantsBySlug := make(map[string]store.Tenant, len(tenants))
	for _, tenant := range tenants {
		tenantsBySlug[tenant.Slug] = tenant
	}

	memberships := make([]accessOverviewDefaultMembership, 0, len(defaultSlugs))
	for _, slug := range defaultSlugs {
		tenant, found := tenantsBySlug[slug]
		status := ""
		if found {
			status = tenant.Status
		}
		memberships = append(memberships, accessOverviewDefaultMembership{
			Slug:   slug,
			Found:  found,
			Status: status,
		})
		if !found {
			*risks = append(*risks, accessOverviewRisk{
				Code:     "default_tenant_missing",
				Severity: "error",
				Message:  "default membership tenant slug does not exist",
				Target:   slug,
			})
			continue
		}
		if tenant.Status != store.TenantStatusActive {
			*risks = append(*risks, accessOverviewRisk{
				Code:     "default_tenant_unavailable",
				Severity: "warning",
				Message:  "default membership tenant is not active",
				Target:   slug,
			})
		}
	}
	return memberships
}

// parseJSONStrings unmarshals a JSON array of strings, returning nil on failure.
func parseJSONStrings(raw []byte) []string {
	var values []string
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil {
		return []string{}
	}
	return values
}
