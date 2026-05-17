package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/store"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func TestAccessOverviewSummarizesRBACAndDeploymentRisks(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newAdminTestDB(t)

	user := store.User{Email: "user@example.com", PasswordHash: "hash", DisplayName: "User", Status: store.UserStatusActive}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	publicTenant := store.Tenant{Name: "Public", Slug: "public", Status: store.TenantStatusActive}
	disabledTenant := store.Tenant{Name: "Disabled", Slug: "disabled", Status: store.TenantStatusDisabled}
	if err := db.Create(&publicTenant).Error; err != nil {
		t.Fatalf("create public tenant: %v", err)
	}
	if err := db.Create(&disabledTenant).Error; err != nil {
		t.Fatalf("create disabled tenant: %v", err)
	}
	member := store.TenantMember{TenantID: publicTenant.ID, UserID: user.ID, Status: store.MemberStatusActive}
	if err := db.Create(&member).Error; err != nil {
		t.Fatalf("create member: %v", err)
	}
	viewer := store.Role{TenantID: publicTenant.ID, Name: "Viewer", Code: "viewer"}
	emptyRole := store.Role{TenantID: publicTenant.ID, Name: "Empty", Code: "empty"}
	if err := db.Create(&viewer).Error; err != nil {
		t.Fatalf("create viewer role: %v", err)
	}
	if err := db.Create(&emptyRole).Error; err != nil {
		t.Fatalf("create empty role: %v", err)
	}
	permission := store.Permission{Resource: "project", Action: "read", Code: "project:read"}
	if err := db.Create(&permission).Error; err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if err := db.Create(&store.RolePermission{RoleID: viewer.ID, PermissionID: permission.ID}).Error; err != nil {
		t.Fatalf("grant permission: %v", err)
	}
	if err := db.Create(&store.MemberRole{MemberID: member.ID, RoleID: viewer.ID}).Error; err != nil {
		t.Fatalf("assign role: %v", err)
	}
	clients := []store.OAuthClient{
		{
			TenantID:                publicTenant.ID,
			ClientID:                "public-web",
			ClientSecretHash:        "hash",
			Name:                    "Public Web",
			RedirectURIs:            datatypes.JSON([]byte(`["https://app.example.com/callback"]`)),
			AllowedScopes:           datatypes.JSON([]byte(`["openid","profile"]`)),
			GrantTypes:              datatypes.JSON([]byte(`["authorization_code","refresh_token"]`)),
			TokenEndpointAuthMethod: "client_secret_post",
			AutoProvisionMembers:    true,
			Status:                  store.UserStatusActive,
		},
		{
			TenantID:                disabledTenant.ID,
			ClientID:                "disabled-web",
			ClientSecretHash:        "hash",
			Name:                    "Disabled Web",
			RedirectURIs:            datatypes.JSON([]byte(`["https://disabled.example.com/callback"]`)),
			AllowedScopes:           datatypes.JSON([]byte(`["openid"]`)),
			GrantTypes:              datatypes.JSON([]byte(`["authorization_code"]`)),
			TokenEndpointAuthMethod: "client_secret_post",
			AutoProvisionMembers:    false,
			Status:                  store.UserStatusDisabled,
		},
	}
	if err := db.Create(&clients).Error; err != nil {
		t.Fatalf("create oauth clients: %v", err)
	}

	handler := NewHandler(db, nil, nil, nil, nil, config.Config{
		DefaultMemberTenantSlugs: []string{"public", "missing"},
	})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/access-overview", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var envelope struct {
		Data struct {
			Summary struct {
				TotalTenants           int `json:"total_tenants"`
				ActiveTenants          int `json:"active_tenants"`
				ActiveMembers          int `json:"active_members"`
				Roles                  int `json:"roles"`
				Permissions            int `json:"permissions"`
				OAuthClients           int `json:"oauth_clients"`
				AutoProvisionClients   int `json:"auto_provision_clients"`
				DefaultMembershipSlugs int `json:"default_membership_slugs"`
			} `json:"summary"`
			DefaultMemberships []struct {
				Slug   string `json:"slug"`
				Found  bool   `json:"found"`
				Status string `json:"status"`
			} `json:"default_memberships"`
			Tenants []struct {
				Slug              string `json:"slug"`
				MembersCount      int    `json:"members_count"`
				RolesCount        int    `json:"roles_count"`
				PermissionsCount  int    `json:"permissions_count"`
				OAuthClientsCount int    `json:"oauth_clients_count"`
			} `json:"tenants"`
			OAuthClients []struct {
				ClientID             string   `json:"client_id"`
				TenantSlug           string   `json:"tenant_slug"`
				AutoProvisionMembers bool     `json:"auto_provision_members"`
				AllowedScopes        []string `json:"allowed_scopes"`
			} `json:"oauth_clients"`
			Risks []accessOverviewRiskResponse `json:"risks"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if envelope.Data.Summary.TotalTenants != 2 || envelope.Data.Summary.ActiveTenants != 1 {
		t.Fatalf("summary tenants = %+v", envelope.Data.Summary)
	}
	if envelope.Data.Summary.ActiveMembers != 1 || envelope.Data.Summary.Roles != 2 || envelope.Data.Summary.Permissions != 1 {
		t.Fatalf("summary access counts = %+v", envelope.Data.Summary)
	}
	if envelope.Data.Summary.OAuthClients != 2 || envelope.Data.Summary.AutoProvisionClients != 1 || envelope.Data.Summary.DefaultMembershipSlugs != 2 {
		t.Fatalf("summary client counts = %+v", envelope.Data.Summary)
	}
	if len(envelope.Data.DefaultMemberships) != 2 {
		t.Fatalf("default memberships = %+v", envelope.Data.DefaultMemberships)
	}
	if envelope.Data.DefaultMemberships[0].Slug != "public" || !envelope.Data.DefaultMemberships[0].Found {
		t.Fatalf("public default membership = %+v", envelope.Data.DefaultMemberships)
	}
	if envelope.Data.DefaultMemberships[1].Slug != "missing" || envelope.Data.DefaultMemberships[1].Found {
		t.Fatalf("missing default membership = %+v", envelope.Data.DefaultMemberships)
	}
	if len(envelope.Data.Tenants) != 2 {
		t.Fatalf("tenants = %+v", envelope.Data.Tenants)
	}
	if envelope.Data.Tenants[0].Slug != "public" || envelope.Data.Tenants[0].MembersCount != 1 || envelope.Data.Tenants[0].RolesCount != 2 || envelope.Data.Tenants[0].PermissionsCount != 1 || envelope.Data.Tenants[0].OAuthClientsCount != 1 {
		t.Fatalf("public tenant row = %+v", envelope.Data.Tenants[0])
	}
	if len(envelope.Data.OAuthClients) != 2 || envelope.Data.OAuthClients[0].ClientID != "public-web" || !envelope.Data.OAuthClients[0].AutoProvisionMembers {
		t.Fatalf("oauth clients = %+v", envelope.Data.OAuthClients)
	}
	if !hasAccessRisk(envelope.Data.Risks, "default_tenant_missing", "error") {
		t.Fatalf("risks missing default_tenant_missing: %+v", envelope.Data.Risks)
	}
	if !hasAccessRisk(envelope.Data.Risks, "role_without_permissions", "warning") {
		t.Fatalf("risks missing role_without_permissions: %+v", envelope.Data.Risks)
	}
}

func newAdminTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := store.OpenDB(config.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

type accessOverviewRiskResponse struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
}

func hasAccessRisk(risks []accessOverviewRiskResponse, code, severity string) bool {
	for _, risk := range risks {
		if risk.Code == code && risk.Severity == severity {
			return true
		}
	}
	return false
}
