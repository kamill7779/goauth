package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/auth"
	"goauth/services/identity-service/internal/store"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type CreateClientInput struct {
	TenantID                int64    `json:"tenant_id"`
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	Name                    string   `json:"name"`
	RedirectURIs            []string `json:"redirect_uris"`
	AllowedScopes           []string `json:"allowed_scopes"`
	GrantTypes              []string `json:"grant_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	AutoProvisionMembers    bool     `json:"auto_provision_members"`
}

func (s *Service) CreateClient(ctx context.Context, input CreateClientInput) (*store.OAuthClient, error) {
	if strings.TrimSpace(input.ClientID) == "" || strings.TrimSpace(input.ClientSecret) == "" {
		return nil, errors.New("client id and secret are required")
	}
	if input.TenantID == 0 || !s.hasActiveTenant(ctx, input.TenantID) {
		return nil, errors.New("active tenant is required")
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, errors.New("client name is required")
	}
	if len(input.RedirectURIs) == 0 {
		return nil, errors.New("at least one redirect uri is required")
	}
	if len(input.GrantTypes) == 0 {
		return nil, errors.New("at least one grant type is required")
	}
	for _, grantType := range input.GrantTypes {
		if !isSupportedGrantType(grantType) {
			return nil, errors.New("unsupported grant type")
		}
	}

	secretHash, err := auth.HashPassword(input.ClientSecret)
	if err != nil {
		return nil, err
	}

	redirectURIs, err := encodeStringSlice(input.RedirectURIs)
	if err != nil {
		return nil, err
	}
	allowedScopes, err := encodeStringSlice(input.AllowedScopes)
	if err != nil {
		return nil, err
	}
	grantTypes, err := encodeStringSlice(input.GrantTypes)
	if err != nil {
		return nil, err
	}

	authMethod := strings.TrimSpace(input.TokenEndpointAuthMethod)
	if authMethod == "" {
		authMethod = authMethodClientSecretPost
	}
	if !isSupportedTokenEndpointAuthMethod(authMethod) {
		return nil, errors.New("unsupported token endpoint auth method")
	}

	client := &store.OAuthClient{
		TenantID:                input.TenantID,
		ClientID:                strings.TrimSpace(input.ClientID),
		ClientSecretHash:        secretHash,
		Name:                    strings.TrimSpace(input.Name),
		RedirectURIs:            redirectURIs,
		AllowedScopes:           allowedScopes,
		GrantTypes:              grantTypes,
		TokenEndpointAuthMethod: authMethod,
		AutoProvisionMembers:    input.AutoProvisionMembers,
		Status:                  store.UserStatusActive,
	}
	if err := s.db.WithContext(ctx).Create(client).Error; err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionOAuthClientChanged,
		TenantID:   client.TenantID,
		TargetType: audit.TargetTypeOAuthClient,
		TargetID:   client.ClientID,
		Metadata: map[string]any{
			"change": "created",
			"name":   client.Name,
		},
	})
	return client, nil
}

func (s *Service) ListClients(ctx context.Context) ([]store.OAuthClient, error) {
	var clients []store.OAuthClient
	err := s.db.WithContext(ctx).Order("id ASC").Find(&clients).Error
	return clients, err
}

func (s *Service) UpdateClientStatus(ctx context.Context, clientID, status string) (*store.OAuthClient, error) {
	clientID = strings.TrimSpace(clientID)
	status = strings.TrimSpace(status)
	if clientID == "" {
		return nil, errors.New("client id is required")
	}
	if status != store.UserStatusActive && status != store.UserStatusDisabled {
		return nil, errors.New("unsupported client status")
	}

	if err := s.db.WithContext(ctx).
		Model(&store.OAuthClient{}).
		Where("client_id = ?", clientID).
		Update("status", status).Error; err != nil {
		return nil, err
	}

	client, err := s.loadClient(ctx, clientID)
	if err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionOAuthClientChanged,
		TenantID:   client.TenantID,
		TargetType: audit.TargetTypeOAuthClient,
		TargetID:   client.ClientID,
		Metadata: map[string]any{
			"change": "status_updated",
			"status": status,
		},
	})
	return client, nil
}

func (s *Service) loadClient(ctx context.Context, clientID string) (*store.OAuthClient, error) {
	var client store.OAuthClient
	if err := s.db.WithContext(ctx).Where("client_id = ?", strings.TrimSpace(clientID)).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (*store.OAuthClient, error) {
	client, err := s.loadClient(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errInvalidClientCredentials
		}
		return nil, err
	}
	if err := auth.CheckPassword(client.ClientSecretHash, clientSecret); err != nil {
		return nil, errInvalidClientCredentials
	}
	if client.Status != store.UserStatusActive {
		return nil, errInvalidClientCredentials
	}
	return client, nil
}

func (s *Service) validateRedirectURI(client *store.OAuthClient, redirectURI string) bool {
	redirectURIs, err := decodeStringSlice(client.RedirectURIs)
	if err != nil {
		return false
	}
	for _, candidate := range redirectURIs {
		if candidate == redirectURI {
			return true
		}
	}
	return false
}

func (s *Service) validateScope(client *store.OAuthClient, scope string) error {
	allowedScopes, err := decodeStringSlice(client.AllowedScopes)
	if err != nil {
		return err
	}
	allowedSet := make(map[string]struct{}, len(allowedScopes))
	for _, item := range allowedScopes {
		allowedSet[item] = struct{}{}
	}

	requested := splitScope(scope)
	if len(requested) == 0 {
		return errors.New("missing scope")
	}

	hasOpenID := false
	for _, item := range requested {
		if item == "openid" {
			hasOpenID = true
		}
		if _, ok := allowedSet[item]; !ok {
			return errors.New("scope not allowed")
		}
	}
	if !hasOpenID {
		return errors.New("openid scope is required")
	}
	return nil
}

func (s *Service) authenticateClientFromRequest(c *gin.Context) (*store.OAuthClient, error) {
	clientID := strings.TrimSpace(c.PostForm("client_id"))
	clientSecret := c.PostForm("client_secret")
	basicClientID, basicClientSecret, basicProvided := parseBasicAuthHeader(c.GetHeader("Authorization"))

	if clientID == "" {
		clientID = basicClientID
	}
	if clientID == "" {
		return nil, errInvalidClientCredentials
	}

	client, err := s.loadClient(c.Request.Context(), clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errInvalidClientCredentials
		}
		return nil, err
	}

	var secret string
	switch client.TokenEndpointAuthMethod {
	case authMethodClientSecretBasic:
		if !basicProvided || basicClientID != client.ClientID || clientSecret != "" || strings.TrimSpace(c.PostForm("client_id")) != "" {
			return nil, errInvalidClientCredentials
		}
		secret = basicClientSecret
	case authMethodClientSecretPost:
		if basicProvided || strings.TrimSpace(c.PostForm("client_id")) != client.ClientID || clientSecret == "" {
			return nil, errInvalidClientCredentials
		}
		secret = clientSecret
	default:
		return nil, errInvalidClientCredentials
	}

	if err := auth.CheckPassword(client.ClientSecretHash, secret); err != nil {
		return nil, errInvalidClientCredentials
	}
	if client.Status != store.UserStatusActive {
		return nil, errInvalidClientCredentials
	}
	return client, nil
}

func splitScope(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

func supportsGrantType(client *store.OAuthClient, grantType string) bool {
	grantTypes, err := decodeStringSlice(client.GrantTypes)
	if err != nil {
		return false
	}
	for _, item := range grantTypes {
		if item == grantType {
			return true
		}
	}
	return false
}

func isSupportedGrantType(value string) bool {
	switch strings.TrimSpace(value) {
	case "authorization_code", "refresh_token":
		return true
	default:
		return false
	}
}

func isSupportedTokenEndpointAuthMethod(value string) bool {
	switch value {
	case authMethodClientSecretBasic, authMethodClientSecretPost:
		return true
	default:
		return false
	}
}

func parseBasicAuthHeader(header string) (string, string, bool) {
	header = strings.TrimSpace(header)
	if len(header) < len("Basic ") || !strings.EqualFold(header[:len("Basic ")], "Basic ") {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(header[len("Basic "):])
	if err != nil {
		return "", "", false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok || strings.TrimSpace(username) == "" || password == "" {
		return "", "", false
	}
	return username, password, true
}

func encodeStringSlice(values []string) (datatypes.JSON, error) {
	bytes, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return datatypes.JSON(bytes), nil
}

func decodeStringSlice(value datatypes.JSON) ([]string, error) {
	if len(value) == 0 {
		return nil, nil
	}
	var result []string
	if err := json.Unmarshal(value, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func oauthError(c *gin.Context, status int, code string) {
	c.JSON(status, gin.H{"error": code})
}

func noContentOrJSON(c *gin.Context) {
	c.Status(http.StatusOK)
}
