package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
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

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// CreateClient validates input, hashes the secret, and persists a new OAuth2 client.
//
// Call chain: POST /v1/admin/oauth-clients → AdminHandler.createClient → CreateClient → DB Create
func (s *Service) CreateClient(ctx context.Context, input CreateClientInput) (*store.OAuthClient, error) {
	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" || strings.TrimSpace(input.ClientSecret) == "" {
		return nil, errors.New("client id and secret are required")
	}
	if !clientIDPattern.MatchString(clientID) {
		return nil, errors.New("client id may only contain letters, numbers, dot, underscore, and hyphen")
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
		ClientID:                clientID,
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

// ListClients returns all OAuth2 clients ordered by ID.
func (s *Service) ListClients(ctx context.Context) ([]store.OAuthClient, error) {
	var clients []store.OAuthClient
	err := s.db.WithContext(ctx).Order("id ASC").Find(&clients).Error
	return clients, err
}

// UpdateClientStatus sets the client's status (active or disabled).
//
// Call chain: PATCH /v1/admin/oauth-clients/:id/status → AdminHandler.updateClientStatus → UpdateClientStatus → DB Update
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

// RotateClientSecret generates a new secret, updates the hash, and returns the
// plaintext secret for one-time display.
//
// Call chain: POST /v1/admin/oauth-clients/:id/rotate-secret → AdminHandler.rotateClientSecret → RotateClientSecret → DB Update
func (s *Service) RotateClientSecret(ctx context.Context, clientID string) (*store.OAuthClient, string, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return nil, "", errors.New("client id is required")
	}

	secret, err := s.randomID(32)
	if err != nil {
		return nil, "", err
	}
	secretHash, err := auth.HashPassword(secret)
	if err != nil {
		return nil, "", err
	}
	if err := s.db.WithContext(ctx).
		Model(&store.OAuthClient{}).
		Where("client_id = ?", clientID).
		Update("client_secret_hash", secretHash).Error; err != nil {
		return nil, "", err
	}

	client, err := s.loadClient(ctx, clientID)
	if err != nil {
		return nil, "", err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		Action:     audit.ActionOAuthClientChanged,
		TenantID:   client.TenantID,
		TargetType: audit.TargetTypeOAuthClient,
		TargetID:   client.ClientID,
		Metadata: map[string]any{
			"change": "secret_rotated",
			"name":   client.Name,
		},
	})
	return client, secret, nil
}

// loadClient fetches a single OAuth2 client by client_id.
//
// Call chain: authenticateClient / authorize / token → loadClient → DB query
func (s *Service) loadClient(ctx context.Context, clientID string) (*store.OAuthClient, error) {
	var client store.OAuthClient
	if err := s.db.WithContext(ctx).Where("client_id = ?", strings.TrimSpace(clientID)).First(&client).Error; err != nil {
		return nil, err
	}
	return &client, nil
}

// authenticateClient validates client credentials (ID + secret) and checks the
// client is active.
//
// Call chain: authenticateClientFromRequest → authenticateClient → loadClient + CheckPassword
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

// validateRedirectURI uses exact string match per RFC 6749 §3.1.2.2; substring
// or pattern matching is intentionally avoided because it has historically led
// to open-redirector vulnerabilities (e.g., suffix-equal but wildly different
// origins).
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

// validateScope checks that every requested scope is in the client's allowed list
// and that "openid" is present.
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

// authenticateClientFromRequest extracts and verifies the OAuth client's
// credentials. The configured TokenEndpointAuthMethod is strictly enforced: a
// "basic" client cannot fall back to posting client_secret in the body and vice
// versa. Mixing both is explicitly rejected to defeat credential-stuffing tricks.
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

// splitScope splits a space-delimited scope string into individual values.
func splitScope(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

// supportsGrantType checks whether the client is configured for the given grant type.
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

// isSupportedGrantType reports whether the given grant type is known.
func isSupportedGrantType(value string) bool {
	switch strings.TrimSpace(value) {
	case "authorization_code", "refresh_token":
		return true
	default:
		return false
	}
}

// isSupportedTokenEndpointAuthMethod reports whether the auth method is known.
func isSupportedTokenEndpointAuthMethod(value string) bool {
	switch value {
	case authMethodClientSecretBasic, authMethodClientSecretPost:
		return true
	default:
		return false
	}
}

// parseBasicAuthHeader decodes a Basic auth header into client_id:client_secret.
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

// encodeStringSlice marshals a string slice to datatypes.JSON.
func encodeStringSlice(values []string) (datatypes.JSON, error) {
	bytes, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	return datatypes.JSON(bytes), nil
}

// decodeStringSlice unmarshals a datatypes.JSON value into a string slice.
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

// oauthError writes an OAuth2-standard JSON error response.
func oauthError(c *gin.Context, status int, code string) {
	httpserver.Error(c, status, code)
}

// noContentOrJSON returns HTTP 200 with no body, satisfying RFC 7009 revocation.
func noContentOrJSON(c *gin.Context) {
	c.Status(http.StatusOK)
}
