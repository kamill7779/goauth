package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"example.com/identity-service/internal/auth"
	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type CreateClientInput struct {
	TenantID                int64
	ClientID                string
	ClientSecret            string
	Name                    string
	RedirectURIs            []string
	AllowedScopes           []string
	GrantTypes              []string
	TokenEndpointAuthMethod string
}

func (s *Service) CreateClient(ctx context.Context, input CreateClientInput) (*store.OAuthClient, error) {
	if strings.TrimSpace(input.ClientID) == "" || strings.TrimSpace(input.ClientSecret) == "" {
		return nil, errors.New("client id and secret are required")
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
		authMethod = "client_secret_post"
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
		Status:                  store.UserStatusActive,
	}
	if err := s.db.WithContext(ctx).Create(client).Error; err != nil {
		return nil, err
	}
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

	if header := strings.TrimSpace(c.GetHeader("Authorization")); strings.HasPrefix(header, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "Basic "))
		if err == nil {
			if username, password, ok := strings.Cut(string(decoded), ":"); ok {
				if clientID == "" {
					clientID = username
				}
				if clientSecret == "" {
					clientSecret = password
				}
			}
		}
	}

	if clientID == "" || clientSecret == "" {
		return nil, errInvalidClientCredentials
	}
	return s.authenticateClient(c.Request.Context(), clientID, clientSecret)
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
