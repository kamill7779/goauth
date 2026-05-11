package oidc

import (
	"errors"
	stdhttp "net/http"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

type AdminHandler struct {
	service          *Service
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

func NewAdminHandler(service *Service, authMiddleware, systemMiddleware gin.HandlerFunc) *AdminHandler {
	return &AdminHandler{
		service:          service,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
	}
}

func (h *AdminHandler) RegisterRoutes(router *gin.Engine) {
	admin := router.Group("/v1/admin")
	if h.authMiddleware != nil {
		admin.Use(h.authMiddleware)
	}
	if h.systemMiddleware != nil {
		admin.Use(h.systemMiddleware)
	}

	admin.GET("/oauth-clients", h.listClients)
	admin.POST("/oauth-clients", h.createClient)
	admin.PATCH("/oauth-clients/:client_id/status", h.updateClientStatus)
	admin.POST("/oauth-clients/:client_id/rotate-secret", h.rotateClientSecret)
}

func (h *AdminHandler) listClients(c *gin.Context) {
	clients, err := h.service.ListClients(c.Request.Context())
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	items := make([]gin.H, 0, len(clients))
	for _, client := range clients {
		payload, err := oauthClientPayload(client)
		if err != nil {
			c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": "invalid oauth client data"})
			return
		}
		items = append(items, payload)
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"oauth_clients": items})
}

func (h *AdminHandler) createClient(c *gin.Context) {
	var request CreateClientInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client, err := h.service.CreateClient(c.Request.Context(), request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	payload, err := oauthClientPayload(*client)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": "invalid oauth client data"})
		return
	}
	httpserver.Success(c, stdhttp.StatusCreated, payload)
}

func (h *AdminHandler) updateClientStatus(c *gin.Context) {
	var request struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client, err := h.service.UpdateClientStatus(c.Request.Context(), c.Param("client_id"), request.Status)
	if err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = stdhttp.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	payload, err := oauthClientPayload(*client)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": "invalid oauth client data"})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, payload)
}

func (h *AdminHandler) rotateClientSecret(c *gin.Context) {
	client, secret, err := h.service.RotateClientSecret(c.Request.Context(), c.Param("client_id"))
	if err != nil {
		status := stdhttp.StatusBadRequest
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = stdhttp.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	payload, err := oauthClientPayload(*client)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": "invalid oauth client data"})
		return
	}
	payload["client_secret"] = secret
	httpserver.Success(c, stdhttp.StatusOK, payload)
}

func oauthClientPayload(client store.OAuthClient) (gin.H, error) {
	redirectURIs, err := decodeStringSlice(client.RedirectURIs)
	if err != nil {
		return nil, err
	}
	allowedScopes, err := decodeStringSlice(client.AllowedScopes)
	if err != nil {
		return nil, err
	}
	grantTypes, err := decodeStringSlice(client.GrantTypes)
	if err != nil {
		return nil, err
	}

	return gin.H{
		"id":                         client.ID,
		"tenant_id":                  client.TenantID,
		"client_id":                  client.ClientID,
		"name":                       client.Name,
		"redirect_uris":              redirectURIs,
		"allowed_scopes":             allowedScopes,
		"grant_types":                grantTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuthMethod,
		"auto_provision_members":     client.AutoProvisionMembers,
		"status":                     client.Status,
		"created_at":                 client.CreatedAt,
		"updated_at":                 client.UpdatedAt,
	}, nil
}
