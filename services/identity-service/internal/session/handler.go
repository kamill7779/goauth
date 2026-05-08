package session

import (
	"crypto/rsa"
	stdhttp "net/http"

	httpserver "example.com/identity-service/internal/http"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	service   *Service
	publicKey *rsa.PublicKey
}

func NewHandler(service *Service, publicKey *rsa.PublicKey) *Handler {
	return &Handler{
		service:   service,
		publicKey: publicKey,
	}
}

func (h *Handler) RegisterRoutes(router gin.IRoutes) {
	router.POST("/refresh", h.refresh)
	router.POST("/logout", h.logout)
	router.POST("/logout-all", h.logoutAll)
	if h.publicKey != nil {
		router.GET("/me", AuthMiddleware(h.publicKey), h.me)
	} else {
		router.GET("/me", h.me)
	}
}

func (h *Handler) refresh(c *gin.Context) {
	var request struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	pair, err := h.service.Refresh(c.Request.Context(), request.RefreshToken)
	if err != nil {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	cookieValue, err := h.service.IssueOIDCAuthorizeCookieBySessionID(c.Request.Context(), pair.SessionID)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	SetOIDCAuthorizeCookie(c, cookieValue, int(h.service.RefreshTokenTTL().Seconds()))
	httpserver.Success(c, stdhttp.StatusOK, pair)
}

func (h *Handler) logout(c *gin.Context) {
	var request struct {
		SessionID string `json:"session_id"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.Logout(c.Request.Context(), request.SessionID); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) logoutAll(c *gin.Context) {
	var request struct {
		UserID int64 `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.LogoutAll(c.Request.Context(), request.UserID); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) me(c *gin.Context) {
	claims, ok := ClaimsFromContext(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"user_id": claims.Subject,
		"email":   claims.Email,
		"sid":     claims.SessionID,
		"tid":     claims.TenantID,
	})
}
