package session

import (
	"crypto/rsa"
	stdhttp "net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
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
	auth := AuthMiddleware(h.service, h.publicKey)
	router.POST("/logout", auth, h.logout)
	if h.publicKey != nil {
		router.POST("/logout-all", auth, h.logoutAll)
		router.GET("/me", auth, h.me)
	} else {
		router.POST("/logout-all", h.logoutAll)
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
	SetOIDCAuthorizeCookie(c, cookieValue, int(h.service.OIDCAuthorizeCookieTTL().Seconds()))
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

	claims, ok := ClaimsFromContext(c)
	if ok {
		if request.SessionID == "" {
			request.SessionID = claims.SessionID
		}
		if request.SessionID != claims.SessionID {
			c.JSON(stdhttp.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
	}
	if request.SessionID == "" {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "missing session_id"})
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
		UserID *int64 `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, ok := ClaimsFromContext(c)
	if !ok {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return
	}
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	if request.UserID != nil && *request.UserID != userID {
		c.JSON(stdhttp.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	if err := h.service.LogoutAll(c.Request.Context(), userID); err != nil {
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
