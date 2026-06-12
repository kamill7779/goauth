package session

import (
	"crypto/rsa"
	stdhttp "net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/jwtkey"
	"goauth/services/identity-service/internal/ratelimit"
)

type Handler struct {
	service     *Service
	publicKey   *rsa.PublicKey
	keyring     *jwtkey.Keyring
	rateLimiter *ratelimit.Service
}

func NewHandler(service *Service, publicKey *rsa.PublicKey) *Handler {
	return &Handler{
		service:   service,
		publicKey: publicKey,
	}
}

func NewHandlerWithKeyring(service *Service, keyring *jwtkey.Keyring) *Handler {
	return &Handler{
		service: service,
		keyring: keyring,
	}
}

func (h *Handler) RegisterRoutes(router gin.IRoutes) {
	router.POST("/refresh", h.refresh)
	auth := AuthMiddleware(h.service, h.publicKey)
	if h.keyring != nil {
		auth = AuthMiddlewareWithKeyring(h.service, h.keyring)
	}
	router.POST("/logout", auth, h.logout)
	if h.publicKey != nil || h.keyring != nil {
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
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	if !h.allowRefreshRateLimit(c) {
		return
	}

	pair, err := h.service.Refresh(c.Request.Context(), request.RefreshToken)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusUnauthorized, err.Error())
		return
	}
	cookieValue, err := h.service.IssueOIDCAuthorizeCookieBySessionID(c.Request.Context(), pair.SessionID)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	h.service.SetOIDCAuthorizeCookie(c, cookieValue, int(h.service.OIDCAuthorizeCookieTTL().Seconds()))
	httpserver.Success(c, stdhttp.StatusOK, pair)
}

func (h *Handler) logout(c *gin.Context) {
	var request struct {
		SessionID string `json:"session_id"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	claims, ok := ClaimsFromContext(c)
	if ok {
		if request.SessionID == "" {
			request.SessionID = claims.SessionID
		}
		if request.SessionID != claims.SessionID {
			httpserver.Error(c, stdhttp.StatusForbidden, "forbidden")
			return
		}
	}
	if request.SessionID == "" {
		httpserver.Error(c, stdhttp.StatusBadRequest, "missing session_id")
		return
	}

	if err := h.service.Logout(c.Request.Context(), request.SessionID); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) logoutAll(c *gin.Context) {
	var request struct {
		UserID *int64 `json:"user_id"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	claims, ok := ClaimsFromContext(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
		return
	}
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "invalid token")
		return
	}
	if request.UserID != nil && *request.UserID != userID {
		httpserver.Error(c, stdhttp.StatusForbidden, "forbidden")
		return
	}

	if err := h.service.LogoutAll(c.Request.Context(), userID); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) me(c *gin.Context) {
	claims, ok := ClaimsFromContext(c)
	if !ok {
		httpserver.Error(c, stdhttp.StatusUnauthorized, "missing auth claims")
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{
		"user_id": claims.Subject,
		"email":   claims.Email,
		"sid":     claims.SessionID,
		"tid":     claims.TenantID,
	})
}
