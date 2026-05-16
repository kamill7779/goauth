package account

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

type Handler struct {
	db             *gorm.DB
	sessionService *session.Service
	authMiddleware gin.HandlerFunc
}

func NewHandler(db *gorm.DB, sessionService *session.Service, authMiddleware gin.HandlerFunc) *Handler {
	return &Handler{
		db:             db,
		sessionService: sessionService,
		authMiddleware: authMiddleware,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	account := router.Group("/v1/account")
	if h.authMiddleware != nil {
		account.Use(h.authMiddleware)
	}

	account.GET("/me", h.me)
	account.GET("/sessions", h.listSessions)
	account.POST("/sessions/:session_id/revoke", h.revokeSession)
	account.POST("/logout-all", h.logoutAll)
}

func (h *Handler) me(c *gin.Context) {
	userID, sessionID, tenantID, ok := currentUser(c)
	if !ok {
		return
	}

	var user store.User
	if err := h.db.WithContext(c.Request.Context()).
		Where("id = ? AND deleted_at IS NULL", userID).
		First(&user).Error; err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	isAdmin, err := h.sessionService.IsSystemUser(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	displayName := userDisplayName(user)
	httpserver.Success(c, http.StatusOK, gin.H{
		"user": gin.H{
			"id":             user.ID,
			"email":          user.Email,
			"username":       user.Username,
			"nickname":       displayName,
			"display_name":   displayName,
			"avatar_url":     user.AvatarURL,
			"locale":         user.Locale,
			"status":         user.Status,
			"email_verified": user.EmailVerifiedAt != nil,
			"created_at":     user.CreatedAt,
		},
		"session": gin.H{
			"id":        sessionID,
			"tenant_id": tenantID,
		},
		"is_admin": isAdmin,
	})
}

func (h *Handler) listSessions(c *gin.Context) {
	userID, currentSessionID, _, ok := currentUser(c)
	if !ok {
		return
	}

	var rows []accountSessionRow
	if err := h.db.WithContext(c.Request.Context()).
		Table("login_sessions").
		Where("user_id = ?", userID).
		Select("id, user_id, tenant_id, client_id, revoked_at, created_at").
		Order("created_at DESC, id DESC").
		Limit(100).
		Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	tokens, err := latestRefreshTokensBySession(c, h.db, rows)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	items := make([]gin.H, 0, len(rows))
	for _, row := range rows {
		token, hasToken := tokens[row.ID]
		active := hasToken && token.RevokedAt == nil && token.ExpiresAt.After(now) && row.RevokedAt == nil
		items = append(items, gin.H{
			"id":         row.ID,
			"tenant_id":  row.TenantID,
			"client":     accountSessionClient(row, token),
			"ip":         token.IPAddress,
			"user_agent": token.UserAgent,
			"created_at": row.CreatedAt,
			"expires_at": token.ExpiresAt,
			"revoked_at": row.RevokedAt,
			"status":     accountSessionStatus(row, token, hasToken, active, now),
			"current":    row.ID == currentSessionID,
		})
	}

	httpserver.Success(c, http.StatusOK, gin.H{"sessions": items})
}

func (h *Handler) revokeSession(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}
	sessionID := strings.TrimSpace(c.Param("session_id"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id is required"})
		return
	}
	if h.sessionService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session service not configured"})
		return
	}

	var loginSession store.LoginSession
	if err := h.db.WithContext(c.Request.Context()).
		Where("id = ? AND user_id = ?", sessionID, userID).
		First(&loginSession).Error; err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	if err := h.sessionService.Logout(c.Request.Context(), sessionID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, http.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) logoutAll(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}
	if h.sessionService == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session service not configured"})
		return
	}
	if err := h.sessionService.LogoutAll(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, http.StatusOK, gin.H{"revoked": true})
}

type accountSessionRow struct {
	ID        string
	UserID    int64
	TenantID  int64
	ClientID  string
	RevokedAt *time.Time
	CreatedAt time.Time
}

func currentUser(c *gin.Context) (int64, string, int64, bool) {
	claims, ok := session.ClaimsFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing auth claims"})
		return 0, "", 0, false
	}
	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return 0, "", 0, false
	}
	return userID, claims.SessionID, claims.TenantID, true
}

func latestRefreshTokensBySession(c *gin.Context, db *gorm.DB, rows []accountSessionRow) (map[string]store.RefreshToken, error) {
	result := map[string]store.RefreshToken{}
	if len(rows) == 0 {
		return result, nil
	}
	sessionIDs := make([]string, 0, len(rows))
	for _, row := range rows {
		sessionIDs = append(sessionIDs, row.ID)
	}

	var tokens []store.RefreshToken
	if err := db.WithContext(c.Request.Context()).
		Where("session_id IN ?", sessionIDs).
		Order("created_at DESC, id DESC").
		Find(&tokens).Error; err != nil {
		return nil, err
	}
	for _, token := range tokens {
		if _, ok := result[token.SessionID]; ok {
			continue
		}
		result[token.SessionID] = token
	}
	return result, nil
}

func accountSessionClient(row accountSessionRow, token store.RefreshToken) string {
	if strings.TrimSpace(row.ClientID) != "" {
		return row.ClientID
	}
	if strings.TrimSpace(token.ClientID) != "" {
		return token.ClientID
	}
	return "GoAuth"
}

func accountSessionStatus(row accountSessionRow, token store.RefreshToken, hasToken, active bool, now time.Time) string {
	if row.RevokedAt != nil {
		return "revoked"
	}
	if active {
		return "active"
	}
	if hasToken && token.RevokedAt != nil {
		return "revoked"
	}
	if hasToken && !token.ExpiresAt.IsZero() && !token.ExpiresAt.After(now) {
		return "expired"
	}
	return "inactive"
}

func userDisplayName(user store.User) string {
	for _, value := range []string{user.Nickname, user.DisplayName, user.Username, user.Email} {
		if text := strings.TrimSpace(value); text != "" {
			return text
		}
	}
	return "GoAuth User"
}
