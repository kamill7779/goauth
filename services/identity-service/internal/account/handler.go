package account

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/auth"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/identity"
	"goauth/services/identity-service/internal/password"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Handler struct {
	db             *gorm.DB
	sessionService *session.Service
	authMiddleware gin.HandlerFunc
	pwPolicy       password.Policy
	avatarDir      string
}

func NewHandler(db *gorm.DB, sessionService *session.Service, authMiddleware gin.HandlerFunc, pwPolicy password.Policy, avatarDir string) *Handler {
	return &Handler{
		db:             db,
		sessionService: sessionService,
		authMiddleware: authMiddleware,
		pwPolicy:       pwPolicy,
		avatarDir:      defaultString(avatarDir, "data/avatars"),
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	account := router.Group("/v1/account")
	if h.authMiddleware != nil {
		account.Use(h.authMiddleware)
	}

	account.GET("/me", h.me)
	account.GET("/overview", h.overview)
	account.GET("/profile", h.profile)
	account.PATCH("/profile", h.updateProfile)
	account.POST("/avatar", h.uploadAvatar)
	account.GET("/login-methods", h.loginMethods)
	account.POST("/password/change", h.changePassword)
	account.GET("/activity", h.activity)
	account.GET("/authorized-apps", h.authorizedApps)
	account.DELETE("/authorized-apps/:client_id", h.revokeAuthorizedApp)
	account.GET("/sessions", h.listSessions)
	account.POST("/sessions/:session_id/revoke", h.revokeSession)
	account.POST("/logout-all", h.logoutAll)

	if err := os.MkdirAll(h.avatarDir, 0o755); err == nil {
		router.Static("/uploads/avatars", h.avatarDir)
	}
}

func (h *Handler) me(c *gin.Context) {
	userID, sessionID, tenantID, ok := currentUser(c)
	if !ok {
		return
	}

	user, err := h.loadActiveUser(c, userID)
	if err != nil {
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

	displayName := userDisplayName(*user)
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

func (h *Handler) overview(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	user, err := h.loadActiveUser(c, userID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	var identities []store.UserIdentity
	if err := h.db.WithContext(c.Request.Context()).
		Where("user_id = ?", userID).
		Order("created_at ASC, id ASC").
		Find(&identities).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	activeSessions, err := h.activeSessionCount(c, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	authorizedApps, err := h.authorizedAppRows(c, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	recentActivity, err := h.activityItems(c, userID, 5)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	loginMethodCount := 1 + len(identities)
	if accountHasLocalPassword(*user) {
		loginMethodCount++
	}
	signInMethodCount := len(identities)
	if accountHasLocalPassword(*user) {
		signInMethodCount++
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"summary": gin.H{
			"display_name":   userDisplayName(*user),
			"email":          user.Email,
			"avatar_url":     user.AvatarURL,
			"email_verified": user.EmailVerifiedAt != nil,
			"created_at":     user.CreatedAt,
		},
		"stats": gin.H{
			"active_sessions": activeSessions,
			"login_methods":   loginMethodCount,
			"authorized_apps": uniqueAuthorizedAppCount(authorizedApps),
		},
		"alerts":          accountOverviewAlerts(*user, signInMethodCount),
		"recent_activity": recentActivity,
	})
}

func (h *Handler) profile(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	user, err := h.loadActiveUser(c, userID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"profile": accountProfilePayload(*user),
	})
}

func (h *Handler) updateProfile(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	var request struct {
		Email       *string `json:"email"`
		Username    *string `json:"username"`
		Nickname    *string `json:"nickname"`
		DisplayName *string `json:"display_name"`
		AvatarURL   *string `json:"avatar_url"`
		Locale      *string `json:"locale"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.Email != nil && strings.TrimSpace(*request.Email) != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email change is not yet supported"})
		return
	}

	updates := map[string]any{}
	changedFields := make([]string, 0, 5)
	if request.Username != nil {
		username, err := identity.NormalizeUsername(*request.Username)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updates["username"] = username
		changedFields = append(changedFields, "username")
	}
	if request.Nickname != nil {
		updates["nickname"] = strings.TrimSpace(*request.Nickname)
		changedFields = append(changedFields, "nickname")
	}
	if request.DisplayName != nil {
		updates["display_name"] = strings.TrimSpace(*request.DisplayName)
		changedFields = append(changedFields, "display_name")
	}
	if request.AvatarURL != nil {
		updates["avatar_url"] = strings.TrimSpace(*request.AvatarURL)
		changedFields = append(changedFields, "avatar_url")
	}
	if request.Locale != nil {
		updates["locale"] = strings.TrimSpace(*request.Locale)
		changedFields = append(changedFields, "locale")
	}

	if len(updates) > 0 {
		updates["updated_at"] = time.Now().UTC()
		if err := h.db.WithContext(c.Request.Context()).
			Model(&store.User{}).
			Where("id = ? AND deleted_at IS NULL", userID).
			Updates(updates).Error; err != nil {
			if isUniqueConstraintError(err, "username") {
				c.JSON(http.StatusConflict, gin.H{"error": "username already exists"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		_ = audit.NewService(h.db).Record(c.Request.Context(), audit.Entry{
			ActorUserID: userID,
			Action:      audit.ActionUserUpdated,
			TargetType:  audit.TargetTypeUser,
			TargetID:    audit.UserTargetID(userID),
			Metadata: map[string]any{
				"fields": changedFields,
				"source": "account_profile",
			},
		})
	}

	user, err := h.loadActiveUser(c, userID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"profile": accountProfilePayload(*user),
	})
}

func (h *Handler) uploadAvatar(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	header, err := c.FormFile("avatar")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "avatar file is required"})
		return
	}
	if header.Size > maxAvatarUploadBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "avatar file is too large"})
		return
	}

	file, err := header.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	defer file.Close()

	payload, err := io.ReadAll(io.LimitReader(file, maxAvatarUploadBytes+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if int64(len(payload)) > maxAvatarUploadBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "avatar file is too large"})
		return
	}

	ext, ok := avatarFileExtension(http.DetectContentType(payload))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "avatar must be png, jpeg, gif, or webp"})
		return
	}

	if err := os.MkdirAll(h.avatarDir, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	filename, err := avatarFilename(userID, ext)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	path := filepath.Join(h.avatarDir, filename)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	avatarURL := "/uploads/avatars/" + filename
	now := time.Now().UTC()
	if err := h.db.WithContext(c.Request.Context()).
		Model(&store.User{}).
		Where("id = ? AND deleted_at IS NULL", userID).
		Updates(map[string]any{
			"avatar_url": avatarURL,
			"updated_at": now,
		}).Error; err != nil {
		_ = os.Remove(path)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_ = audit.NewService(h.db).Record(c.Request.Context(), audit.Entry{
		ActorUserID: userID,
		Action:      audit.ActionUserUpdated,
		TargetType:  audit.TargetTypeUser,
		TargetID:    audit.UserTargetID(userID),
		Metadata: map[string]any{
			"fields": []string{"avatar_url"},
			"source": "account_avatar",
		},
	})

	httpserver.Success(c, http.StatusOK, gin.H{
		"avatar_url": avatarURL,
	})
}

func (h *Handler) loginMethods(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	user, err := h.loadActiveUser(c, userID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	var identities []store.UserIdentity
	if err := h.db.WithContext(c.Request.Context()).
		Where("user_id = ?", userID).
		Order("created_at ASC, id ASC").
		Find(&identities).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	methods := make([]gin.H, 0, len(identities)+2)
	if accountHasLocalPassword(*user) {
		methods = append(methods, gin.H{
			"key":          "password",
			"type":         "password",
			"label":        "密码",
			"bound":        true,
			"status":       "enabled",
			"verified":     true,
			"identifier":   "已设置密码",
			"can_unbind":   false,
			"created_at":   user.CreatedAt,
			"last_used_at": nil,
		})
	}
	methods = append(methods, gin.H{
		"key":          "email",
		"type":         "email",
		"label":        "邮箱",
		"bound":        strings.TrimSpace(user.Email) != "",
		"status":       accountEmailStatus(*user),
		"verified":     user.EmailVerifiedAt != nil,
		"identifier":   user.Email,
		"can_unbind":   false,
		"created_at":   user.CreatedAt,
		"last_used_at": nil,
	})
	for _, identity := range identities {
		methods = append(methods, accountIdentityMethod(identity))
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"methods": methods,
	})
}

func (h *Handler) changePassword(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	var request struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.CurrentPassword == "" || request.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password and new_password are required"})
		return
	}

	user, err := h.loadActiveUser(c, userID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	if !accountHasLocalPassword(*user) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "local password is not set"})
		return
	}
	if err := auth.CheckPassword(user.PasswordHash, request.CurrentPassword); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	if err := h.pwPolicy.Validate(request.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.pwPolicy.HistoryCount > 0 {
		var historyHashes []string
		if err := h.db.WithContext(c.Request.Context()).
			Model(&store.PasswordHistory{}).
			Where("user_id = ?", userID).
			Order("created_at DESC").
			Limit(h.pwPolicy.HistoryCount).
			Pluck("password_hash", &historyHashes).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		historyHashes = append([]string{user.PasswordHash}, historyHashes...)
		if err := h.pwPolicy.CheckHistory(request.NewPassword, historyHashes); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	newHash, err := auth.HashPassword(request.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash password: " + err.Error()})
		return
	}

	now := time.Now().UTC()
	if err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&store.User{}).
			Where("id = ? AND deleted_at IS NULL", userID).
			Updates(map[string]any{
				"password_hash": newHash,
				"token_version": gorm.Expr("token_version + 1"),
				"updated_at":    now,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		if h.pwPolicy.HistoryCount > 0 {
			if err := tx.Create(&store.PasswordHistory{
				UserID:       userID,
				PasswordHash: user.PasswordHash,
				CreatedAt:    now,
			}).Error; err != nil {
				return err
			}
		}
		return audit.NewService(tx).Record(c.Request.Context(), audit.Entry{
			ActorUserID: userID,
			Action:      audit.ActionPasswordChanged,
			TargetType:  audit.TargetTypeUser,
			TargetID:    audit.UserTargetID(userID),
			Metadata: map[string]any{
				"source": "account_center",
			},
		})
	}); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusUnauthorized
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"changed": true,
	})
}

func (h *Handler) authorizedApps(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	rows, err := h.authorizedAppRows(c, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now()
	byClientID := make(map[string]gin.H, len(rows))
	order := make([]string, 0, len(rows))
	for _, row := range rows {
		app, ok := byClientID[row.ClientID]
		if !ok {
			app = gin.H{
				"client_id":      row.ClientID,
				"name":           row.Name,
				"scopes":         parseJSONStringArray(row.AllowedScopes),
				"granted_at":     row.CreatedAt,
				"last_access_at": row.CreatedAt,
				"active":         false,
			}
			byClientID[row.ClientID] = app
			order = append(order, row.ClientID)
		}
		if createdAt, ok := app["granted_at"].(time.Time); !ok || row.CreatedAt.Before(createdAt) {
			app["granted_at"] = row.CreatedAt
		}
		if lastAccessAt, ok := app["last_access_at"].(time.Time); !ok || row.CreatedAt.After(lastAccessAt) {
			app["last_access_at"] = row.CreatedAt
		}
		if row.RevokedAt == nil && row.ExpiresAt.After(now) {
			app["active"] = true
		}
	}

	apps := make([]gin.H, 0, len(order))
	for _, clientID := range order {
		apps = append(apps, byClientID[clientID])
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"apps": apps,
	})
}

func (h *Handler) activity(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	limit := 20
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be a positive integer"})
			return
		}
		if value > 100 {
			value = 100
		}
		limit = value
	}

	items, err := h.activityItems(c, userID, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"items": items,
	})
}

func (h *Handler) revokeAuthorizedApp(c *gin.Context) {
	userID, _, _, ok := currentUser(c)
	if !ok {
		return
	}

	clientID := strings.TrimSpace(c.Param("client_id"))
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return
	}

	now := time.Now().UTC()
	if err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&store.LoginSession{}).
			Where("user_id = ? AND client_id = ? AND revoked_at IS NULL", userID, clientID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}
		if err := tx.Model(&store.RefreshToken{}).
			Where("user_id = ? AND client_id = ? AND revoked_at IS NULL", userID, clientID).
			Update("revoked_at", now).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_ = audit.NewService(h.db).Record(c.Request.Context(), audit.Entry{
		ActorUserID: userID,
		Action:      audit.ActionLogout,
		TargetType:  audit.TargetTypeOAuthClient,
		TargetID:    clientID,
		Metadata: map[string]any{
			"scope":     "authorized_app",
			"client_id": clientID,
		},
	})

	httpserver.Success(c, http.StatusOK, gin.H{
		"revoked": true,
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

const maxAvatarUploadBytes int64 = 2 * 1024 * 1024

func avatarFileExtension(contentType string) (string, bool) {
	switch contentType {
	case "image/png":
		return ".png", true
	case "image/jpeg":
		return ".jpg", true
	case "image/gif":
		return ".gif", true
	case "image/webp":
		return ".webp", true
	default:
		return "", false
	}
}

func avatarFilename(userID int64, ext string) (string, error) {
	random := make([]byte, 16)
	if _, err := cryptorand.Read(random); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s%s", userID, hex.EncodeToString(random), ext), nil
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

func (h *Handler) loadActiveUser(c *gin.Context, userID int64) (*store.User, error) {
	var user store.User
	if err := h.db.WithContext(c.Request.Context()).
		Where("id = ? AND deleted_at IS NULL", userID).
		First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func accountProfilePayload(user store.User) gin.H {
	return gin.H{
		"id":             user.ID,
		"email":          user.Email,
		"email_verified": user.EmailVerifiedAt != nil,
		"username":       user.Username,
		"nickname":       user.Nickname,
		"display_name":   user.DisplayName,
		"avatar_url":     user.AvatarURL,
		"locale":         user.Locale,
		"timezone":       "",
		"status":         user.Status,
		"created_at":     user.CreatedAt,
		"updated_at":     user.UpdatedAt,
	}
}

func isUniqueConstraintError(err error, field string) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "unique") && !strings.Contains(lower, "duplicate") {
		return false
	}
	return strings.Contains(lower, strings.ToLower(field))
}

func accountHasLocalPassword(user store.User) bool {
	hash := strings.TrimSpace(user.PasswordHash)
	return hash != "" && !strings.HasPrefix(hash, "!external:")
}

func accountEmailStatus(user store.User) string {
	if user.EmailVerifiedAt != nil {
		return "verified"
	}
	return "pending"
}

func accountIdentityMethod(identityRecord store.UserIdentity) gin.H {
	label := strings.TrimSpace(identityRecord.Provider)
	if label == "" {
		label = "oauth"
	}
	return gin.H{
		"key":          identityRecord.Provider,
		"type":         "oauth",
		"label":        strings.ToUpper(label[:1]) + label[1:],
		"bound":        true,
		"status":       "bound",
		"verified":     identityRecord.EmailVerified,
		"identifier":   accountIdentityIdentifier(identityRecord),
		"can_unbind":   true,
		"created_at":   identityRecord.CreatedAt,
		"last_used_at": nil,
		"avatar_url":   identityRecord.AvatarURL,
	}
}

func accountIdentityIdentifier(identityRecord store.UserIdentity) string {
	for _, value := range []string{identityRecord.Username, identityRecord.Email, identityRecord.ProviderUserID} {
		if text := strings.TrimSpace(value); text != "" {
			return text
		}
	}
	return identityRecord.Provider
}

type accountAuthorizedAppRow struct {
	ClientID      string
	Name          string
	AllowedScopes datatypes.JSON
	CreatedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
}

func (h *Handler) authorizedAppRows(c *gin.Context, userID int64) ([]accountAuthorizedAppRow, error) {
	var tokens []struct {
		ClientID  string
		CreatedAt time.Time
		ExpiresAt time.Time
		RevokedAt *time.Time
	}
	if err := h.db.WithContext(c.Request.Context()).
		Model(&store.RefreshToken{}).
		Where("user_id = ? AND client_id <> ''", userID).
		Order("created_at DESC, id DESC").
		Find(&tokens).Error; err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, nil
	}

	clientIDs := make([]string, 0, len(tokens))
	seenClientIDs := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if _, seen := seenClientIDs[token.ClientID]; seen {
			continue
		}
		seenClientIDs[token.ClientID] = struct{}{}
		clientIDs = append(clientIDs, token.ClientID)
	}

	var clients []store.OAuthClient
	if err := h.db.WithContext(c.Request.Context()).
		Model(&store.OAuthClient{}).
		Where("client_id IN ?", clientIDs).
		Find(&clients).Error; err != nil {
		return nil, err
	}

	clientMap := make(map[string]store.OAuthClient, len(clients))
	for _, client := range clients {
		clientMap[client.ClientID] = client
	}

	rows := make([]accountAuthorizedAppRow, 0, len(tokens))
	for _, token := range tokens {
		client, ok := clientMap[token.ClientID]
		if !ok {
			continue
		}
		rows = append(rows, accountAuthorizedAppRow{
			ClientID:      token.ClientID,
			Name:          client.Name,
			AllowedScopes: client.AllowedScopes,
			CreatedAt:     token.CreatedAt,
			ExpiresAt:     token.ExpiresAt,
			RevokedAt:     token.RevokedAt,
		})
	}
	return rows, nil
}

func parseJSONStringArray(raw datatypes.JSON) []string {
	if len(raw) == 0 {
		return nil
	}
	var items []string
	if err := encodingjson.Unmarshal(raw, &items); err != nil {
		return nil
	}
	return items
}

func parseJSONMap(raw datatypes.JSON) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var payload map[string]any
	if err := encodingjson.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return payload
}

func (h *Handler) activityItems(c *gin.Context, userID int64, limit int) ([]gin.H, error) {
	var logs []store.AuditLog
	if err := h.db.WithContext(c.Request.Context()).
		Where("actor_user_id = ?", userID).
		Order("created_at DESC, id DESC").
		Limit(limit).
		Find(&logs).Error; err != nil {
		return nil, err
	}
	items := make([]gin.H, 0, len(logs))
	for _, log := range logs {
		items = append(items, accountActivityPayload(log))
	}
	return items, nil
}

func accountActivityPayload(log store.AuditLog) gin.H {
	metadata := parseJSONMap(log.Metadata)
	category, title, description := accountActivityPresentation(log.Action, metadata)
	return gin.H{
		"id":          log.ID,
		"action":      log.Action,
		"category":    category,
		"title":       title,
		"description": description,
		"created_at":  log.CreatedAt,
		"ip_address":  log.IPAddress,
		"user_agent":  log.UserAgent,
	}
}

func accountActivityPresentation(action string, metadata map[string]any) (string, string, string) {
	switch action {
	case audit.ActionUserUpdated:
		fields := jsonStringArrayValue(metadata, "fields")
		description := "更新了个人资料"
		if len(fields) > 0 {
			description = "变更字段：" + strings.Join(fields, "、")
		}
		return "profile", "更新了个人资料", description
	case audit.ActionExternalIdentityChanged:
		provider := accountProviderLabel(jsonStringValue(metadata, "provider"))
		change := jsonStringValue(metadata, "change")
		identifier := jsonStringValue(metadata, "identity_username")
		if identifier == "" {
			identifier = jsonStringValue(metadata, "provider_user_id")
		}
		description := identifier
		if description != "" {
			description = "账号：" + description
		}
		switch change {
		case "unbound":
			return "login_method", "解绑了 " + provider, description
		case "auto_bound":
			return "login_method", "自动绑定了 " + provider, description
		default:
			return "login_method", "绑定了 " + provider, description
		}
	case audit.ActionPasswordChanged:
		return "security", "修改了密码", jsonStringValue(metadata, "source")
	case audit.ActionPasswordReset:
		return "security", "重置了密码", jsonStringValue(metadata, "source")
	case audit.ActionLogin:
		provider := accountProviderLabel(jsonStringValue(metadata, "provider"))
		if provider == "" {
			return "session", "登录了账号", ""
		}
		return "session", "通过 " + provider + " 登录", ""
	case audit.ActionLogout:
		return "session", "退出了登录", jsonStringValue(metadata, "scope")
	default:
		return "account", action, ""
	}
}

func accountProviderLabel(provider string) string {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return ""
	}
	switch strings.ToLower(provider) {
	case "github":
		return "GitHub"
	default:
		return strings.ToUpper(provider[:1]) + provider[1:]
	}
}

func jsonStringValue(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	if value, ok := metadata[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func jsonStringArrayValue(metadata map[string]any, key string) []string {
	if metadata == nil {
		return nil
	}
	values, ok := metadata[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		result = append(result, text)
	}
	return result
}

func (h *Handler) activeSessionCount(c *gin.Context, userID int64) (int64, error) {
	var count int64
	err := h.db.WithContext(c.Request.Context()).
		Model(&store.LoginSession{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Count(&count).Error
	return count, err
}

func uniqueAuthorizedAppCount(rows []accountAuthorizedAppRow) int {
	if len(rows) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		seen[row.ClientID] = struct{}{}
	}
	return len(seen)
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func accountOverviewAlerts(user store.User, signInMethodCount int) []gin.H {
	alerts := make([]gin.H, 0, 2)
	if user.EmailVerifiedAt == nil {
		alerts = append(alerts, gin.H{
			"key":         "email_unverified",
			"severity":    "warning",
			"title":       "邮箱尚未验证",
			"description": "验证邮箱后才能稳定接收安全通知和后续自助验证能力。",
		})
	}
	if signInMethodCount < 2 {
		alerts = append(alerts, gin.H{
			"key":         "single_login_method",
			"severity":    "info",
			"title":       "建议至少绑定两种登录方式",
			"description": "增加第二登录方式可以降低单一凭据失效时的账号恢复风险。",
		})
	}
	return alerts
}
