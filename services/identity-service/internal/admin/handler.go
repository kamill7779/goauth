package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/audit"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

type Handler struct {
	db               *gorm.DB
	sessionService   *session.Service
	audit            audit.Recorder
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

func NewHandler(db *gorm.DB, sessionService *session.Service, recorder audit.Recorder, authMiddleware, systemMiddleware gin.HandlerFunc) *Handler {
	if recorder == nil {
		recorder = audit.NoopRecorder{}
	}
	return &Handler{
		db:               db,
		sessionService:   sessionService,
		audit:            recorder,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
	}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	admin := router.Group("/v1/admin")
	if h.authMiddleware != nil {
		admin.Use(h.authMiddleware)
	}
	if h.systemMiddleware != nil {
		admin.Use(h.systemMiddleware)
	}

	admin.GET("/dashboard", h.dashboard)
	admin.GET("/permissions", h.listPermissions)
	admin.POST("/permissions", h.createPermission)
	admin.PATCH("/permissions/:id", h.updatePermission)
	admin.DELETE("/permissions/:id", h.deletePermission)
	admin.GET("/users/:id/sessions", h.listUserSessions)
	admin.POST("/users/:id/logout-all", h.logoutUserSessions)
	admin.GET("/audit-logs", h.listAuditLogs)
}

func (h *Handler) dashboard(c *gin.Context) {
	var totalUsers, activeSessions, totalTenants, totalOAuthClients int64
	if err := h.db.WithContext(c.Request.Context()).Model(&store.User{}).Count(&totalUsers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.db.WithContext(c.Request.Context()).Model(&store.RefreshToken{}).
		Distinct("session_id").
		Where("revoked_at IS NULL AND expires_at > ?", time.Now()).
		Count(&activeSessions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.db.WithContext(c.Request.Context()).Model(&store.Tenant{}).Where("deleted_at IS NULL").Count(&totalTenants).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.db.WithContext(c.Request.Context()).Model(&store.OAuthClient{}).Count(&totalOAuthClients).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	recentLogins, err := h.recentLogins(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	permissionChanges, err := h.permissionChanges(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"stats": gin.H{
			"total_users":         totalUsers,
			"active_sessions":     activeSessions,
			"total_tenants":       totalTenants,
			"total_oauth_clients": totalOAuthClients,
			"users_change":        "+0%",
			"sessions_change":     "+0%",
			"tenants_change":      "+0",
			"clients_change":      "+0",
		},
		"recent_logins":      recentLogins,
		"permission_changes": permissionChanges,
		"alerts":             []gin.H{},
	})
}

func (h *Handler) listPermissions(c *gin.Context) {
	var permissions []store.Permission
	if err := h.db.WithContext(c.Request.Context()).Order("resource ASC, action ASC, id ASC").Find(&permissions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, http.StatusOK, gin.H{"permissions": permissions})
}

func (h *Handler) createPermission(c *gin.Context) {
	var request permissionRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	record := store.Permission{
		Resource:    strings.TrimSpace(request.Resource),
		Action:      strings.TrimSpace(request.Action),
		Code:        strings.TrimSpace(request.Code),
		Description: strings.TrimSpace(request.Description),
	}
	if record.Code == "" {
		record.Code = record.Resource + ":" + record.Action
	}
	if record.Resource == "" || record.Action == "" || record.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource, action and code are required"})
		return
	}
	if err := h.db.WithContext(c.Request.Context()).Create(&record).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = h.recordAudit(c, "permission_created", "permission", strconv.FormatInt(record.ID, 10), map[string]any{
		"code": record.Code,
	})
	httpserver.Success(c, http.StatusCreated, record)
}

func (h *Handler) updatePermission(c *gin.Context) {
	id, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}
	var request permissionPatchRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]any{}
	if request.Resource != nil {
		updates["resource"] = strings.TrimSpace(*request.Resource)
	}
	if request.Action != nil {
		updates["action"] = strings.TrimSpace(*request.Action)
	}
	if request.Code != nil {
		updates["code"] = strings.TrimSpace(*request.Code)
	}
	if request.Description != nil {
		updates["description"] = strings.TrimSpace(*request.Description)
	}

	if len(updates) > 0 {
		if err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
			if err := tx.Model(&store.Permission{}).Where("id = ?", id).Updates(updates).Error; err != nil {
				return err
			}
			return bumpAllPermissionVersions(tx)
		}); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	var record store.Permission
	if err := h.db.WithContext(c.Request.Context()).First(&record, id).Error; err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	if len(updates) > 0 {
		_ = h.recordAudit(c, "permission_updated", "permission", strconv.FormatInt(record.ID, 10), updates)
	}
	httpserver.Success(c, http.StatusOK, record)
}

func (h *Handler) deletePermission(c *gin.Context) {
	id, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}
	if err := h.db.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("permission_id = ?", id).Delete(&store.RolePermission{}).Error; err != nil {
			return err
		}
		if err := tx.Delete(&store.Permission{}, id).Error; err != nil {
			return err
		}
		return bumpAllPermissionVersions(tx)
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = h.recordAudit(c, "permission_deleted", "permission", strconv.FormatInt(id, 10), nil)
	httpserver.Success(c, http.StatusOK, gin.H{"deleted": true})
}

func (h *Handler) listUserSessions(c *gin.Context) {
	userID, err := parseInt64Param(c, "id")
	if err != nil {
		return
	}
	var user store.User
	if err := h.db.WithContext(c.Request.Context()).First(&user, userID).Error; err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, gorm.ErrRecordNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	var tokens []store.RefreshToken
	if err := h.db.WithContext(c.Request.Context()).
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, time.Now()).
		Order("created_at DESC").
		Find(&tokens).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]gin.H, 0, len(tokens))
	seen := map[string]struct{}{}
	for _, token := range tokens {
		if _, ok := seen[token.SessionID]; ok {
			continue
		}
		seen[token.SessionID] = struct{}{}
		items = append(items, gin.H{
			"id":         token.SessionID,
			"user":       user.Email,
			"client":     sessionClientLabel(token),
			"ip":         token.IPAddress,
			"created_at": token.CreatedAt,
			"expires_at": token.ExpiresAt,
			"status":     "active",
		})
	}
	httpserver.Success(c, http.StatusOK, gin.H{"sessions": items})
}

func (h *Handler) logoutUserSessions(c *gin.Context) {
	userID, err := parseInt64Param(c, "id")
	if err != nil {
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
	_ = h.recordAudit(c, "admin_user_logout_all", audit.TargetTypeUser, strconv.FormatInt(userID, 10), nil)
	httpserver.Success(c, http.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) listAuditLogs(c *gin.Context) {
	page, pageSize := pagination(c)
	query := h.db.WithContext(c.Request.Context()).Model(&store.AuditLog{})
	if action := strings.TrimSpace(c.Query("action")); action != "" {
		query = query.Where("action = ?", action)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var logs []store.AuditLog
	if err := query.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	actorEmails, err := h.actorEmails(c, logs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]gin.H, 0, len(logs))
	for _, log := range logs {
		items = append(items, gin.H{
			"id":     log.ID,
			"action": log.Action,
			"actor":  actorEmails[log.ActorUserID],
			"target": log.TargetType + ":" + log.TargetID,
			"time":   log.CreatedAt,
			"ip":     log.IPAddress,
			"status": "success",
		})
	}

	httpserver.Success(c, http.StatusOK, gin.H{
		"audit_logs": items,
		"total":      total,
		"page":       page,
		"page_size":  pageSize,
	})
}

type permissionRequest struct {
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

type permissionPatchRequest struct {
	Resource    *string `json:"resource"`
	Action      *string `json:"action"`
	Code        *string `json:"code"`
	Description *string `json:"description"`
}

func parseInt64Param(c *gin.Context, name string) (int64, error) {
	value, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid " + name})
		return 0, err
	}
	return value, nil
}

func pagination(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.Query("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

func bumpAllPermissionVersions(tx *gorm.DB) error {
	return tx.Model(&store.TenantMember{}).
		Where("deleted_at IS NULL").
		Update("permission_version", gorm.Expr("permission_version + 1")).Error
}

func sessionClientLabel(token store.RefreshToken) string {
	if strings.TrimSpace(token.UserAgent) != "" {
		return token.UserAgent
	}
	if strings.TrimSpace(token.ClientID) != "" {
		return token.ClientID
	}
	return "GoAuth"
}

func (h *Handler) recentLogins(c *gin.Context) ([]gin.H, error) {
	var logs []store.AuditLog
	if err := h.db.WithContext(c.Request.Context()).
		Where("action = ?", "login").
		Order("id DESC").
		Limit(5).
		Find(&logs).Error; err != nil {
		return nil, err
	}
	actorEmails, err := h.actorEmails(c, logs)
	if err != nil {
		return nil, err
	}
	items := make([]gin.H, 0, len(logs))
	for _, log := range logs {
		items = append(items, gin.H{
			"id":       log.ID,
			"user":     actorEmails[log.ActorUserID],
			"ip":       log.IPAddress,
			"time":     log.CreatedAt.Format(time.RFC3339),
			"status":   "success",
			"location": "-",
		})
	}
	return items, nil
}

func (h *Handler) permissionChanges(c *gin.Context) ([]gin.H, error) {
	var logs []store.AuditLog
	if err := h.db.WithContext(c.Request.Context()).
		Where("action IN ?", []string{"role_permissions_granted", "role_permission_revoked", "role_assigned", "role_removed"}).
		Order("id DESC").
		Limit(5).
		Find(&logs).Error; err != nil {
		return nil, err
	}
	actorEmails, err := h.actorEmails(c, logs)
	if err != nil {
		return nil, err
	}
	items := make([]gin.H, 0, len(logs))
	for _, log := range logs {
		items = append(items, gin.H{
			"user":   actorEmails[log.ActorUserID],
			"action": log.Action,
			"time":   log.CreatedAt.Format(time.RFC3339),
		})
	}
	return items, nil
}

func (h *Handler) actorEmails(c *gin.Context, logs []store.AuditLog) (map[int64]string, error) {
	ids := make([]int64, 0, len(logs))
	seen := map[int64]struct{}{}
	for _, log := range logs {
		if log.ActorUserID == 0 {
			continue
		}
		if _, ok := seen[log.ActorUserID]; ok {
			continue
		}
		seen[log.ActorUserID] = struct{}{}
		ids = append(ids, log.ActorUserID)
	}
	result := map[int64]string{0: "system"}
	if len(ids) == 0 {
		return result, nil
	}

	var users []store.User
	if err := h.db.WithContext(c.Request.Context()).Where("id IN ?", ids).Find(&users).Error; err != nil {
		return nil, err
	}
	for _, user := range users {
		result[user.ID] = user.Email
	}
	for _, id := range ids {
		if result[id] == "" {
			result[id] = "user:" + strconv.FormatInt(id, 10)
		}
	}
	return result, nil
}

func (h *Handler) recordAudit(c *gin.Context, action, targetType, targetID string, metadata map[string]any) error {
	actorUserID := int64(0)
	if claims, ok := session.ClaimsFromContext(c); ok {
		if parsed, err := strconv.ParseInt(claims.Subject, 10, 64); err == nil {
			actorUserID = parsed
		}
	}
	return h.audit.Record(c.Request.Context(), audit.Entry{
		ActorUserID: actorUserID,
		Action:      action,
		TargetType:  targetType,
		TargetID:    targetID,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.Request.UserAgent(),
		Metadata:    metadata,
	})
}
