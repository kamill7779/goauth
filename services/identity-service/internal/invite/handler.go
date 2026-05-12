package invite

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
)

// Handler exposes invite management and redemption endpoints.
type Handler struct {
	service          *Service
	authMiddleware   gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

// NewHandler creates an invite Handler.
func NewHandler(svc *Service, authMiddleware, systemMiddleware gin.HandlerFunc) *Handler {
	return &Handler{
		service:          svc,
		authMiddleware:   authMiddleware,
		systemMiddleware: systemMiddleware,
	}
}

// RegisterRoutes registers invite routes on the engine.
func (h *Handler) RegisterRoutes(router *gin.Engine) {
	// Admin routes (require auth + system role).
	admin := router.Group("/v1/admin")
	if h.authMiddleware != nil {
		admin.Use(h.authMiddleware)
	}
	if h.systemMiddleware != nil {
		admin.Use(h.systemMiddleware)
	}
	admin.POST("/tenants/:id/invites", h.createInvite)
	admin.GET("/tenants/:id/invites", h.listInvites)
	admin.DELETE("/invites/:invite_id", h.revokeInvite)

	// Redeem route (requires auth — user must be logged in).
	v1 := router.Group("/v1")
	if h.authMiddleware != nil {
		v1.Use(h.authMiddleware)
	}
	v1.POST("/invites/redeem", h.redeemInvite)
}

func (h *Handler) createInvite(c *gin.Context) {
	tenantID, err := parseTenantID(c)
	if err != nil {
		return
	}

	var req struct {
		TargetEmail string `json:"target_email"`
		RoleID      int64  `json:"role_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	inviterID := int64(0)
	if claims, ok := session.ClaimsFromContext(c); ok {
		if parsed, err := strconv.ParseInt(claims.Subject, 10, 64); err == nil {
			inviterID = parsed
		}
	}

	inv, err := h.service.Create(c.Request.Context(), CreateInput{
		TenantID:    tenantID,
		RoleID:      req.RoleID,
		TargetEmail: req.TargetEmail,
		InviterID:   inviterID,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, http.StatusCreated, invitePayload(inv))
}

func (h *Handler) listInvites(c *gin.Context) {
	tenantID, err := parseTenantID(c)
	if err != nil {
		return
	}

	page, _ := strconv.Atoi(c.Query("page"))
	pageSize, _ := strconv.Atoi(c.Query("page_size"))

	invites, total, err := h.service.List(c.Request.Context(), tenantID, page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	items := make([]gin.H, 0, len(invites))
	for i := range invites {
		items = append(items, invitePayload(&invites[i]))
	}
	httpserver.Success(c, http.StatusOK, gin.H{
		"invites":   items,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

func (h *Handler) revokeInvite(c *gin.Context) {
	inviteID, err := strconv.ParseInt(c.Param("invite_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid invite_id"})
		return
	}

	if err := h.service.Revoke(c.Request.Context(), inviteID); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrInviteNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, http.StatusOK, gin.H{"revoked": true})
}

func (h *Handler) redeemInvite(c *gin.Context) {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := int64(0)
	if claims, ok := session.ClaimsFromContext(c); ok {
		if parsed, err := strconv.ParseInt(claims.Subject, 10, 64); err == nil {
			userID = parsed
		}
	}
	if userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	if err := h.service.Redeem(c.Request.Context(), RedeemInput{
		Token:  req.Token,
		UserID: userID,
	}); err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, ErrInviteExpired):
			status = http.StatusGone
		case errors.Is(err, ErrInviteRedeemed), errors.Is(err, ErrInviteRevoked):
			status = http.StatusConflict
		case errors.Is(err, ErrInvalidToken):
			status = http.StatusUnprocessableEntity
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, http.StatusOK, gin.H{"redeemed": true})
}

func parseTenantID(c *gin.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return 0, err
	}
	return id, nil
}

func invitePayload(inv *store.Invite) gin.H {
	return gin.H{
		"id":           inv.ID,
		"tenant_id":    inv.TenantID,
		"role_id":      inv.RoleID,
		"target_email": inv.TargetEmail,
		"status":       inv.Status,
		"expires_at":   inv.ExpiresAt,
		"created_at":   inv.CreatedAt,
	}
}
