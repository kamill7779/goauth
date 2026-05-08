package user

import (
	stdhttp "net/http"
	"strconv"

	httpserver "example.com/identity-service/internal/http"
	"example.com/identity-service/internal/store"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	admin := router.Group("/v1/admin")

	admin.GET("/users", h.listUsers)
	admin.POST("/users", h.createUser)
	admin.PATCH("/users/:id", h.updateUser)
	admin.POST("/users/:id/disable", h.disableUser)
	admin.POST("/users/:id/enable", h.enableUser)
	admin.POST("/users/:id/reset-password", h.resetPassword)
}

func (h *Handler) listUsers(c *gin.Context) {
	users, err := h.service.ListUsers(c.Request.Context())
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	items := make([]gin.H, 0, len(users))
	for _, user := range users {
		items = append(items, userPayload(user))
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"users": items})
}

func (h *Handler) createUser(c *gin.Context) {
	var request CreateUserInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.service.CreateUser(c.Request.Context(), request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusCreated, userPayload(*user))
}

func (h *Handler) updateUser(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	var request UpdateUserInput
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.service.UpdateUser(c.Request.Context(), id, request)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, userPayload(*user))
}

func (h *Handler) disableUser(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	if err := h.service.DisableUser(c.Request.Context(), id); err != nil {
		status := stdhttp.StatusBadRequest
		if err == ErrProtectedUser {
			status = stdhttp.StatusForbidden
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"disabled": true})
}

func (h *Handler) enableUser(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	if err := h.service.EnableUser(c.Request.Context(), id); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"enabled": true})
}

func (h *Handler) resetPassword(c *gin.Context) {
	id, err := parseUserID(c)
	if err != nil {
		return
	}

	var request struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.ResetPassword(c.Request.Context(), id, request.NewPassword); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusOK, gin.H{"reset": true})
}

func parseUserID(c *gin.Context) (int64, error) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": "invalid id"})
		return 0, err
	}
	return id, nil
}

func userPayload(user store.User) gin.H {
	return gin.H{
		"id":           user.ID,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"avatar_url":   user.AvatarURL,
		"status":       user.Status,
		"created_at":   user.CreatedAt,
		"updated_at":   user.UpdatedAt,
	}
}
