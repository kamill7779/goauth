package humancheck

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) RegisterRoutes(router gin.IRoutes) {
	router.GET("/human-check/slider", h.createSlider)
	router.POST("/human-check/slider/verify", h.verifySlider)
}

func (h *Handler) createSlider(c *gin.Context) {
	challenge, err := h.service.CreateSliderChallenge(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": "human check unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": publicChallenge(challenge)})
}

func (h *Handler) verifySlider(c *gin.Context) {
	var input VerifyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	token, err := h.service.VerifySlider(c.Request.Context(), input)
	if err != nil {
		status := http.StatusForbidden
		if !errors.Is(err, ErrInvalidChallenge) {
			status = http.StatusServiceUnavailable
		}
		c.JSON(status, gin.H{"success": false, "error": "human check verification failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": token})
}

func publicChallenge(challenge Challenge) gin.H {
	return gin.H{
		"id":           challenge.ID,
		"nonce":        challenge.Nonce,
		"thumb_x":      challenge.ThumbX,
		"thumb_y":      challenge.ThumbY,
		"thumb_width":  challenge.ThumbWidth,
		"thumb_height": challenge.ThumbHeight,
		"width":        challenge.Width,
		"height":       challenge.Height,
		"image":        challenge.Image,
		"thumb":        challenge.Thumb,
	}
}
