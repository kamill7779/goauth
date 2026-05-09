package auth

import (
	stdhttp "net/http"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/session"
)

type Handler struct {
	service *Service
	session *session.Service
}

func NewHandler(service *Service, sessionService *session.Service) *Handler {
	return &Handler{
		service: service,
		session: sessionService,
	}
}

func (h *Handler) RegisterRoutes(router gin.IRoutes) {
	router.POST("/email/send-code", h.sendCode)
	router.POST("/register", h.register)
	router.POST("/login", h.login)
	router.POST("/password/forgot", h.forgotPassword)
	router.POST("/password/reset", h.resetPassword)
}

func (h *Handler) sendCode(c *gin.Context) {
	var request struct {
		Purpose string `json:"purpose"`
		Email   string `json:"email"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if request.Purpose == "" {
		request.Purpose = EmailCodePurposeRegister
	}
	if _, err := h.service.SendEmailCode(c.Request.Context(), request.Purpose, request.Email); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"sent": true})
}

func (h *Handler) register(c *gin.Context) {
	var request struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		EmailCode   string `json:"email_code"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.service.Register(c.Request.Context(), RegisterInput{
		Email:       request.Email,
		DisplayName: request.DisplayName,
		Password:    request.Password,
		EmailCode:   request.EmailCode,
		CodePurpose: EmailCodePurposeRegister,
	})
	if err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	httpserver.Success(c, stdhttp.StatusCreated, gin.H{
		"id":    user.ID,
		"email": user.Email,
	})
}

func (h *Handler) login(c *gin.Context) {
	var request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.service.Login(c.Request.Context(), LoginInput{
		Email:    request.Email,
		Password: request.Password,
	})
	if err != nil {
		c.JSON(stdhttp.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if h.session == nil {
		httpserver.Success(c, stdhttp.StatusOK, gin.H{
			"id":    user.ID,
			"email": user.Email,
		})
		return
	}

	pair, err := h.session.IssueTokens(c.Request.Context(), session.IssueTokensInput{
		User:     *user,
		TenantID: 0,
		ClientID: "goauth-web",
	})
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	cookieValue, err := h.session.IssueOIDCAuthorizeCookie(*user, 0, pair.SessionID)
	if err != nil {
		c.JSON(stdhttp.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	session.SetOIDCAuthorizeCookie(c, cookieValue, int(h.session.OIDCAuthorizeCookieTTL().Seconds()))

	httpserver.Success(c, stdhttp.StatusOK, pair)
}

func (h *Handler) forgotPassword(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.ForgotPassword(c.Request.Context(), request.Email); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"sent": true})
}

func (h *Handler) resetPassword(c *gin.Context) {
	var request struct {
		Email       string `json:"email"`
		NewPassword string `json:"new_password"`
		EmailCode   string `json:"email_code"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.service.ResetPassword(c.Request.Context(), ResetPasswordInput{
		Email:       request.Email,
		NewPassword: request.NewPassword,
		EmailCode:   request.EmailCode,
	}); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	httpserver.Success(c, stdhttp.StatusOK, gin.H{"reset": true})
}
