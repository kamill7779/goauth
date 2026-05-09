package auth

import (
	"errors"
	stdhttp "net/http"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/ratelimit"
	"goauth/services/identity-service/internal/session"
)

type Handler struct {
	service     *Service
	session     *session.Service
	rateLimiter *ratelimit.Service
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

func (h *Handler) RegisterBrowserRoutes(router gin.IRoutes) {
	router.GET("/oauth2/login", h.browserLoginPage)
	router.POST("/oauth2/login", h.browserLoginSubmit)
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
	if !h.allowJSONRateLimit(c, emailCodeRateLimitScope, rateLimitEmailCodeKey(c, request.Purpose, request.Email), emailCodeRateLimitLimit, emailCodeRateLimitWindow) {
		return
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
	if !h.allowJSONRateLimit(c, loginRateLimitScope, rateLimitKey(c, request.Email), loginRateLimitLimit, loginRateLimitWindow) {
		return
	}

	result, err := h.completeLogin(c.Request.Context(), LoginInput{
		Email:    request.Email,
		Password: request.Password,
	})
	if err != nil {
		statusCode, message := loginErrorResponse(err)
		c.JSON(statusCode, gin.H{"error": message})
		return
	}

	if result.pair == nil {
		httpserver.Success(c, stdhttp.StatusOK, gin.H{
			"id":    result.user.ID,
			"email": result.user.Email,
		})
		return
	}

	session.SetOIDCAuthorizeCookie(c, result.cookieValue, int(h.session.OIDCAuthorizeCookieTTL().Seconds()))
	httpserver.Success(c, stdhttp.StatusOK, result.pair)
}

func loginErrorResponse(err error) (int, string) {
	if errors.Is(err, ErrInvalidCredential) || errors.Is(err, ErrUserDisabled) {
		return stdhttp.StatusUnauthorized, err.Error()
	}
	return stdhttp.StatusInternalServerError, "login unavailable"
}

func (h *Handler) forgotPassword(c *gin.Context) {
	var request struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(stdhttp.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !h.allowJSONRateLimit(c, passwordResetRateLimitScope, rateLimitKey(c, request.Email), passwordResetRateLimitLimit, passwordResetRateLimitWindow) {
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
	if !h.allowJSONRateLimit(c, passwordResetRateLimitScope, rateLimitKey(c, request.Email), passwordResetRateLimitLimit, passwordResetRateLimitWindow) {
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
