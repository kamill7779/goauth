package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/account"
	adminconsole "goauth/services/identity-service/internal/admin"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/auth"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/captcha"
	"goauth/services/identity-service/internal/config"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/idp"
	githubidp "goauth/services/identity-service/internal/idp/github"
	"goauth/services/identity-service/internal/invite"
	"goauth/services/identity-service/internal/jwtkey"
	"goauth/services/identity-service/internal/lockout"
	"goauth/services/identity-service/internal/logout"
	"goauth/services/identity-service/internal/mailer"
	"goauth/services/identity-service/internal/metrics"
	"goauth/services/identity-service/internal/middleware"
	"goauth/services/identity-service/internal/oidc"
	"goauth/services/identity-service/internal/password"
	"goauth/services/identity-service/internal/provisioning"
	"goauth/services/identity-service/internal/ratelimit"
	"goauth/services/identity-service/internal/rbac"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"goauth/services/identity-service/internal/tenant"
	"goauth/services/identity-service/internal/user"
	"gorm.io/gorm"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("identity service: %v", err)
	}
}

func run() error {
	// Set up structured JSON logging globally.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	db, err := store.OpenDB(cfg)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("db handle: %w", err)
	}
	defer func() {
		if err := sqlDB.Close(); err != nil {
			log.Printf("close db: %v", err)
		}
	}()

	if err := store.AutoMigrate(db); err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}
	if err := bootstrapAdminUser(db, cfg); err != nil {
		return fmt.Errorf("bootstrap admin: %w", err)
	}

	keyring, err := loadSigningKeyring(cfg)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	redisClient, err := requireRedis(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if redisClient == nil {
			return
		}
		if err := redisClient.Close(); err != nil {
			log.Printf("close redis: %v", err)
		}
	}()

	router := buildRouterWithKeyring(cfg, db, redisClient, keyring)
	if err := router.Run(cfg.HTTPAddr); err != nil {
		return fmt.Errorf("run server: %w", err)
	}
	return nil
}

func requireRedis(cfg config.Config) (*redis.Client, error) {
	client, err := cache.OpenRedis(cfg)
	if err != nil {
		return nil, fmt.Errorf("redis is required: %w", err)
	}
	return client, nil
}

func loadSigningKey(cfg config.Config) (*rsa.PrivateKey, error) {
	keyring, err := loadSigningKeyring(cfg)
	if err != nil {
		return nil, err
	}
	return keyring.ActivePrivateKey(), nil
}

func loadSigningKeyring(cfg config.Config) (*jwtkey.Keyring, error) {
	if strings.TrimSpace(cfg.JWTPrivateKeyPath) == "" && strings.TrimSpace(cfg.JWTKeysetDir) == "" {
		log.Printf("JWT signing key path is empty, generating ephemeral RSA key for local development")
	}
	return jwtkey.Load(cfg)
}

func bootstrapAdminUser(db *gorm.DB, cfg config.Config) error {
	email := strings.TrimSpace(cfg.BootstrapAdminEmail)
	password := strings.TrimSpace(cfg.BootstrapAdminPassword)
	if email == "" && password == "" {
		return nil
	}
	if email == "" || password == "" {
		return fmt.Errorf("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be set together")
	}

	roleCode := strings.TrimSpace(cfg.BootstrapAdminRoleCode)
	if roleCode == "" {
		roleCode = "root"
	}

	userService := user.NewService(db, audit.NewService(db))
	record, err := userService.EnsureBootstrapAdmin(context.Background(), user.BootstrapAdminInput{
		Email:       email,
		Username:    strings.TrimSpace(cfg.BootstrapAdminUsername),
		Nickname:    strings.TrimSpace(cfg.BootstrapAdminNickname),
		DisplayName: strings.TrimSpace(cfg.BootstrapAdminDisplayName),
		Password:    password,
		RoleCode:    roleCode,
	})
	if err != nil {
		return err
	}

	log.Printf("bootstrap admin ready: user_id=%d email=%s role=%s", record.ID, record.Email, roleCode)
	return nil
}

func buildRouter(cfg config.Config, db *gorm.DB, redisClient *redis.Client, privateKey *rsa.PrivateKey) *gin.Engine {
	var keyring *jwtkey.Keyring
	if privateKey != nil {
		keyring, _ = jwtkey.NewKeyring(cfg.JWTKeyID, map[string]*rsa.PrivateKey{cfg.JWTKeyID: privateKey})
	}
	return buildRouterWithKeyring(cfg, db, redisClient, keyring)
}

func buildRouterWithKeyring(cfg config.Config, db *gorm.DB, redisClient *redis.Client, keyring *jwtkey.Keyring) *gin.Engine {
	privateKey := keyring.ActivePrivateKey()
	sessionService := session.NewServiceWithKeyring(db, cfg, keyring)
	sessionHandler := session.NewHandlerWithKeyring(sessionService, keyring)
	rateLimiter := ratelimit.NewService(redisClient)
	sessionHandler.SetRateLimiter(rateLimiter)
	authMiddleware := session.AuthMiddlewareWithKeyring(sessionService, keyring)
	systemMiddleware := session.SystemUserMiddleware(sessionService)
	auditService := audit.NewService(db)
	sessionService.SetAuditRecorder(auditService)
	oidcService := oidc.NewServiceWithKeyring(db, cfg, keyring)
	oidcService.SetAuditRecorder(auditService)
	oidcService.SetRateLimiter(rateLimiter)
	oidcService.SetBrowserLoginURL(cfg.BrowserLoginURL)
	defaultMembershipPolicy := provisioning.NewDefaultMembershipPolicy(cfg.DefaultMemberTenantSlugs)

	// Lockout manager.
	lockoutMgr := lockout.NewManager(redisClient, cfg.LockoutThreshold, cfg.LockoutDuration)

	// Password policy.
	pwPolicy := password.LoadFromConfig(cfg)

	// CAPTCHA verifier.
	captchaVerifier := captcha.NewVerifier(captcha.Provider(cfg.CaptchaProvider), cfg.CaptchaSecretKey)

	// Back-channel logout coordinator.
	logoutCoord := logout.NewCoordinatorWithKeyring(db, keyring, cfg.PublicIssuerURL)
	logoutCoord.SetAuditRecorder(auditService)
	sessionService.SetLogoutCoordinator(logoutCoord)

	// Email template engine.
	tmplEngine := mailer.NewTemplateEngine(cfg.DefaultLocale)

	// Metrics.
	if cfg.MetricsEnabled {
		metrics.Register()
	}

	registrars := []httpserver.Registrar{
		httpserver.NewReadinessRegistrar(buildReadinessChecks(db, redisClient)...),
	}
	if githubIDPConfigured(cfg) {
		githubProvider := githubidp.New(githubidp.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURI:  cfg.GitHubRedirectURI,
		})
		idpService := idp.NewService(db, githubProvider)
		idpService.SetAuditRecorder(auditService)
		idpService.SetDefaultMembershipPolicy(defaultMembershipPolicy)
		idpService.SetRegistrationMode(cfg.RegistrationMode)
		idpHandler := idp.NewHandler(idpService, sessionService, authMiddleware, cfg.BrowserCookieSecure)
		idpHandler.SetCaptchaVerifier(captchaVerifier)
		idpHandler.SetCaptchaActions(cfg.CaptchaActions)
		idpHandler.SetFrontendCallbackPath(frontendCallbackURLFromBrowserLoginURL(cfg.BrowserLoginURL))
		idpHandler.SetTrustedReturnToOrigins(cfg.PublicIssuerURL)
		if redisClient != nil {
			idpHandler.SetExchangeStore(idp.NewExchangeStore(redisClient))
		}
		registrars = append(registrars, idpHandler)
	}

	router := httpserver.NewRouter(cfg, registrars...)

	// Replace default Gin logger with structured middleware.
	router.Use(middleware.RequestID(), middleware.StructuredLogger())

	// Metrics endpoint.
	if cfg.MetricsEnabled {
		router.GET("/metrics", gin.WrapH(metrics.Handler()))
	}

	rbacService := rbac.NewService(db, redisClient)
	tenantService := tenant.NewService(db, rbacService)
	tenantService.SetAuditRecorder(auditService)
	userService := user.NewService(db, auditService)

	userHandler := user.NewHandler(userService, tenantService, sessionService, authMiddleware, systemMiddleware)
	userHandler.SetLockoutManager(lockoutMgr)

	authGroup := router.Group("/v1/auth")
	auth.NewPublicConfigHandler(cfg).RegisterRoutes(authGroup)
	sessionHandler.RegisterRoutes(authGroup)
	oidc.RegisterRoutes(router, oidcService)
	httpserver.RegisterRoutes(
		router,
		rbac.NewHandler(rbacService, authMiddleware, systemMiddleware),
		tenant.NewHandler(tenantService, authMiddleware, systemMiddleware),
		userHandler,
		oidc.NewAdminHandler(oidcService, authMiddleware, systemMiddleware),
		account.NewHandler(db, sessionService, authMiddleware, pwPolicy, cfg.AvatarStorageDir),
		adminconsole.NewHandler(db, sessionService, auditService, authMiddleware, systemMiddleware, cfg),
	)

	// Invite handler.
	inviteService := invite.NewService(db, privateKey, buildMailSender(cfg), tmplEngine, defaultString(cfg.BrandName, "GoAuth"), cfg.PublicIssuerURL)
	inviteService.SetAuditRecorder(auditService)
	invite.NewHandler(inviteService, authMiddleware, systemMiddleware).RegisterRoutes(router)

	if redisClient != nil {
		authService := auth.NewService(db, redisClient, buildMailSender(cfg))
		authService.SetAuditRecorder(auditService)
		authService.SetDefaultMembershipPolicy(defaultMembershipPolicy)
		authService.SetLockoutManager(lockoutMgr)
		authService.SetPasswordPolicy(pwPolicy)
		authHandler := auth.NewHandler(authService, sessionService)
		authHandler.SetRateLimiter(rateLimiter)
		authHandler.SetCaptchaVerifier(captchaVerifier)
		authHandler.SetCaptchaActions(cfg.CaptchaActions)
		authHandler.SetRegistrationMode(cfg.RegistrationMode)
		authHandler.SetLocalPasswordLoginEnabled(cfg.LocalPasswordLoginEnabled)
		authHandler.RegisterRoutes(authGroup)
	}

	return router
}

func buildMailSender(cfg config.Config) mailer.Sender {
	switch cfg.MailerProvider {
	case "noop":
		return mailer.NoopSender{}
	case "smtp":
		if strings.TrimSpace(cfg.SMTPHost) == "" || strings.TrimSpace(cfg.SMTPFrom) == "" {
			return mailer.NoopSender{}
		}
		return mailer.NewSMTPSender(mailer.SMTPConfig{
			Host:      cfg.SMTPHost,
			Port:      cfg.SMTPPort,
			Username:  cfg.SMTPUsername,
			Password:  cfg.SMTPPassword,
			From:      cfg.SMTPFrom,
			SSL:       cfg.SMTPSSLEnabled,
			AuthLogin: cfg.SMTPAuthLogin,
		})
	default:
		return mailer.NewConsoleSender(nil)
	}
}

func buildReadinessChecks(db *gorm.DB, redisClient *redis.Client) []httpserver.ReadinessCheck {
	return []httpserver.ReadinessCheck{
		{
			Name: "mysql",
			Check: func(ctx context.Context) error {
				if db == nil {
					return fmt.Errorf("db not configured")
				}
				sqlDB, err := db.DB()
				if err != nil {
					return fmt.Errorf("db handle: %w", err)
				}
				if err := sqlDB.PingContext(ctx); err != nil {
					return fmt.Errorf("ping db: %w", err)
				}
				return nil
			},
		},
		{
			Name: "redis",
			Check: func(ctx context.Context) error {
				if redisClient == nil {
					return fmt.Errorf("redis not configured")
				}
				if err := redisClient.Ping(ctx).Err(); err != nil {
					return fmt.Errorf("ping redis: %w", err)
				}
				return nil
			},
		},
	}
}

func githubIDPConfigured(cfg config.Config) bool {
	return cfg.GitHubOAuthEnabled &&
		strings.TrimSpace(cfg.GitHubClientID) != "" &&
		strings.TrimSpace(cfg.GitHubClientSecret) != "" &&
		strings.TrimSpace(cfg.GitHubRedirectURI) != ""
}

func frontendCallbackURLFromBrowserLoginURL(browserLoginURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(browserLoginURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "/external/callback"
	}
	return parsed.Scheme + "://" + parsed.Host + "/external/callback"
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
