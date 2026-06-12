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
	"goauth/services/identity-service/internal/util"
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
	svc := buildServices(cfg, db, redisClient, keyring)
	router := buildRouterWithServices(cfg, db, redisClient, svc)
	registerRoutes(router, cfg, db, redisClient, keyring, svc)
	return router
}

// services holds all shared dependencies wired at startup.
type services struct {
	session     *session.Service
	sessionH    *session.Handler
	oidc        *oidc.Service
	audit       *audit.Service
	rateLimiter *ratelimit.Service
	lockout     *lockout.Manager
	pwPolicy    password.Policy
	captcha     *captcha.Verifier
	logoutCoord *logout.Coordinator
	tmplEngine  *mailer.TemplateEngine
	rbac        *rbac.Service
	tenant      *tenant.Service
	user        *user.Service
	userH       *user.Handler
	provisioning *provisioning.DefaultMembershipPolicy
	idp         *idp.Service
	idpH        *idp.Handler

	authMiddleware  gin.HandlerFunc
	systemMiddleware gin.HandlerFunc
}

func buildServices(cfg config.Config, db *gorm.DB, redisClient *redis.Client, keyring *jwtkey.Keyring) *services {
	// Pre-create shared dependencies that multiple services need.
	auditService := audit.NewService(db)
	rateLimiter := ratelimit.NewService(redisClient)
	logoutCoord := logout.NewCoordinatorWithKeyring(db, keyring, cfg.PublicIssuerURL)
	logoutCoord.SetAuditRecorder(auditService)

	// Session service with all deps via constructor.
	sessionService := session.NewServiceWithKeyringAndDeps(db, cfg, keyring, session.Dependencies{
		Sessions:          store.NewSessionRepository(db),
		Audit:             auditService,
		LogoutCoordinator: logoutCoord,
	})
	sessionHandler := session.NewHandlerWithKeyring(sessionService, keyring)
	sessionHandler.SetRateLimiter(rateLimiter)
	authMW := session.AuthMiddlewareWithKeyring(sessionService, keyring)
	sysMW := session.SystemUserMiddleware(sessionService)

	oidcService := oidc.NewServiceWithKeyring(db, cfg, keyring)
	oidcService.SetDependencies(oidc.Dependencies{
		Audit:           auditService,
		RateLimiter:     rateLimiter,
		BrowserLoginURL: cfg.BrowserLoginURL,
	})

	defaultPolicy := provisioning.NewDefaultMembershipPolicy(cfg.DefaultMemberTenantSlugs)
	lockoutMgr := lockout.NewManager(redisClient, cfg.LockoutThreshold, cfg.LockoutDuration)
	pwPolicy := password.LoadFromConfig(cfg)
	captchaVerifier := captcha.NewVerifier(captcha.Provider(cfg.CaptchaProvider), cfg.CaptchaSecretKey)

	tmplEngine := mailer.NewTemplateEngine(cfg.DefaultLocale)

	rbacService := rbac.NewService(db, redisClient)
	tenantService := tenant.NewService(db, rbacService)
	tenantService.SetAuditRecorder(auditService)
	userService := user.NewService(db, auditService)

	userHandler := user.NewHandler(userService, tenantService, sessionService,
		authMW,
		sysMW)
	userHandler.SetLockoutManager(lockoutMgr)

	var idpService *idp.Service
	var idpHandler *idp.Handler
	if cfg.IsGitHubConfigured() {
		githubProvider := githubidp.New(githubidp.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURI:  cfg.GitHubRedirectURI,
		})
		idpService = idp.NewService(db, githubProvider)
		idpService.SetDependencies(idp.Dependencies{
			Audit:            auditService,
			Policy:           defaultPolicy,
			RegistrationMode: cfg.RegistrationMode,
		})

		idpHandler = idp.NewHandler(idpService, sessionService,
			authMW,
			cfg.BrowserCookieSecure)
		idpHandler.SetCaptchaVerifier(captchaVerifier)
		idpHandler.SetCaptchaActions(cfg.CaptchaActions)
		idpHandler.SetFrontendCallbackPath(frontendCallbackURLFromBrowserLoginURL(cfg.BrowserLoginURL))
		idpHandler.SetTrustedReturnToOrigins(cfg.PublicIssuerURL)
		if redisClient != nil {
			idpHandler.SetExchangeStore(idp.NewExchangeStore(redisClient))
		}
	}

	return &services{
		session:        sessionService,
		sessionH:       sessionHandler,
		oidc:           oidcService,
		audit:          auditService,
		rateLimiter:    rateLimiter,
		lockout:        lockoutMgr,
		pwPolicy:       pwPolicy,
		captcha:        captchaVerifier,
		logoutCoord:    logoutCoord,
		tmplEngine:     tmplEngine,
		rbac:           rbacService,
		tenant:         tenantService,
		user:           userService,
		userH:          userHandler,
		provisioning:   defaultPolicy,
		idp:            idpService,
		idpH:           idpHandler,
		authMiddleware:  authMW,
		systemMiddleware: sysMW,
	}
}

func buildRouterWithServices(cfg config.Config, db *gorm.DB, redisClient *redis.Client, svc *services) *gin.Engine {
	if cfg.MetricsEnabled {
		metrics.Register()
	}

	registrars := []httpserver.Registrar{
		httpserver.NewReadinessRegistrar(buildReadinessChecks(db, redisClient)...),
	}
	if svc.idpH != nil {
		registrars = append(registrars, svc.idpH)
	}

	router := httpserver.NewRouter(cfg, registrars...)
	router.Use(middleware.RequestID(), middleware.StructuredLogger())

	if cfg.MetricsEnabled {
		router.GET("/metrics", gin.WrapH(metrics.Handler()))
	}
	return router
}

func registerRoutes(router *gin.Engine, cfg config.Config, db *gorm.DB, redisClient *redis.Client, keyring *jwtkey.Keyring, svc *services) {
	privateKey := keyring.ActivePrivateKey()
	authGroup := router.Group("/v1/auth")
	auth.NewPublicConfigHandler(cfg).RegisterRoutes(authGroup)
	svc.sessionH.RegisterRoutes(authGroup)

	oidc.RegisterRoutes(router, svc.oidc)

	httpserver.RegisterRoutes(router,
		rbac.NewHandler(svc.rbac, svc.authMiddleware, svc.systemMiddleware),
		tenant.NewHandler(svc.tenant, svc.authMiddleware, svc.systemMiddleware),
		svc.userH,
		oidc.NewAdminHandler(svc.oidc, svc.authMiddleware, svc.systemMiddleware),
		account.NewHandler(db, svc.session, svc.authMiddleware, svc.pwPolicy, cfg.AvatarStorageDir),
		adminconsole.NewHandler(db, svc.session, svc.audit, svc.authMiddleware, svc.systemMiddleware, cfg),
	)

	inviteService := invite.NewService(db, privateKey, buildMailSender(cfg), svc.tmplEngine,
		util.DefaultString(cfg.BrandName, "GoAuth"), cfg.PublicIssuerURL)
	inviteService.SetAuditRecorder(svc.audit)
	invite.NewHandler(inviteService, svc.authMiddleware, svc.systemMiddleware).RegisterRoutes(router)

	if redisClient != nil {
		authService := auth.NewServiceWithDeps(auth.Dependencies{
			Users:    store.NewUserRepository(db),
			Redis:    redisClient,
			Mailer:   buildMailSender(cfg),
			DB:       db,
			Audit:    svc.audit,
			Policy:   svc.provisioning,
			Lockout:  svc.lockout,
			Password: svc.pwPolicy,
		})
		authHandler := auth.NewHandler(authService, svc.session)
		authHandler.SetRateLimiter(svc.rateLimiter)
		authHandler.SetCaptchaVerifier(svc.captcha)
		authHandler.SetCaptchaActions(cfg.CaptchaActions)
		authHandler.SetRegistrationMode(cfg.RegistrationMode)
		authHandler.SetLocalPasswordLoginEnabled(cfg.LocalPasswordLoginEnabled)
		authHandler.RegisterRoutes(authGroup)
	}
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


func frontendCallbackURLFromBrowserLoginURL(browserLoginURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(browserLoginURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "/external/callback"
	}
	return parsed.Scheme + "://" + parsed.Host + "/external/callback"
}

