// Package main is the entry point for the identity-service.
// It wires together configuration, database, Redis, and HTTP router,
// then starts the Gin server with graceful shutdown.
//
// @title           GoAuth Identity Service
// @version         1.0
// @description     OAuth2 / OpenID Connect identity provider with self-service auth flows.
// @termsOfService  https://goauth.dev/terms
//
// @contact.name   GoAuth Team
// @contact.url    https://goauth.dev
// @contact.email  dev@goauth.dev
//
// @license.name   MIT
// @license.url    https://opensource.org/licenses/MIT
//
// @host           localhost:8080
// @BasePath       /
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and the access token.
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
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "goauth/services/identity-service/cmd/server/docs"
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

// main is the process entry point; it calls run and exits fatally on error.
func main() {
	if err := run(); err != nil {
		log.Fatalf("identity service: %v", err)
	}
}

// run initialises logging, config, DB, keyring, Redis, and the HTTP router,
// then starts the Gin server. It returns an error instead of calling log.Fatal
// so defers still run.
//
// Call chain: main.main → run → config.Load / store.OpenDB / store.AutoMigrate / loadSigningKeyring / requireRedis / bootstrapAdminUser / buildRouterWithKeyring
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

// requireRedis opens a Redis client; if Redis is unavailable the service cannot
// start (rate limiting, caching, and OIDC sessions all depend on it).
//
// Call chain: main.run → requireRedis → cache.OpenRedis
func requireRedis(cfg config.Config) (*redis.Client, error) {
	client, err := cache.OpenRedis(cfg)
	if err != nil {
		return nil, fmt.Errorf("redis is required: %w", err)
	}
	return client, nil
}

// loadSigningKeyring creates the JWT keyring from config, logging a notice
// when neither a key path nor a keyset directory is configured (ephemeral key).
//
// Call chain: main.run → loadSigningKeyring → jwtkey.Load
func loadSigningKeyring(cfg config.Config) (*jwtkey.Keyring, error) {
	if strings.TrimSpace(cfg.JWTPrivateKeyPath) == "" && strings.TrimSpace(cfg.JWTKeysetDir) == "" {
		log.Printf("JWT signing key path is empty, generating ephemeral RSA key for local development")
	}
	return jwtkey.Load(cfg)
}

// bootstrapAdminUser ensures a root-level admin account exists on first run.
// BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must both be set or both
// empty; a partial pair is an error.
//
// Call chain: main.run → bootstrapAdminUser → user.NewService / user.Service.EnsureBootstrapAdmin
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

// buildRouter constructs the full Gin router from a *rsa.PrivateKey for
// backward-compatibility with legacy callers. Prefer buildRouterWithKeyring.
//
// Call chain: legacy callers → buildRouter → jwtkey.NewKeyring / buildRouterWithKeyring
func buildRouter(cfg config.Config, db *gorm.DB, redisClient *redis.Client, privateKey *rsa.PrivateKey) *gin.Engine {
	var keyring *jwtkey.Keyring
	if privateKey != nil {
		keyring, _ = jwtkey.NewKeyring(cfg.JWTKeyID, map[string]*rsa.PrivateKey{cfg.JWTKeyID: privateKey})
	}
	return buildRouterWithKeyring(cfg, db, redisClient, keyring)
}

// buildRouterWithKeyring wires all services, constructs the Gin engine with
// middleware, registers every route group, and returns the ready-to-run router.
//
// Call chain: main.run → buildRouterWithKeyring → buildServices / buildRouterWithServices / registerRoutes
func buildRouterWithKeyring(cfg config.Config, db *gorm.DB, redisClient *redis.Client, keyring *jwtkey.Keyring) *gin.Engine {
	svc := buildServices(cfg, db, redisClient, keyring)
	router := buildRouterWithServices(cfg, db, redisClient, svc)
	registerRoutes(router, cfg, db, redisClient, keyring, svc)
	return router
}

// services holds all shared dependencies wired at startup — a manual DI
// container that avoids package-level globals.
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

// buildServices constructs every service/handler in dependency order, returning
// them in a single services struct. Callers that require optional subsystems
// (e.g. GitHub IDP) check Config flags before accessing the fields.
//
// Call chain: main.buildRouterWithKeyring → buildServices → audit.NewService / ratelimit.NewService / logout.NewCoordinatorWithKeyring / session.NewServiceWithKeyringAndDeps / oidc.NewServiceWithKeyring / ... (all service constructors)
func buildServices(cfg config.Config, db *gorm.DB, redisClient *redis.Client, keyring *jwtkey.Keyring) *services {
	// Pre-create shared dependencies that multiple services need.
	auditService := audit.NewService(db)
	rateLimiter := ratelimit.NewService(redisClient)
	logoutCoord := logout.NewCoordinatorWithKeyring(db, keyring, cfg.PublicIssuerURL)
	logoutCoord.SetDependencies(auditService)

	// Session service with all deps via constructor.
	sessionService := session.NewServiceWithKeyringAndDeps(db, cfg, keyring, session.Dependencies{
		Sessions:          store.NewSessionRepository(db),
		Audit:             auditService,
		LogoutCoordinator: logoutCoord,
	})
	sessionHandler := session.NewHandlerWithKeyring(sessionService, keyring, rateLimiter)
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
	tenantService.SetDependencies(auditService)
	userService := user.NewService(db, auditService)

	userHandler := user.NewHandler(userService, tenantService, sessionService,
		authMW,
		sysMW,
		lockoutMgr)

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
		idpHandler.SetDeps(idp.HandlerDeps{
			CaptchaVerifier:        captchaVerifier,
			CaptchaActions:         cfg.CaptchaActions,
			FrontendCallbackPath:   frontendCallbackURLFromBrowserLoginURL(cfg.BrowserLoginURL),
			TrustedReturnToOrigins: []string{cfg.PublicIssuerURL},
			ExchangeStore:          buildExchangeStore(redisClient),
		})
		if redisClient != nil {
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

// buildRouterWithServices creates the Gin engine, attaches middleware (RequestID,
// StructuredLogger), readiness checks, and the optional /metrics endpoint.
//
// Call chain: main.buildRouterWithKeyring → buildRouterWithServices → metrics.Register / http.NewReadinessRegistrar / http.NewRouter / middleware.RequestID / middleware.StructuredLogger
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

// registerRoutes mounts every route group on the engine: /v1/auth (auth flows,
// sessions), OIDC discovery/token/userinfo, admin CRUD (RBAC, tenants, users,
// clients, account, console), invites, and the Swagger UI.
//
// Call chain: main.buildRouterWithKeyring → registerRoutes → (all handler constructors and RegisterRoutes calls)
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
	inviteService.SetDependencies(svc.audit)
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
		authHandler.SetDeps(auth.HandlerDeps{
			RateLimiter:               svc.rateLimiter,
			CaptchaVerifier:           svc.captcha,
			CaptchaActions:            cfg.CaptchaActions,
			RegistrationMode:          cfg.RegistrationMode,
			LocalPasswordLoginEnabled: &cfg.LocalPasswordLoginEnabled,
		})
		authHandler.RegisterRoutes(authGroup)
	}

	// Swagger UI
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
}

// buildExchangeStore returns an IDP exchange store backed by Redis, or nil when
// Redis is unavailable.
//
// Call chain: main.buildServices → buildExchangeStore → idp.NewExchangeStore
func buildExchangeStore(redisClient *redis.Client) *idp.ExchangeStore {
	if redisClient != nil {
		return idp.NewExchangeStore(redisClient)
	}
	return nil
}

// buildMailSender returns the configured mailer.Sender implementation (console,
// SMTP, or noop). Falls back to noop when SMTP is requested but host/from are
// missing.
//
// Call chain: main.registerRoutes → buildMailSender → mailer constructors
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

// buildReadinessChecks returns the standard MySQL + Redis health checks for the
// /readyz endpoint.
//
// Call chain: main.buildRouterWithServices → buildReadinessChecks → (no downstream)
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


// frontendCallbackURLFromBrowserLoginURL derives the external IDP callback URL
// from the configured browser login URL by replacing the path with /external/callback.
// If parsing fails it falls back to a relative path.
//
// Call chain: main.buildServices → frontendCallbackURLFromBrowserLoginURL → url.Parse
func frontendCallbackURLFromBrowserLoginURL(browserLoginURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(browserLoginURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "/external/callback"
	}
	return parsed.Scheme + "://" + parsed.Host + "/external/callback"
}

