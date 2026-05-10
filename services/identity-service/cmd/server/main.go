package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/auth"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/config"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/idp"
	githubidp "goauth/services/identity-service/internal/idp/github"
	"goauth/services/identity-service/internal/mailer"
	"goauth/services/identity-service/internal/oidc"
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

	privateKey, err := loadSigningKey(cfg)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	redisClient, err := cache.OpenRedis(cfg)
	if err != nil {
		log.Printf("auth routes disabled until redis is available: %v", err)
		redisClient = nil
	} else {
		defer func() {
			if err := redisClient.Close(); err != nil {
				log.Printf("close redis: %v", err)
			}
		}()
	}

	router := buildRouter(cfg, db, redisClient, privateKey)
	if err := router.Run(cfg.HTTPAddr); err != nil {
		return fmt.Errorf("run server: %w", err)
	}
	return nil
}

func loadSigningKey(cfg config.Config) (*rsa.PrivateKey, error) {
	if cfg.JWTPrivateKeyPath != "" {
		return session.LoadRSAPrivateKey(cfg.JWTPrivateKeyPath)
	}

	log.Printf("JWT_PRIVATE_KEY_PATH is empty, generating ephemeral RSA key for local development")
	return rsa.GenerateKey(rand.Reader, 2048)
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
	sessionService := session.NewService(db, cfg, privateKey)
	sessionHandler := session.NewHandler(sessionService, &privateKey.PublicKey)
	rateLimiter := ratelimit.NewService(redisClient)
	sessionHandler.SetRateLimiter(rateLimiter)
	authMiddleware := session.AuthMiddleware(sessionService, &privateKey.PublicKey)
	systemMiddleware := session.SystemUserMiddleware(sessionService)
	auditService := audit.NewService(db)
	sessionService.SetAuditRecorder(auditService)
	oidcService := oidc.NewService(db, cfg, privateKey)
	oidcService.SetAuditRecorder(auditService)
	oidcService.SetRateLimiter(rateLimiter)
	oidcService.SetBrowserLoginURL(cfg.BrowserLoginURL)
	defaultMembershipPolicy := provisioning.NewDefaultMembershipPolicy(cfg.DefaultMemberTenantSlugs)

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
		registrars = append(registrars, idp.NewHandler(idpService, sessionService, authMiddleware))
	}

	router := httpserver.NewRouter(cfg, registrars...)

	rbacService := rbac.NewService(db, redisClient)
	tenantService := tenant.NewService(db, rbacService)
	tenantService.SetAuditRecorder(auditService)
	userService := user.NewService(db, auditService)

	authGroup := router.Group("/v1/auth")
	sessionHandler.RegisterRoutes(authGroup)
	oidc.RegisterRoutes(router, oidcService)
	httpserver.RegisterRoutes(
		router,
		rbac.NewHandler(rbacService, authMiddleware, systemMiddleware),
		tenant.NewHandler(tenantService, authMiddleware, systemMiddleware),
		user.NewHandler(userService, authMiddleware, systemMiddleware),
		oidc.NewAdminHandler(oidcService, authMiddleware, systemMiddleware),
	)

	if redisClient != nil {
		authService := auth.NewService(db, redisClient, buildMailSender(cfg))
		authService.SetAuditRecorder(auditService)
		authService.SetDefaultMembershipPolicy(defaultMembershipPolicy)
		authHandler := auth.NewHandler(authService, sessionService)
		authHandler.SetRateLimiter(rateLimiter)
		authHandler.RegisterRoutes(authGroup)
	}

	return router
}

func buildMailSender(cfg config.Config) mailer.Sender {
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
