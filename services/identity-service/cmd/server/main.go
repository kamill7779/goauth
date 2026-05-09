package main

import (
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

func buildRouter(cfg config.Config, db *gorm.DB, redisClient *redis.Client, privateKey *rsa.PrivateKey) *gin.Engine {
	sessionService := session.NewService(db, cfg, privateKey)
	sessionHandler := session.NewHandler(sessionService, &privateKey.PublicKey)
	authMiddleware := session.AuthMiddleware(sessionService, &privateKey.PublicKey)
	systemMiddleware := session.SystemUserMiddleware(sessionService)
	auditService := audit.NewService(db)
	sessionService.SetAuditRecorder(auditService)
	oidcService := oidc.NewService(db, cfg, privateKey)
	oidcService.SetAuditRecorder(auditService)

	var registrars []httpserver.Registrar
	if githubIDPConfigured(cfg) {
		githubProvider := githubidp.New(githubidp.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURI:  cfg.GitHubRedirectURI,
		})
		idpService := idp.NewService(db, githubProvider)
		idpService.SetAuditRecorder(auditService)
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
	)

	if redisClient != nil {
		authService := auth.NewService(db, redisClient, mailer.NoopSender{})
		authService.SetAuditRecorder(auditService)
		authHandler := auth.NewHandler(authService, sessionService)
		authHandler.RegisterRoutes(authGroup)
	}

	return router
}

func githubIDPConfigured(cfg config.Config) bool {
	return cfg.GitHubOAuthEnabled &&
		strings.TrimSpace(cfg.GitHubClientID) != "" &&
		strings.TrimSpace(cfg.GitHubClientSecret) != "" &&
		strings.TrimSpace(cfg.GitHubRedirectURI) != ""
}
