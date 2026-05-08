package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"strings"

	"example.com/identity-service/internal/auth"
	"example.com/identity-service/internal/cache"
	"example.com/identity-service/internal/config"
	httpserver "example.com/identity-service/internal/http"
	"example.com/identity-service/internal/idp"
	githubidp "example.com/identity-service/internal/idp/github"
	"example.com/identity-service/internal/mailer"
	"example.com/identity-service/internal/rbac"
	"example.com/identity-service/internal/session"
	"example.com/identity-service/internal/store"
	"example.com/identity-service/internal/tenant"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	db, err := store.OpenDB(cfg)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := store.AutoMigrate(db); err != nil {
		log.Fatalf("auto migrate: %v", err)
	}

	privateKey, err := loadSigningKey(cfg)
	if err != nil {
		log.Fatalf("load signing key: %v", err)
	}

	redisClient, err := cache.OpenRedis(cfg)
	if err != nil {
		log.Printf("auth routes disabled until redis is available: %v", err)
		redisClient = nil
	}

	router := buildRouter(cfg, db, redisClient, privateKey)

	if err := router.Run(cfg.HTTPAddr); err != nil {
		log.Fatalf("run server: %v", err)
	}
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

	var registrars []httpserver.Registrar
	if githubIDPConfigured(cfg) {
		githubProvider := githubidp.New(githubidp.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURI:  cfg.GitHubRedirectURI,
		})
		idpService := idp.NewService(db, githubProvider)
		registrars = append(registrars, idp.NewHandler(idpService, sessionService, session.AuthMiddleware(&privateKey.PublicKey)))
	}

	router := httpserver.NewRouter(cfg, registrars...)

	rbacService := rbac.NewService(db, redisClient)
	tenantService := tenant.NewService(db, rbacService)

	authGroup := router.Group("/v1/auth")
	sessionHandler.RegisterRoutes(authGroup)
	rbac.NewHandler(rbacService).RegisterRoutes(router)
	tenant.NewHandler(tenantService).RegisterRoutes(router)

	if redisClient != nil {
		authService := auth.NewService(db, redisClient, mailer.NoopSender{})
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
