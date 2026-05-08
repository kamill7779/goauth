# GoAuth Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build GoAuth, a standalone, deployable multi-tenant identity service with email login, token lifecycle management, tenant-scoped RBAC, OIDC provider endpoints, and a GitHub external login adapter.

**Architecture:** Create a new service with a clean router -> handler -> service -> repository structure. MySQL is the primary database, Redis handles ephemeral state and hot-path caches, and OIDC/JWT endpoints expose the service as an identity provider for other systems.

**Tech Stack:** Go 1.22+, Gin, GORM v2, MySQL, Redis, golang-jwt/jwt/v5, bcrypt or argon2id, Docker Compose.

---

## Phase 0: Repository Decision

This plan assumes the identity service will be created as a standalone repository or a top-level standalone service directory. If it is developed inside the current repository first, use `services/identity-service` as the root and avoid touching existing gateway code.

Recommended root for in-repo prototyping:

```text
services/identity-service
```

## Task 1: Create Service Skeleton

**Files:**

- Create: `services/identity-service/go.mod`
- Create: `services/identity-service/cmd/server/main.go`
- Create: `services/identity-service/internal/config/config.go`
- Create: `services/identity-service/internal/http/router.go`
- Create: `services/identity-service/internal/http/response.go`
- Create: `services/identity-service/.env.example`

**Step 1: Initialize module**

Run:

```bash
cd services/identity-service
go mod init example.com/identity-service
go get github.com/gin-gonic/gin gorm.io/gorm gorm.io/driver/mysql gorm.io/driver/sqlite github.com/redis/go-redis/v9 github.com/golang-jwt/jwt/v5 golang.org/x/crypto
```

Expected: `go.mod` and `go.sum` are created.

**Step 2: Add config loader**

Implement `internal/config/config.go` with typed fields for HTTP address, issuer URL, MySQL DSN, Redis URL, token TTLs, SMTP, CORS, and GitHub OAuth settings.

**Step 3: Add health route**

Implement:

```text
GET /healthz
```

Expected response:

```json
{"success":true,"data":{"status":"ok"}}
```

**Step 4: Verify**

Run:

```bash
go run ./cmd/server
curl -fsS http://127.0.0.1:8080/healthz
```

Expected: health response returns HTTP 200.

**Step 5: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): scaffold standalone identity service"
```

## Task 2: Add Database and Redis Infrastructure

**Files:**

- Create: `services/identity-service/internal/store/db.go`
- Create: `services/identity-service/internal/store/models.go`
- Create: `services/identity-service/internal/cache/redis.go`
- Create: `services/identity-service/internal/cache/keys.go`
- Modify: `services/identity-service/cmd/server/main.go`

**Step 1: Define GORM models**

Create models for:

- `User`
- `UserIdentity`
- `Tenant`
- `TenantMember`
- `Role`
- `Permission`
- `RolePermission`
- `MemberRole`
- `OAuthClient`
- `OAuthAuthorizationCode`
- `RefreshToken`
- `ExternalProviderConfig`
- `AuditLog`

Use explicit GORM indexes for unique constraints described in the design document.

**Step 2: Add database initialization**

Implement `OpenDB(cfg)` and `AutoMigrate(db)`.

Use MySQL when `MYSQL_DSN` is set and SQLite only for local tests.

**Step 3: Add Redis initialization**

Implement `OpenRedis(cfg)` and typed key helpers:

```go
EmailCodeKey(purpose, email string) string
UserCacheKey(userID int64) string
SessionKey(sessionID string) string
PermissionCacheKey(tenantID, userID int64) string
JtiDenylistKey(jti string) string
OIDCStateKey(state string) string
```

**Step 4: Verify**

Run:

```bash
go test ./internal/store ./internal/cache
```

Expected: packages compile and unit tests pass.

**Step 5: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): add store and cache infrastructure"
```

## Task 3: Implement Email Verification and Password Auth

**Files:**

- Create: `services/identity-service/internal/auth/password.go`
- Create: `services/identity-service/internal/auth/email_code.go`
- Create: `services/identity-service/internal/auth/service.go`
- Create: `services/identity-service/internal/auth/handler.go`
- Create: `services/identity-service/internal/mailer/mailer.go`
- Modify: `services/identity-service/internal/http/router.go`

**Step 1: Write tests first**

Create tests for:

- Password hash validates the original password.
- Wrong password fails.
- Email verification code is stored in Redis with TTL.
- Registration requires a verified code.
- Duplicate email registration fails.
- Login fails for disabled users.

Run:

```bash
go test ./internal/auth
```

Expected: tests fail before implementation.

**Step 2: Implement password helpers**

Use bcrypt first because it is already familiar in the reference project. Keep the interface small so argon2id can replace it later.

**Step 3: Implement auth endpoints**

Routes:

```text
POST /v1/auth/email/send-code
POST /v1/auth/register
POST /v1/auth/login
POST /v1/auth/password/forgot
POST /v1/auth/password/reset
```

**Step 4: Verify**

Run:

```bash
go test ./internal/auth
```

Expected: tests pass.

**Step 5: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): add email and password authentication"
```

## Task 4: Implement Access and Refresh Tokens

**Files:**

- Create: `services/identity-service/internal/session/token.go`
- Create: `services/identity-service/internal/session/refresh.go`
- Create: `services/identity-service/internal/session/handler.go`
- Create: `services/identity-service/internal/session/middleware.go`
- Modify: `services/identity-service/internal/http/router.go`
- Modify: `services/identity-service/internal/auth/service.go`

**Step 1: Write tests first**

Create tests for:

- Access token contains `sub`, `sid`, `tid`, `aud`, `jti`, and `ver`.
- Refresh token is stored only as a hash.
- Refresh rotates the token.
- Reusing a rotated refresh token revokes the token family.
- Logout revokes one session.
- Logout all increments user token version.

Run:

```bash
go test ./internal/session
```

Expected: tests fail before implementation.

**Step 2: Implement JWT signing**

Use `github.com/golang-jwt/jwt/v5`.

Support:

- RSA private key loading.
- Key ID in JWT header.
- JWKS public key export later in the OIDC task.

**Step 3: Implement refresh token lifecycle**

Implement:

```text
POST /v1/auth/refresh
POST /v1/auth/logout
POST /v1/auth/logout-all
GET  /v1/auth/me
```

**Step 4: Verify**

Run:

```bash
go test ./internal/session ./internal/auth
```

Expected: tests pass.

**Step 5: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): add access and refresh token lifecycle"
```

## Task 5: Implement Tenant-Scoped RBAC

**Files:**

- Create: `services/identity-service/internal/rbac/service.go`
- Create: `services/identity-service/internal/rbac/handler.go`
- Create: `services/identity-service/internal/tenant/service.go`
- Create: `services/identity-service/internal/tenant/handler.go`
- Modify: `services/identity-service/internal/http/router.go`

**Step 1: Write tests first**

Create tests for:

- A member with a role has the role permissions.
- Removing a role removes access.
- A user can have different roles in different tenants.
- Permission cache invalidates after role changes.
- Disabled users and disabled members fail checks.

Run:

```bash
go test ./internal/rbac ./internal/tenant
```

Expected: tests fail before implementation.

**Step 2: Implement RBAC service**

Implement permission resolution:

```go
Can(ctx, userID, tenantID int64, permission string) (bool, error)
ListPermissions(ctx, userID, tenantID int64) ([]string, error)
```

Use Redis for permission cache and MySQL as source of truth.

**Step 3: Add RBAC APIs**

Routes:

```text
POST /v1/authz/check
POST /v1/authz/check-batch
GET  /v1/tenants/:tenant_id/my-permissions
```

**Step 4: Add tenant and role admin APIs**

Routes:

```text
GET    /v1/admin/tenants
POST   /v1/admin/tenants
PATCH  /v1/admin/tenants/:id
POST   /v1/admin/tenants/:id/members
DELETE /v1/admin/tenants/:id/members/:user_id
GET    /v1/admin/roles
POST   /v1/admin/roles
PATCH  /v1/admin/roles/:id
DELETE /v1/admin/roles/:id
POST   /v1/admin/roles/:id/permissions
DELETE /v1/admin/roles/:id/permissions/:permission_id
POST   /v1/admin/members/:member_id/roles
DELETE /v1/admin/members/:member_id/roles/:role_id
```

**Step 5: Verify**

Run:

```bash
go test ./internal/rbac ./internal/tenant
```

Expected: tests pass.

**Step 6: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): add tenant scoped rbac"
```

## Task 6: Implement OIDC Provider

**Files:**

- Create: `services/identity-service/internal/oidc/discovery.go`
- Create: `services/identity-service/internal/oidc/jwks.go`
- Create: `services/identity-service/internal/oidc/authorize.go`
- Create: `services/identity-service/internal/oidc/token.go`
- Create: `services/identity-service/internal/oidc/userinfo.go`
- Create: `services/identity-service/internal/oidc/client.go`
- Modify: `services/identity-service/internal/http/router.go`

**Step 1: Write tests first**

Create tests for:

- Discovery document contains issuer, authorization endpoint, token endpoint, userinfo endpoint, and jwks URI.
- Authorization endpoint requires a valid client and redirect URI.
- Authorization code is hashed in storage.
- Token endpoint validates PKCE.
- Token endpoint returns ID token, access token, and refresh token.
- UserInfo returns user claims for a valid access token.
- Revocation revokes refresh tokens.

Run:

```bash
go test ./internal/oidc
```

Expected: tests fail before implementation.

**Step 2: Implement discovery and JWKS**

Routes:

```text
GET /.well-known/openid-configuration
GET /oauth2/jwks
```

**Step 3: Implement OAuth clients**

Add repository and admin service methods for client creation, secret hashing, redirect URI validation, and scope validation.

**Step 4: Implement Authorization Code + PKCE**

Routes:

```text
GET  /oauth2/authorize
POST /oauth2/token
```

Do not implement implicit flow.

**Step 5: Implement UserInfo, Introspection, Revocation, Logout**

Routes:

```text
GET  /oauth2/userinfo
POST /oauth2/introspect
POST /oauth2/revoke
GET  /oauth2/logout
```

**Step 6: Verify**

Run:

```bash
go test ./internal/oidc ./internal/session ./internal/auth
```

Expected: tests pass.

**Step 7: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): add oidc provider endpoints"
```

## Task 7: Implement External Provider Abstraction and GitHub

**Files:**

- Create: `services/identity-service/internal/idp/provider.go`
- Create: `services/identity-service/internal/idp/service.go`
- Create: `services/identity-service/internal/idp/handler.go`
- Create: `services/identity-service/internal/idp/github/github.go`
- Modify: `services/identity-service/internal/http/router.go`

**Step 1: Write tests first**

Create tests for:

- GitHub adapter builds the correct authorization URL.
- GitHub adapter exchanges code using the configured redirect URI.
- GitHub adapter fetches `/user` and `/user/emails`.
- Hidden GitHub email is resolved from primary verified email.
- Existing identity logs into the local user.
- Existing email without identity requires local login before binding.
- Logged-in user can bind GitHub identity.

Run:

```bash
go test ./internal/idp ./internal/idp/github
```

Expected: tests fail before implementation.

**Step 2: Implement provider interface**

Use:

```go
type Provider interface {
    Slug() string
    DisplayName() string
    AuthCodeURL(state string, opts AuthCodeOptions) (string, error)
    ExchangeCode(ctx context.Context, code string, redirectURI string) (*TokenSet, error)
    FetchProfile(ctx context.Context, token *TokenSet) (*ExternalProfile, error)
}
```

**Step 3: Implement GitHub provider**

Use:

```text
Authorization URL: https://github.com/login/oauth/authorize
Token URL:         https://github.com/login/oauth/access_token
User API:          https://api.github.com/user
Emails API:        https://api.github.com/user/emails
Scopes:            read:user user:email
```

**Step 4: Add routes**

```text
GET    /v1/external/github/start
GET    /v1/external/github/callback
POST   /v1/external/github/bind
DELETE /v1/external/github/bind
GET    /v1/me/identities
```

**Step 5: Verify**

Run:

```bash
go test ./internal/idp ./internal/idp/github ./internal/auth
```

Expected: tests pass.

**Step 6: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): add github external identity provider"
```

## Task 8: Add Admin User Management and Audit Logs

**Files:**

- Create: `services/identity-service/internal/user/service.go`
- Create: `services/identity-service/internal/user/handler.go`
- Create: `services/identity-service/internal/audit/service.go`
- Modify: `services/identity-service/internal/http/router.go`

**Step 1: Write tests first**

Create tests for:

- Admin can list users.
- Admin can disable and enable users.
- Admin can reset user password.
- Root or system admin cannot be accidentally disabled without explicit permission checks.
- Role changes write audit logs.
- Login and logout write audit logs.

Run:

```bash
go test ./internal/user ./internal/audit
```

Expected: tests fail before implementation.

**Step 2: Implement admin APIs**

Routes:

```text
GET   /v1/admin/users
POST  /v1/admin/users
PATCH /v1/admin/users/:id
POST  /v1/admin/users/:id/disable
POST  /v1/admin/users/:id/enable
POST  /v1/admin/users/:id/reset-password
```

**Step 3: Implement audit writer**

Write audit events for:

- login
- logout
- password reset
- token refresh reuse detection
- tenant membership changes
- role assignment changes
- OAuth client changes
- external identity binding changes

**Step 4: Verify**

Run:

```bash
go test ./internal/user ./internal/audit ./...
```

Expected: tests pass.

**Step 5: Commit**

```bash
git add services/identity-service
git commit -m "feat(identity): add admin user management and audit logs"
```

## Task 9: Add Docker Compose and Operational Documentation

**Files:**

- Create: `services/identity-service/Dockerfile`
- Create: `services/identity-service/docker-compose.yml`
- Create: `services/identity-service/README.md`
- Create: `services/identity-service/docs/client-integration.md`
- Create: `services/identity-service/docs/oidc-integration.md`

**Step 1: Add Dockerfile**

Build a small production image with a multi-stage Go build.

**Step 2: Add Docker Compose**

Services:

```text
identity-service
mysql
redis
```

**Step 3: Add integration docs**

Document:

- Environment variables.
- How to create the first admin.
- How to register an OAuth client.
- How a business system redirects to `/oauth2/authorize`.
- How a business API validates JWTs with JWKS.
- How a business API calls `/v1/authz/check`.

**Step 4: Verify**

Run:

```bash
docker compose up -d --build
curl -fsS http://127.0.0.1:8080/healthz
docker compose logs identity-service
```

Expected: service starts and health check succeeds.

**Step 5: Commit**

```bash
git add services/identity-service
git commit -m "docs(identity): add deployment and integration guide"
```

## Final Verification

Run:

```bash
go test ./...
docker compose up -d --build
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/.well-known/openid-configuration
```

Expected:

- All Go tests pass.
- Health check returns HTTP 200.
- OIDC discovery document returns HTTP 200 and contains the configured issuer.

## Execution Options

Plan complete and saved to `docs/plans/2026-05-08-identity-service-implementation-plan.md`.

Two execution options:

1. Subagent-Driven (this session) - Dispatch a fresh subagent per task, review between tasks, and iterate quickly.
2. Parallel Session (separate) - Open a new session with `executing-plans` and execute the plan with checkpoints.
