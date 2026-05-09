# GoAuth 实现计划

> **For Claude:** 实现该计划时，必须逐任务使用 `superpowers:executing-plans` 子技能。

**目标：** 构建 GoAuth，一个可独立部署的多租户身份认证服务，提供邮箱登录、令牌生命周期管理、租户级 RBAC、OIDC Provider 端点，以及 GitHub 外部登录适配器。

**架构：** 以清晰的 `router -> handler -> service -> repository` 分层结构实现服务。MySQL 作为主数据库，Redis 负责临时状态和热点缓存，OIDC/JWT 端点将该服务暴露为其他系统可接入的身份提供方。

**技术栈：** Go 1.24+、Gin、GORM v2、MySQL、Redis、golang-jwt/jwt/v5、bcrypt 或 argon2id、Docker Compose。

## 实现约束

- 本地开发、CI 与运行时镜像统一以 Go 1.24+ 作为最低语言和工具链基线。
- 实现保持轻量、直接、可读。优先使用小函数、显式流程控制和标准库优先方案，避免预先抽象、过早接口化和单次使用的额外间接层。
- 如果存在并行开发需求，必须在 `.worktrees/` 下创建隔离的 git worktree，并在独立分支中完成任务，不能把多个并行任务混入主工作区。
- 在创建项目内 worktree 之前，必须先确认 `.worktrees/` 已被 git 忽略。

推荐的并行开发初始化方式：

```bash
git check-ignore -q .worktrees
git worktree add .worktrees/<task-name> -b feat/<task-name> HEAD
cd .worktrees/<task-name>
```

---

## 阶段 0：仓库放置方式

这个计划默认身份服务要么作为独立仓库开发，要么作为当前仓库中的顶层独立服务目录开发。如果先在当前仓库内孵化，根目录使用 `services/identity-service`，并避免触碰现有 gateway 代码。

推荐的仓库内原型目录：

```text
services/identity-service
```

## 任务 1：创建服务骨架

**文件：**

- Create: `services/identity-service/go.mod`
- Create: `services/identity-service/cmd/server/main.go`
- Create: `services/identity-service/internal/config/config.go`
- Create: `services/identity-service/internal/http/router.go`
- Create: `services/identity-service/internal/http/response.go`
- Create: `services/identity-service/.env.example`

**步骤 1：初始化模块**

运行：

```bash
cd services/identity-service
go mod init goauth/services/identity-service
go get github.com/gin-gonic/gin gorm.io/gorm gorm.io/driver/mysql gorm.io/driver/sqlite github.com/redis/go-redis/v9 github.com/golang-jwt/jwt/v5 golang.org/x/crypto
```

预期：生成 `go.mod` 和 `go.sum`。

**步骤 2：添加配置加载器**

在 `internal/config/config.go` 中实现强类型配置，覆盖 HTTP 地址、Issuer URL、MySQL DSN、Redis URL、Token TTL、SMTP、CORS 与 GitHub OAuth 配置项。

**步骤 3：添加健康检查路由**

实现：

```text
GET /healthz
```

预期响应：

```json
{"success":true,"data":{"status":"ok"}}
```

**步骤 4：验证**

运行：

```bash
go run ./cmd/server
curl -fsS http://127.0.0.1:8080/healthz
```

预期：健康检查返回 HTTP 200。

**步骤 5：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): scaffold standalone identity service"
```

## 任务 2：添加数据库与 Redis 基础设施

**文件：**

- Create: `services/identity-service/internal/store/db.go`
- Create: `services/identity-service/internal/store/models.go`
- Create: `services/identity-service/internal/cache/redis.go`
- Create: `services/identity-service/internal/cache/keys.go`
- Modify: `services/identity-service/cmd/server/main.go`

**步骤 1：定义 GORM 模型**

为下列实体创建模型：

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

唯一约束按设计文档中的要求，通过显式 GORM 索引表达。

**步骤 2：添加数据库初始化**

实现 `OpenDB(cfg)` 与 `AutoMigrate(db)`。

当设置了 `MYSQL_DSN` 时使用 MySQL；SQLite 仅用于本地测试。

**步骤 3：添加 Redis 初始化**

实现 `OpenRedis(cfg)` 以及类型化 key 辅助函数：

```text
EmailCodeKey(purpose, email string) string
UserCacheKey(userID int64) string
SessionKey(sessionID string) string
PermissionCacheKey(tenantID, userID int64) string
JtiDenylistKey(jti string) string
OIDCStateKey(state string) string
```

**步骤 4：验证**

运行：

```bash
go test ./internal/store ./internal/cache
```

预期：相关包可以编译，单元测试通过。

**步骤 5：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): add store and cache infrastructure"
```

## 任务 3：实现邮箱验证与密码认证

**文件：**

- Create: `services/identity-service/internal/auth/password.go`
- Create: `services/identity-service/internal/auth/email_code.go`
- Create: `services/identity-service/internal/auth/service.go`
- Create: `services/identity-service/internal/auth/handler.go`
- Create: `services/identity-service/internal/mailer/mailer.go`
- Modify: `services/identity-service/internal/http/router.go`

**步骤 1：先写测试**

为下列行为编写测试：

- 密码哈希可以验证原始密码。
- 错误密码校验失败。
- 邮箱验证码写入 Redis 且带 TTL。
- 注册必须依赖已验证的验证码。
- 重复邮箱注册失败。
- 被禁用用户登录失败。

运行：

```bash
go test ./internal/auth
```

预期：在实现前测试先失败。

**步骤 2：实现密码辅助逻辑**

首版先使用 bcrypt，因为它在参考项目中更熟悉。接口保持足够小，以便未来切换到 argon2id。

**步骤 3：实现认证端点**

路由：

```text
POST /v1/auth/email/send-code
POST /v1/auth/register
POST /v1/auth/login
POST /v1/auth/password/forgot
POST /v1/auth/password/reset
```

**步骤 4：验证**

运行：

```bash
go test ./internal/auth
```

预期：测试通过。

**步骤 5：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): add email and password authentication"
```

## 任务 4：实现 Access Token 与 Refresh Token

**文件：**

- Create: `services/identity-service/internal/session/token.go`
- Create: `services/identity-service/internal/session/refresh.go`
- Create: `services/identity-service/internal/session/handler.go`
- Create: `services/identity-service/internal/session/middleware.go`
- Modify: `services/identity-service/internal/http/router.go`
- Modify: `services/identity-service/internal/auth/service.go`

**步骤 1：先写测试**

为下列行为编写测试：

- Access Token 包含 `sub`、`sid`、`tid`、`aud`、`jti` 和 `ver`。
- Refresh Token 在存储层只保存哈希。
- 刷新动作会轮换 Token。
- 轮换后的旧 Refresh Token 被复用时，整个 token family 会被撤销。
- Logout 只撤销一个会话。
- Logout all 会增加用户 token version。

运行：

```bash
go test ./internal/session
```

预期：在实现前测试先失败。

**步骤 2：实现 JWT 签名**

使用 `github.com/golang-jwt/jwt/v5`。

需要支持：

- RSA 私钥加载。
- JWT Header 中的 Key ID。
- 在后续 OIDC 任务中导出 JWKS 公钥。

**步骤 3：实现 Refresh Token 生命周期**

实现：

```text
POST /v1/auth/refresh
POST /v1/auth/logout
POST /v1/auth/logout-all
GET  /v1/auth/me
```

**步骤 4：验证**

运行：

```bash
go test ./internal/session ./internal/auth
```

预期：测试通过。

**步骤 5：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): add access and refresh token lifecycle"
```

## 任务 5：实现租户级 RBAC

**文件：**

- Create: `services/identity-service/internal/rbac/service.go`
- Create: `services/identity-service/internal/rbac/handler.go`
- Create: `services/identity-service/internal/tenant/service.go`
- Create: `services/identity-service/internal/tenant/handler.go`
- Modify: `services/identity-service/internal/http/router.go`

**步骤 1：先写测试**

为下列行为编写测试：

- 某成员持有角色后，会继承该角色的权限。
- 移除角色后，相应访问权也消失。
- 同一用户在不同租户中可以拥有不同角色。
- 角色变更后，权限缓存会失效。
- 被禁用用户和被禁用成员都无法通过权限校验。

运行：

```bash
go test ./internal/rbac ./internal/tenant
```

预期：在实现前测试先失败。

**步骤 2：实现 RBAC 服务**

实现权限解析接口：

```text
Can(ctx, userID, tenantID int64, permission string) (bool, error)
ListPermissions(ctx, userID, tenantID int64) ([]string, error)
```

Redis 作为权限缓存，MySQL 作为事实来源。

**步骤 3：添加 RBAC API**

路由：

```text
POST /v1/authz/check
POST /v1/authz/check-batch
GET  /v1/tenants/:tenant_id/my-permissions
```

**步骤 4：添加租户与角色管理 API**

路由：

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

**步骤 5：验证**

运行：

```bash
go test ./internal/rbac ./internal/tenant
```

预期：测试通过。

**步骤 6：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): add tenant scoped rbac"
```

## 任务 6：实现 OIDC Provider

**文件：**

- Create: `services/identity-service/internal/oidc/discovery.go`
- Create: `services/identity-service/internal/oidc/jwks.go`
- Create: `services/identity-service/internal/oidc/authorize.go`
- Create: `services/identity-service/internal/oidc/token.go`
- Create: `services/identity-service/internal/oidc/userinfo.go`
- Create: `services/identity-service/internal/oidc/client.go`
- Modify: `services/identity-service/internal/http/router.go`

**步骤 1：先写测试**

为下列行为编写测试：

- Discovery 文档包含 issuer、authorization endpoint、token endpoint、userinfo endpoint 和 jwks URI。
- Authorization endpoint 会校验合法 client 与 redirect URI。
- Authorization Code 在存储层以哈希保存。
- Token endpoint 会校验 PKCE。
- Token endpoint 返回 ID Token、Access Token 与 Refresh Token。
- 合法 Access Token 调用 UserInfo 时会返回用户 claims。
- Revocation 可以撤销 Refresh Token。

运行：

```bash
go test ./internal/oidc
```

预期：在实现前测试先失败。

**步骤 2：实现 Discovery 与 JWKS**

路由：

```text
GET /.well-known/openid-configuration
GET /oauth2/jwks
```

**步骤 3：实现 OAuth Client**

增加仓储层与后台服务方法，用于：

- 创建客户端。
- 哈希存储 client secret。
- 校验 redirect URI。
- 校验 scope。

**步骤 4：实现 Authorization Code + PKCE**

路由：

```text
GET  /oauth2/authorize
POST /oauth2/token
```

不要实现 Implicit Flow。

**步骤 5：实现 UserInfo、Introspection、Revocation、Logout**

路由：

```text
GET  /oauth2/userinfo
POST /oauth2/introspect
POST /oauth2/revoke
GET  /oauth2/logout
```

**步骤 6：验证**

运行：

```bash
go test ./internal/oidc ./internal/session ./internal/auth
```

预期：测试通过。

**步骤 7：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): add oidc provider endpoints"
```

## 任务 7：实现外部 Provider 抽象与 GitHub 适配器

**文件：**

- Create: `services/identity-service/internal/idp/provider.go`
- Create: `services/identity-service/internal/idp/service.go`
- Create: `services/identity-service/internal/idp/handler.go`
- Create: `services/identity-service/internal/idp/github/github.go`
- Modify: `services/identity-service/internal/http/router.go`

**步骤 1：先写测试**

为下列行为编写测试：

- GitHub 适配器可以生成正确的授权 URL。
- GitHub 适配器使用已配置的 redirect URI 交换 code。
- GitHub 适配器可以获取 `/user` 和 `/user/emails`。
- 隐藏邮箱时，可以从主已验证邮箱中解析出来。
- 已存在的外部身份可以直接登录到对应本地用户。
- 如果邮箱已存在但身份未绑定，必须先本地登录才能绑定。
- 已登录用户可以绑定 GitHub 身份。

运行：

```bash
go test ./internal/idp ./internal/idp/github
```

预期：在实现前测试先失败。

**步骤 2：实现 Provider 接口**

使用：

```text
type Provider interface {
    Slug() string
    DisplayName() string
    AuthCodeURL(state string, opts AuthCodeOptions) (string, error)
    ExchangeCode(ctx context.Context, code string, redirectURI string) (*TokenSet, error)
    FetchProfile(ctx context.Context, token *TokenSet) (*ExternalProfile, error)
}
```

**步骤 3：实现 GitHub Provider**

使用：

```text
Authorization URL: https://github.com/login/oauth/authorize
Token URL:         https://github.com/login/oauth/access_token
User API:          https://api.github.com/user
Emails API:        https://api.github.com/user/emails
Scopes:            read:user user:email
```

**步骤 4：添加路由**

```text
GET    /v1/external/github/start
GET    /v1/external/github/callback
POST   /v1/external/github/bind
DELETE /v1/external/github/bind
GET    /v1/me/identities
```

**步骤 5：验证**

运行：

```bash
go test ./internal/idp ./internal/idp/github ./internal/auth
```

预期：测试通过。

**步骤 6：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): add github external identity provider"
```

## 任务 8：添加后台用户管理与审计日志

**文件：**

- Create: `services/identity-service/internal/user/service.go`
- Create: `services/identity-service/internal/user/handler.go`
- Create: `services/identity-service/internal/audit/service.go`
- Modify: `services/identity-service/internal/http/router.go`

**步骤 1：先写测试**

为下列行为编写测试：

- 管理员可以列出用户。
- 管理员可以禁用与启用用户。
- 管理员可以重置用户密码。
- Root 或系统管理员不能在未显式校验权限的情况下被误禁用。
- 角色变更会写入审计日志。
- 登录与退出会写入审计日志。

运行：

```bash
go test ./internal/user ./internal/audit
```

预期：在实现前测试先失败。

**步骤 2：实现后台 API**

路由：

```text
GET   /v1/admin/users
POST  /v1/admin/users
PATCH /v1/admin/users/:id
POST  /v1/admin/users/:id/disable
POST  /v1/admin/users/:id/enable
POST  /v1/admin/users/:id/reset-password
```

**步骤 3：实现审计写入**

为以下事件写入审计日志：

- login
- logout
- password reset
- token refresh reuse detection
- tenant membership changes
- role assignment changes
- OAuth client changes
- external identity binding changes

**步骤 4：验证**

运行：

```bash
go test ./internal/user ./internal/audit ./...
```

预期：测试通过。

**步骤 5：提交**

```bash
git add services/identity-service
git commit -m "feat(identity): add admin user management and audit logs"
```

## 任务 9：添加 Docker Compose 与运维文档

**文件：**

- Create: `services/identity-service/Dockerfile`
- Create: `services/identity-service/docker-compose.yml`
- Create: `services/identity-service/README.md`
- Create: `services/identity-service/docs/client-integration.md`
- Create: `services/identity-service/docs/oidc-integration.md`

**步骤 1：添加 Dockerfile**

通过多阶段 Go 构建生成体积较小的生产镜像。

**步骤 2：添加 Docker Compose**

服务：

```text
identity-service
mysql
redis
```

**步骤 3：添加集成文档**

需要说明：

- 环境变量。
- 如何创建第一个管理员。
- 如何注册一个 OAuth Client。
- 业务系统如何跳转到 `/oauth2/authorize`。
- 业务 API 如何通过 JWKS 校验 JWT。
- 业务 API 如何调用 `/v1/authz/check`。

**步骤 4：验证**

运行：

```bash
docker compose up -d --build
curl -fsS http://127.0.0.1:8080/healthz
docker compose logs identity-service
```

预期：服务成功启动，健康检查通过。

**步骤 5：提交**

```bash
git add services/identity-service
git commit -m "docs(identity): add deployment and integration guide"
```

## 最终验证

运行：

```bash
go test ./...
docker compose up -d --build
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/.well-known/openid-configuration
```

预期：

- 所有 Go 测试通过。
- 健康检查返回 HTTP 200。
- OIDC discovery 文档返回 HTTP 200，并包含已配置的 issuer。

## 执行方式

计划已保存到 `docs/plans/2026-05-08-identity-service-implementation-plan.md`。

有两种执行方式：

1. Subagent-Driven（当前会话）- 每个任务派发一个新的子代理，中间穿插 review，迭代快。
2. Parallel Session（独立会话）- 新开一个使用 `executing-plans` 的会话，按检查点推进整个计划。
