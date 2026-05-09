# GoAuth 设计文档

日期：2026-05-08

## 目标

构建 GoAuth，一个可独立部署的身份认证服务，作为后续系统的通用脚手架能力。首版需要开箱即用地提供：以邮箱为主的注册与登录、令牌生命周期管理、租户级 RBAC、用户管理，以及 OAuth2 / OpenID Connect 提供方能力。

这个服务不是嵌入当前网关的库，而是一个独立的服务，供其他业务系统通过 HTTP / OIDC 接入。

## 非目标

- 不把 quota、billing、model groups、channel keys、subscriptions、invitation rewards 等业务概念迁入身份服务。
- 首版不实现完整的 ABAC 策略引擎。
- 不把 DAC 作为首要权限模型。
- 不要求其他系统与身份服务共享数据库。
- 不把第三方 OAuth 登录做成产品主形态。外部 OAuth 提供方只是上游身份来源的可选接入方式。

## 产品形态

服务中有两类 OAuth 相关能力，代码和文档里必须严格区分：

1. OIDC Provider
   - 身份服务本身是授权服务器和身份提供方。
   - 业务系统以 OAuth Client 的身份注册到该服务。
   - 业务系统把用户重定向到该服务完成登录。
   - 该服务返回授权码、ID Token、Access Token、Refresh Token、JWKS 以及 UserInfo。

2. External Identity Provider Adapters
   - 服务也支持用户通过外部身份提供方登录。
   - 首个外部提供方是 GitHub。
   - 外部登录只负责建立或绑定本地用户身份。之后仍然由本服务向下游业务系统签发自己的令牌和 RBAC 上下文。

## 推荐权限模型

首版使用租户级 RBAC。

```text
User -> TenantMember -> Role -> Permission
```

含义如下：

- 一个用户可以属于多个租户。
- 用户进入某个租户后，表现为该租户中的一个 TenantMember。
- 一个成员可以拥有一个或多个角色。
- 一个角色包含一组权限。
- 权限使用 `resource:action` 这样的命名方式，例如 `user:read`、`member:invite`、`project:create`。

RBAC 是合适的首版默认值，因为它简单、可配置、易于推理，也容易通过管理 API 暴露。若未来出现真实产品需求，再通过独立的策略扩展层引入 ABAC。

## 架构

```text
cmd/server
  main.go

internal/config
  环境变量与强类型配置加载。

internal/http
  Gin 路由、中间件、请求绑定、统一响应辅助。

internal/auth
  邮箱注册、密码登录、密码重置、访问令牌签发。

internal/session
  Refresh Token 轮换、设备会话、退出登录、令牌撤销。

internal/oidc
  OAuth2 授权服务器与 OpenID Connect 提供方端点。

internal/idp
  外部身份提供方抽象。

internal/idp/github
  GitHub OAuth2 适配器。

internal/rbac
  租户级角色与权限校验。

internal/user
  用户资料与后台用户管理。

internal/tenant
  租户与租户成员管理。

internal/store
  GORM 模型与仓储层。

internal/cache
  Redis 客户端与类型化缓存 key。

internal/mailer
  SMTP 邮件发送。

internal/audit
  审计事件记录。

pkg/client
  提供给业务服务的可选 Go Client。
```

分层关系：

```text
router -> handler -> service -> repository -> database/cache
```

约束：

- Handler 只负责解析请求、调用 service、返回响应。
- 业务规则放在 service。
- Repository 封装 GORM 细节。
- Redis 的 key 命名和 TTL 统一收敛在 `internal/cache`。

## 存储设计

主数据库目标是 MySQL。仍然使用 GORM，以便在本地测试中继续支持 SQLite，并为未来兼容 PostgreSQL 保留余地。

推荐数据表：

```text
users
  id
  email
  email_verified_at
  password_hash
  display_name
  avatar_url
  status
  token_version
  created_at
  updated_at
  deleted_at

user_identities
  id
  user_id
  provider
  provider_user_id
  email
  email_verified
  username
  display_name
  avatar_url
  created_at
  updated_at

tenants
  id
  name
  slug
  status
  created_at
  updated_at
  deleted_at

tenant_members
  id
  tenant_id
  user_id
  status
  created_at
  updated_at
  deleted_at

roles
  id
  tenant_id
  name
  code
  description
  is_system
  created_at
  updated_at

permissions
  id
  resource
  action
  code
  description
  created_at
  updated_at

role_permissions
  role_id
  permission_id

member_roles
  member_id
  role_id

oauth_clients
  id
  tenant_id
  client_id
  client_secret_hash
  name
  redirect_uris
  allowed_scopes
  grant_types
  token_endpoint_auth_method
  status
  created_at
  updated_at

oauth_authorization_codes
  id
  code_hash
  client_id
  user_id
  tenant_id
  redirect_uri
  scope
  code_challenge
  code_challenge_method
  nonce
  expires_at
  consumed_at
  created_at

refresh_tokens
  id
  token_hash
  family_id
  session_id
  user_id
  tenant_id
  client_id
  user_agent
  ip_address
  expires_at
  revoked_at
  replaced_by_token_id
  created_at

external_provider_configs
  id
  provider
  name
  client_id
  client_secret_ciphertext
  scopes
  enabled
  created_at
  updated_at

audit_logs
  id
  actor_user_id
  tenant_id
  action
  target_type
  target_id
  ip_address
  user_agent
  metadata
  created_at
```

关键约束：

- `users.email` 对活跃用户唯一。
- `user_identities` 上 `(provider, provider_user_id)` 唯一。
- `user_identities` 上 `(user_id, provider)` 唯一，保证一个本地用户在每个 provider 下最多绑定一个身份。
- `tenants.slug` 唯一。
- `roles` 上 `(tenant_id, code)` 唯一。
- `permissions.code` 唯一。
- `oauth_clients.client_id` 唯一。
- Refresh Token 只保存哈希。
- Authorization Code 只保存哈希。

## Redis

Redis 用于热点路径和临时状态，MySQL 仍然是最终事实来源。

```text
auth:email_code:{purpose}:{email}
auth:rate:{scope}:{key}
auth:user:{user_id}
auth:session:{session_id}
auth:permissions:{tenant_id}:{user_id}
auth:jti_denylist:{jti}
auth:oidc_state:{state}
auth:pkce:{state}
```

推荐 TTL：

- 邮箱验证码：10 分钟
- 密码重置码：10 分钟
- OIDC state：10 分钟
- 授权码：5 分钟
- Access Token denylist 条目：直到令牌过期
- 权限缓存：1 到 5 分钟
- 用户缓存：1 到 5 分钟

## 令牌设计

Access Token 使用 JWT，Refresh Token 使用不透明随机字符串。

默认生命周期：

- Access Token：15 分钟
- Refresh Token：30 天
- Authorization Code：5 分钟

Access Token Claims：

```json
{
  "iss": "https://auth.example.com",
  "sub": "user_id",
  "aud": "client_id",
  "tid": "tenant_id",
  "sid": "session_id",
  "email": "user@example.com",
  "email_verified": true,
  "roles": ["admin"],
  "permissions": ["user:read", "member:invite"],
  "ver": 3,
  "iat": 1710000000,
  "exp": 1710000900,
  "jti": "random_id"
}
```

ID Token 的 claims 要符合 OIDC 预期；请求中带有 `nonce` 时需要回填，同时在可用时包含 `iss`、`sub`、`aud`、`exp`、`iat`、`email`、`email_verified`、`name`、`picture`。

Refresh Token 规则：

- 只保存 Token 哈希。
- 每次刷新都轮换 Refresh Token。
- 记录 token family ID，用于复用检测。
- 如果旧 Refresh Token 在轮换后被再次使用，撤销整个 token family。
- 支持单会话退出和全会话退出。
- 通过增加 `users.token_version` 使某个用户现有的所有 Access Token 失效。

## OIDC Provider 端点

```text
GET  /.well-known/openid-configuration
GET  /oauth2/authorize
POST /oauth2/token
GET  /oauth2/userinfo
GET  /oauth2/jwks
POST /oauth2/introspect
POST /oauth2/revoke
GET  /oauth2/logout
```

首版必须支持的流程：

- Authorization Code + PKCE
- Refresh Token

首版可选流程：

- 若存在明确场景，可为服务间客户端增加 Client Credentials。

不要支持 Implicit Flow。

## 认证与用户 API

```text
POST /v1/auth/email/send-code
POST /v1/auth/register
POST /v1/auth/login
POST /v1/auth/refresh
POST /v1/auth/logout
POST /v1/auth/logout-all
POST /v1/auth/password/forgot
POST /v1/auth/password/reset
GET  /v1/auth/me
```

## 外部身份提供方 API

```text
GET    /v1/external/github/start
GET    /v1/external/github/callback
POST   /v1/external/github/bind
DELETE /v1/external/github/bind
GET    /v1/me/identities
```

外部提供方行为约束：

- 如果 GitHub 身份已经存在，则直接登录到已绑定的本地用户。
- 如果 GitHub 身份不存在，但其已验证邮箱已属于某个本地用户，则要求先完成本地登录再执行绑定。
- 如果身份和邮箱都不存在，则新建本地用户并绑定该身份。
- 如果请求来自已登录用户，则将 GitHub 身份绑定到当前用户，但前提是它没有绑定到其他用户。

## RBAC 与租户 API

```text
POST /v1/authz/check
POST /v1/authz/check-batch
GET  /v1/tenants/:tenant_id/my-permissions

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

`/v1/authz/check` 的输入示例：

```json
{
  "user_id": 1,
  "tenant_id": 10,
  "permission": "project:create"
}
```

返回示例：

```json
{
  "allowed": true
}
```

## CORS

使用 allowlist，不要把通配符 origin 和 credentials 混用。

配置项：

```text
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
CORS_ALLOWED_METHODS=GET,POST,PUT,PATCH,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Tenant-ID
CORS_ALLOW_CREDENTIALS=true
```

## 配置

本地开发和 Docker Compose 部署都使用 `.env`。

必需配置：

```text
APP_ENV
HTTP_ADDR
PUBLIC_ISSUER_URL
MYSQL_DSN
REDIS_URL
JWT_PRIVATE_KEY_PATH
JWT_KEY_ID
ACCESS_TOKEN_TTL
REFRESH_TOKEN_TTL
SMTP_HOST
SMTP_PORT
SMTP_USERNAME
SMTP_PASSWORD
SMTP_FROM
CORS_ALLOWED_ORIGINS
```

GitHub 外部提供方配置：

```text
GITHUB_OAUTH_ENABLED
GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET
GITHUB_REDIRECT_URI
```

## 安全要求

- 密码使用 bcrypt 或 argon2id 哈希。
- Client Secret 以哈希形式存储。
- Refresh Token 和 Authorization Code 只以哈希形式存储。
- Access Token 签名密钥需要支持通过 JWKS 轮换。
- 登录、邮箱验证码、密码重置、令牌刷新、授权端点都必须限流。
- 必须启用 OIDC state 和 PKCE。
- 如果浏览器会话使用 cookie，则浏览器会话端点必须具备 CSRF 保护。
- 登录、退出、密码变更、角色变更、租户成员变更、客户端变更、令牌撤销都要写入审计日志。

## 部署

首版交付包含 Docker Compose：

```text
auth-service
mysql
redis
```

服务应支持通过下面命令启动：

```bash
docker compose up -d
```

本地开发应支持：

```bash
go run ./cmd/server
```

## 测试策略

单元测试：

- 密码哈希与校验。
- JWT 创建与校验。
- Refresh Token 哈希、轮换与复用检测。
- RBAC 权限解析。
- GitHub 用户资料标准化。

集成测试：

- 带邮箱验证的注册流程。
- 登录与刷新流程。
- 登出与令牌撤销。
- Authorization Code + PKCE 流程。
- 使用 Access Token 获取 UserInfo。
- 租户角色分配与权限校验。

兼容性测试：

- MySQL 作为主集成数据库。
- SQLite 作为本地快速测试数据库。
- 基于 Redis 的验证码与限流能力。

## 实现顺序

1. 项目骨架与配置。
2. Store 模型与迁移。
3. Redis 缓存封装。
4. 邮箱注册与密码登录。
5. Access Token 与 Refresh Token 生命周期。
6. 租户级 RBAC。
7. OIDC Provider 端点。
8. 外部提供方抽象与 GitHub 适配器。
9. 管理后台 API。
10. Docker Compose 与示例客户端文档。
