# Identity Service

Goauth 的 SSO/身份服务，提供本地账号会话、OIDC 授权码流程、JWKS、用户信息、租户 RBAC 和权限校验能力。

## 本地运行

```powershell
cd services/identity-service
Copy-Item .env.example .env
go test ./...
go run ./cmd/server
```

默认监听 `:8080`。`/healthz` 只表示进程存活，`/readyz` 会检查 DB/Redis 依赖是否可用：

```powershell
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
```

如果 `MYSQL_DSN` 留空，服务会使用进程内 SQLite 内存库，适合快速跑单测或验证路由；`REDIS_URL` 为空时默认连接 `redis://127.0.0.1:6379/0`。Redis 是运行时必需依赖，如果不可用，服务会直接启动失败，而不是以裁掉浏览器登录链路的半可用状态继续提供流量。

后端服务不托管登录/注册 UI。SSO 浏览器登录入口由 `BROWSER_LOGIN_URL` 指向独立前端页面，默认是同源 Nginx 部署下的 `/login`。

## Docker Compose

Compose 会启动 `identity-service`、`mysql`、`redis`，并等待 MySQL/Redis 健康后再启动服务。

```powershell
cd services/identity-service
docker compose up --build
```

常用检查：

```powershell
docker compose ps
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

Compose 固定容器内监听 `:8080`，只通过 `IDENTITY_HTTP_PORT` 改宿主机端口，例如 `IDENTITY_HTTP_PORT=18080 docker compose up --build`。`PUBLIC_ISSUER_URL` 默认随宿主机端口变为 `http://localhost:${IDENTITY_HTTP_PORT}`；只有在代理、域名或 HTTPS 场景下才需要显式设置。

清理本地容器和数据卷：

```powershell
docker compose down -v
```

## 常见配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `APP_ENV` | `development` | 运行环境标识。 |
| `HTTP_ADDR` | `:8080` | HTTP 监听地址。Compose 固定容器内为 `:8080`，不要用它调整宿主机端口。 |
| `PUBLIC_ISSUER_URL` | `http://127.0.0.1:8080` | OIDC issuer，必须是业务系统可访问的外部地址；Compose 默认 `http://localhost:${IDENTITY_HTTP_PORT:-8080}`。 |
| `BROWSER_LOGIN_URL` | `/login` | 浏览器访问 `/oauth2/authorize` 缺少 SSO 会话时跳转的独立前端登录页。可配置为同源路径或完整 URL。 |
| `BROWSER_COOKIE_SECURE` | 跟随 `PUBLIC_ISSUER_URL` 协议 | 浏览器 SSO cookie 和 GitHub OAuth state cookie 是否带 `Secure`。`PUBLIC_ISSUER_URL` 为 `http://...` 时默认 `false`，方便本地 HTTP/Compose 联调；生产 HTTPS 场景建议保持 `true`。 |
| `MYSQL_DSN` | 空 | MySQL DSN。为空时使用内存 SQLite。 |
| `REDIS_URL` | 空 | Redis URL，例如 `redis://redis:6379/0`。 |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM` | 空 / `587` / 空 / 空 / 空 | 注册、找回密码验证码邮件发送配置；`SMTP_HOST` 与 `SMTP_FROM` 为空时使用 Noop sender。 |
| `SMTP_SSL` | `false` | 是否使用 SMTPS 直连，常见于 465 端口。 |
| `SMTP_AUTH_LOGIN` | `false` | 是否使用 `AUTH LOGIN`；默认使用 `AUTH PLAIN`。 |
| `JWT_PRIVATE_KEY_PATH` | 空 | RSA 私钥路径。为空时本地开发会生成临时 key，重启后 JWKS 会变化。 |
| `JWT_KEY_ID` | 空 | JWKS/Token header 的 `kid`。本地 Compose 默认 `local-dev`。 |
| `ACCESS_TOKEN_TTL` | `15m` | access token 有效期。 |
| `BROWSER_SESSION_TTL` | `12h` | 浏览器 SSO 会话时长，对应 `goauth_oidc_session` 授权 cookie；只影响浏览器侧 OIDC 连续登录体验，不改变 access/refresh token 语义。 |
| `REFRESH_TOKEN_TTL` | `720h` | refresh token 有效期。 |
| `TRUSTED_PROXIES` | 空 | 逗号分隔的受信任反向代理/CIDR，例如 `10.0.0.0/8,192.168.1.10`。默认空表示不信任任何代理，忽略 `X-Forwarded-For`，避免客户端伪造来源 IP；只有在服务确实部署在受控代理后面时才配置。 |
| `CORS_ALLOWED_ORIGINS` | 空 | 逗号分隔的允许来源。 |
| `GITHUB_OAUTH_ENABLED` | `false` | 是否启用 GitHub 外部登录。启用时还需配置 client id/secret/redirect URI。 |
| `DEFAULT_MEMBER_TENANT_SLUGS` | 空 | 逗号分隔的租户 slug。配置后，GoAuth 创建新用户时会自动把用户加入这些活跃租户；为空表示不做默认入组。 |
| `BOOTSTRAP_ADMIN_EMAIL` | 空 | 可选。与 `BOOTSTRAP_ADMIN_PASSWORD` 一起设置后，服务启动时会确保该账号存在并授予系统角色。 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 空 | 可选。bootstrap 管理员密码；建议首次登录后立即通过管理流程轮换并移除该环境变量。 |
| `BOOTSTRAP_ADMIN_ROLE` | `root` | bootstrap 账号授予的系统角色代码，默认 `root`。 |

`.env.example` 列出了服务读取的全部环境变量。Compose 使用 `${VAR:-default}`，复制 `.env.example` 后即使变量值为空，也会使用 Compose 内置默认值；因此示例里的 `PUBLIC_ISSUER_URL` 保持为空，避免覆盖随 `IDENTITY_HTTP_PORT` 变化的 issuer 默认值。

代理部署升级提示：如果服务跑在 Nginx、Ingress、LB 等反向代理后面，并且你依赖真实客户端 IP 做登录/验证码限流，升级到当前版本后需要显式配置 `TRUSTED_PROXIES`；否则服务会安全地退回到“只信任 TCP 对端地址”，多个用户可能共享代理出口的限流桶。

默认入组策略只读取 GoAuth 租户数据，不包含任何下游业务代码。需要让新注册用户默认可访问某些公共业务系统时，先创建对应租户，再把租户 slug 写入 `DEFAULT_MEMBER_TENANT_SLUGS`，例如 `DEFAULT_MEMBER_TENANT_SLUGS=public-app,community`。如果配置了不存在或禁用的租户 slug，注册/外部 IdP 创建用户会失败，以便暴露部署配置错误。

## 创建第一个管理员

最简单的本地或首部署方式是在 `.env` 中设置：

```text
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123!
BOOTSTRAP_ADMIN_DISPLAY_NAME=Initial Admin
BOOTSTRAP_ADMIN_ROLE=root
```

服务启动后会幂等地确保该用户存在、处于激活状态，并属于 `system` 租户下对应的系统角色。建议在首次登录、创建正式管理员并完成 OAuth Client/租户初始化后，删除这些 bootstrap 环境变量并重启服务。

不要把 `JWT_PRIVATE_KEY_PATH` 指向服务目录内的私钥文件；私钥应通过运行时 volume/secret 注入。

## 集成文档

- [业务系统接入指南](docs/client-integration.md)
- [OIDC 集成细节](docs/oidc-integration.md)
