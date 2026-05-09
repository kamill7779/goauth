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

如果 `MYSQL_DSN` 留空，服务会使用进程内 SQLite 内存库，适合快速跑单测或验证路由；如果 `REDIS_URL` 留空或不可用，登录/注册等依赖 Redis 的 auth routes 会被禁用，但基础会话/OIDC/RBAC 路由仍会注册。生产或联调建议显式配置 MySQL 和 Redis。

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
| `MYSQL_DSN` | 空 | MySQL DSN。为空时使用内存 SQLite。 |
| `REDIS_URL` | 空 | Redis URL，例如 `redis://redis:6379/0`。 |
| `JWT_PRIVATE_KEY_PATH` | 空 | RSA 私钥路径。为空时本地开发会生成临时 key，重启后 JWKS 会变化。 |
| `JWT_KEY_ID` | 空 | JWKS/Token header 的 `kid`。本地 Compose 默认 `local-dev`。 |
| `ACCESS_TOKEN_TTL` | `15m` | access token 有效期。 |
| `BROWSER_SESSION_TTL` | `12h` | 浏览器 SSO 会话时长，对应 `goauth_oidc_session` 授权 cookie；只影响浏览器侧 OIDC 连续登录体验，不改变 access/refresh token 语义。 |
| `REFRESH_TOKEN_TTL` | `720h` | refresh token 有效期。 |
| `TRUSTED_PROXIES` | 空 | 逗号分隔的受信任反向代理/CIDR，例如 `10.0.0.0/8,192.168.1.10`。默认空表示不信任任何代理，忽略 `X-Forwarded-For`，避免客户端伪造来源 IP；只有在服务确实部署在受控代理后面时才配置。 |
| `CORS_ALLOWED_ORIGINS` | 空 | 逗号分隔的允许来源。 |
| `GITHUB_OAUTH_ENABLED` | `false` | 是否启用 GitHub 外部登录。启用时还需配置 client id/secret/redirect URI。 |
| `BOOTSTRAP_ADMIN_EMAIL` | 空 | 可选。与 `BOOTSTRAP_ADMIN_PASSWORD` 一起设置后，服务启动时会确保该账号存在并授予系统角色。 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 空 | 可选。bootstrap 管理员密码；建议首次登录后立即通过管理流程轮换并移除该环境变量。 |
| `BOOTSTRAP_ADMIN_ROLE` | `root` | bootstrap 账号授予的系统角色代码，默认 `root`。 |

`.env.example` 列出了服务读取的全部环境变量。Compose 使用 `${VAR:-default}`，复制 `.env.example` 后即使变量值为空，也会使用 Compose 内置默认值；因此示例里的 `PUBLIC_ISSUER_URL` 保持为空，避免覆盖随 `IDENTITY_HTTP_PORT` 变化的 issuer 默认值。

代理部署升级提示：如果服务跑在 Nginx、Ingress、LB 等反向代理后面，并且你依赖真实客户端 IP 做登录/验证码限流，升级到当前版本后需要显式配置 `TRUSTED_PROXIES`；否则服务会安全地退回到“只信任 TCP 对端地址”，多个用户可能共享代理出口的限流桶。

## 创建第一个管理员

最简单的本地或首部署方式是在 `.env` 中设置：

```text
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123!
BOOTSTRAP_ADMIN_DISPLAY_NAME=Initial Admin
BOOTSTRAP_ADMIN_ROLE=root
```

服务启动后会幂等地确保该用户存在、处于激活状态，并属于 `system` 租户下对应的系统角色。建议在首次登录、创建正式管理员并完成 OAuth Client/租户初始化后，删除这些 bootstrap 环境变量并重启服务。

不要把 `JWT_PRIVATE_KEY_PATH` 指向服务目录内的私钥文件；私钥应通过运行时 volume/secret 注入。`.dockerignore` 会排除常见 key/secrets 文件，避免它们进入 Docker build context。

## 集成文档

- [业务系统接入指南](docs/client-integration.md)
- [OIDC 集成细节](docs/oidc-integration.md)
