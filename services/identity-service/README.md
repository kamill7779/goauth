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
| `REFRESH_TOKEN_TTL` | `720h` | refresh token 有效期。 |
| `CORS_ALLOWED_ORIGINS` | 空 | 逗号分隔的允许来源。 |
| `GITHUB_OAUTH_ENABLED` | `false` | 是否启用 GitHub 外部登录。启用时还需配置 client id/secret/redirect URI。 |

`.env.example` 列出了服务读取的全部环境变量。Compose 使用 `${VAR:-default}`，复制 `.env.example` 后即使变量值为空，也会使用 Compose 内置默认值；因此示例里的 `PUBLIC_ISSUER_URL` 保持为空，避免覆盖随 `IDENTITY_HTTP_PORT` 变化的 issuer 默认值。

## 集成文档

- [业务系统接入指南](docs/client-integration.md)
- [OIDC 集成细节](docs/oidc-integration.md)
