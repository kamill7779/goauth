# Quickstart

从 clone 到本地完整跑起来，5 分钟。

## 前置条件

- Docker Desktop 或 Docker Engine + Compose
- Go 1.24+ (仅跑测试或本地 go run)
- Node.js 20+ (前端登录页和 Admin Console)

## 1. 启动后端

```powershell
cd services/identity-service
Copy-Item .env.example .env
docker compose up --build
```

启动 3 个容器: identity-service (:8080) + MySQL (3306) + Redis (6379)。

```powershell
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

## 2. 启动前端

```powershell
cd frontend
npm install
npm run dev
```

- 登录页: `http://127.0.0.1:3000/login`
- Admin Console: `http://127.0.0.1:3000/admin`

## 3. 本地默认行为

| 设置 | 默认值 | 说明 |
|------|--------|------|
| `REGISTRATION_MODE` | `open` | 允许自助注册 |
| `MAILER_PROVIDER` | `console` | 验证码写入临时 mailbox 文件 |
| `CAPTCHA_PROVIDER` | (空) | 不启用验证码 |
| `JWT_PRIVATE_KEY_PATH` | (空) | 自动生成临时 key |

**查看验证码**: `docker compose logs -f identity-service` 找 `mailbox_path`。

## 4. 创建第一个管理员

`.env` 中设置:

```env
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123!
BOOTSTRAP_ADMIN_NICKNAME=Initial Admin
```

启动后幂等创建 root 管理员。

## 5. 创建第一个 OAuth Client

1. 用管理员登录 Admin Console
2. 进入 "OAuth Clients" → "Create Client"
3. 重定向 URI 填 `http://localhost:4000/callback`
4. 用 client_id 和 redirect_uri 测试 OIDC 流程

## 生产部署

生产前必须:
- `APP_ENV=production`
- `REGISTRATION_MODE=invite_only` 或 `disabled`
- 持久 MySQL/Redis
- 固定 JWT 私钥
- 删除 `BOOTSTRAP_ADMIN_PASSWORD` 环境变量

详见 `docs/deployment/production-checklist.md`。
