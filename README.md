# GoAuth

[![CI](https://github.com/kamill7779/goauth/actions/workflows/ci.yml/badge.svg)](https://github.com/kamill7779/goauth/actions/workflows/ci.yml)

GoAuth 是一个轻量级、可独立部署、可配置的 SSO/身份服务。它面向新项目脚手架和中小团队统一登录场景，提供邮箱账号、浏览器登录、OAuth2 / OpenID Connect Provider、租户 RBAC、Admin Console、外部登录适配和审计能力。

## 核心能力

- 邮箱注册、登录、密码重置、两步验证和账户中心。
- Access Token、Refresh Token、浏览器 SSO Cookie、退出登录和会话撤销。
- OIDC Authorization Code + PKCE、Discovery、JWKS、UserInfo、Introspection、Revoke、Logout。
- 多租户 RBAC、权限校验、用户/租户/角色/Admin Console 管理。
- GitHub 外部登录、运行时公开配置、品牌配置、CAPTCHA、SMTP 邮件。
- MySQL 作为权威数据库，Redis 用于验证码、限流、会话和缓存。

## 5 分钟启动后端

```powershell
cd services/identity-service
docker compose up --build
```

检查服务：

```powershell
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
curl http://127.0.0.1:8080/v1/auth/public-config
```

当前 Compose 启动的是后端、MySQL 和 Redis。登录页和 Admin Console 已在 `frontend/` 中实现，本地完整 UI 体验需要另开一个终端启动前端：

```powershell
cd frontend
npm install
npm run dev
```

然后访问：

- 登录页：`http://127.0.0.1:3000/login`
- Admin Console：`http://127.0.0.1:3000/admin`
- OIDC Issuer：`http://localhost:8080`

## 文档入口

- [快速上手](docs/quickstart.md)：从 clone 到本地登录、Admin、创建第一个 OAuth Client。
- [业务系统 SSO 接入](docs/integration/sso-quickstart.md)：让业务项目用 GoAuth 登录。
- [Docker Compose 部署](docs/deployment/docker-compose.md)：本地 Compose、生产 Compose、前端托管和反代路径。
- [SMTP 邮件配置](docs/config/smtp.md)：126 邮箱、Outlook/Microsoft 365、常见 SMTP 排障。
- [配置矩阵](docs/configuration.md)：全部环境变量、默认值、secret 分类和公开配置可见性。
- [生产发布检查](docs/production-checklist.md)：上线前必须确认的安全和运维项。
- [故障排查](docs/troubleshooting.md)：登录、OIDC、Cookie、SMTP、CORS、JWKS 常见问题。

## 本地默认行为

- `REGISTRATION_MODE=open`：允许本地自助注册。
- `MAILER_PROVIDER=console`：验证码邮件正文写入本机临时 mailbox 文件，日志只记录文件路径。
- `GET /v1/auth/public-config`：返回前端可安全使用的认证入口、品牌、CAPTCHA、SMTP provider 等公开配置。
- GitHub 登录和 CAPTCHA 默认关闭，通过环境变量启用。

查看本地验证码：

```powershell
cd services/identity-service
docker compose logs -f identity-service
```

日志中查找 `mailbox_path`，打开对应文件查看验证码正文。

## 生产提醒

生产发布前不要沿用本地注册默认值。设置 `APP_ENV=production` 后，建议将 `REGISTRATION_MODE` 改为 `invite_only` 或 `disabled`，再通过 `/v1/auth/public-config` 和 Admin Console 设置页确认运行状态。

生产环境必须使用持久 MySQL、Redis、JWT 签名密钥、HTTPS issuer、SMTP 实发配置，并删除 bootstrap admin secret。详见 [生产发布检查](docs/production-checklist.md)。

## 设计与实现

- [设计文档](docs/design.md)
- [实现计划](docs/implementation-plan.md)
- [Identity Service README](services/identity-service/README.md)
