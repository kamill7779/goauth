# GoAuth

GoAuth 是一个可独立部署的身份认证服务，面向后续新系统的脚手架场景。

当前规划中的能力包括：

- 以邮箱为主的注册与登录。
- Access Token 与 Refresh Token 的完整生命周期管理。
- 面向下游系统的 OAuth2 / OpenID Connect 提供方端点。
- 外部 OAuth2 身份提供方适配器，首个接入 GitHub。
- 基于 Redis 的验证码、限流、权限缓存与会话缓存。
- 以 MySQL 作为主权威数据库。

## 文档

- [设计文档](docs/design.md)
- [配置矩阵](docs/configuration.md)
- [实现计划](docs/implementation-plan.md)

## 快速启动

```powershell
cd services/identity-service
docker compose up --build
```

默认认证入口适合开源本地体验：

- `REGISTRATION_MODE=open`，允许邮箱验证码注册。
- `MAILER_PROVIDER=console`，验证码邮件正文会写入本机临时 mailbox 文件，服务日志只记录文件路径。
- `GET /v1/auth/public-config` 暴露前端所需的非敏感运行配置，包括认证能力和公开品牌展示。
- GitHub 登录和 CAPTCHA 默认关闭，可通过环境变量按需启用。

登录页、Admin Console、浏览器标题和 favicon 可通过 `BRAND_NAME`、`BRAND_TAGLINE`、`BRAND_ICON_TEXT`、`BRAND_ICON_URL` 配置；默认是 `GoAuth` / 空 tagline / `G`。

生产发布前不要沿用本地注册默认值。设置 `APP_ENV=production` 后，建议将 `REGISTRATION_MODE` 改为 `invite_only` 或 `disabled`，再通过 `/v1/auth/public-config` 和 Admin Console 设置页确认运行状态。

查看本地验证码：

```powershell
cd services/identity-service
docker compose logs -f identity-service
```

日志中查找 `mailbox_path`，再打开对应文件查看验证码正文。
