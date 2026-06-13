# GoAuth

[![CI](https://github.com/kamill7779/goauth/actions/workflows/ci.yml/badge.svg)](https://github.com/kamill7779/goauth/actions/workflows/ci.yml)

GoAuth 是一个可独立部署的 SSO/身份服务——面向新项目脚手架和中小团队统一登录场景。

**核心能力**: 邮箱注册/登录/2FA · OIDC Provider (Auth Code + PKCE) · 多租户 RBAC · 浏览器 SSO · GitHub 外部登录 · Admin Console · 审计日志。

## 5 分钟跑起来

```powershell
cd services/identity-service
docker compose up --build
```

```powershell
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

前端 (SPA):
```powershell
cd frontend && npm install && npm run dev
# 登录页 http://127.0.0.1:3000/login
# Admin   http://127.0.0.1:3000/admin
```

## 文档

所有文档从 **[docs/](docs/README.md)** 进入：

| 分类 | 入口 |
|------|------|
| 架构设计 | [C4 分层 → 数据模型 → 认证流程 → RBAC](docs/README.md#-架构文档) |
| 决策记录 | [6 篇 ADR: MySQL / JWT / Redis / bcrypt / Token 轮换 / SSO Cookie](docs/README.md#-架构决策记录-adr) |
| 开发手册 | [Quickstart · 代码规范 · 测试 · 贡献](docs/README.md#-开发手册) |
| 部署运维 | [Docker Compose · 配置矩阵 · SMTP · 上线检查 · 排障](docs/README.md#-部署运维) |
| 接入集成 | [OIDC Provider · SSO 快速接入](docs/README.md#-集成接入) |
| API 参考 | [OpenAPI 3.0 Spec](docs/api/openapi.yaml) |

## 技术栈

`Go 1.24` · `Gin` · `GORM v2` · `MySQL` · `Redis` · `golang-jwt/jwt/v5` · `bcrypt` · `React 18` · `Vite` · `Tailwind`

## 生产提醒

生产前必须: `APP_ENV=production` · `REGISTRATION_MODE=invite_only` · 持久 MySQL/Redis · 固定 JWT 私钥 · 删除 bootstrap admin secret。详见 [上线检查](docs/operations/production-checklist.md)。
