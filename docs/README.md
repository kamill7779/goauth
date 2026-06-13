# GoAuth Documentation

欢迎。这是 GoAuth 的完整文档入口。

## 导航

### 🏗 架构文档
按 C4 模型分层，从系统上下文到代码级组件。

| 文档 | 内容 |
|------|------|
| [01 — System Context](architecture/01-system-context.md) | GoAuth 在整个生态系统中的位置和外部依赖 |
| [02 — Container Architecture](architecture/02-container.md) | 运行容器、技术栈、通信方式 |
| [03 — Component Architecture](architecture/03-component.md) | identity-service 包结构、分层规范、启动流程 |
| [04 — Data Model](architecture/04-data-model.md) | 17 张 MySQL 表 ER 图 + Redis Key 体系 |
| [05 — Authentication Flows](architecture/05-auth-flows.md) | 6 张时序图：注册/登录/刷新/OIDC/GitHub/SSO Cookie |
| [06 — RBAC Model](architecture/06-rbac-model.md) | 租户 RBAC 模型、权限检查流程、缓存失效机制 |

### 📋 架构决策记录 (ADR)
为什么做出这些技术选择。

| ADR | 决策 |
|-----|------|
| [0001](adr/0001-mysql-primary-store.md) | MySQL 作为主存储 + GORM 抽象 |
| [0002](adr/0002-jwt-access-token.md) | JWT Access Token + Opaque Refresh Token |
| [0003](adr/0003-redis-cache-ratelimit.md) | Redis 承担临时状态和热点缓存 |
| [0004](adr/0004-bcrypt-over-argon2.md) | bcrypt 密码哈希 |
| [0005](adr/0005-refresh-token-family.md) | Refresh Token 家族链轮换 + 复用检测 |
| [0006](adr/0006-browser-sso-cookie.md) | 浏览器 SSO Cookie (RS256 JWT) |

### 🛠 开发手册

| 文档 | 内容 |
|------|------|
| [Quickstart](development/quickstart.md) | 5 分钟从 clone 到跑起来 |
| [Project Conventions](development/project-conventions.md) | 目录规范、分层、命名约定、文件拆分、注释原则 |
| [Testing](development/testing.md) | 测试策略、运行方法、CI 流程 |
| [Contributing](development/contributing.md) | PR 流程、分支策略、代码审查检查清单 |

### 🚀 部署运维

| 文档 | 内容 |
|------|------|
| [Docker Compose](deployment/docker-compose.md) | 本地 Compose + 生产 Compose + 前端托管 |
| [Configuration](deployment/configuration.md) | 全部 60 个环境变量、默认值、分类 |
| [SMTP Setup](deployment/smtp.md) | 邮件配置：126/Outlook/常见排障 |
| [Production Checklist](operations/production-checklist.md) | 上线前安全 & 运维检查 |
| [Troubleshooting](operations/troubleshooting.md) | 常见问题：登录/OIDC/Cookie/SMTP/CORS/JWKS |

### 🔌 集成接入

| 文档 | 内容 |
|------|------|
| [OIDC Provider Integration](integration/oidc-provider.md) | 业务系统接入 GoAuth 作为 OIDC IdP |
| [SSO Quickstart](integration/sso-quickstart.md) | 让业务项目用 GoAuth 登录 |

### 📡 API 参考

- [OpenAPI 3.0 Spec](api/openapi.yaml) — Swagger / OpenAPI 规范文件

## 阅读路线

**新人入职**：按顺序读
1. System Context → Container → Component (了解全貌)
2. Data Model (了解存储)
3. Quickstart (动手跑起来)

**接入方开发者**：
1. [OIDC Provider Integration](integration/oidc-provider.md)
2. [Auth Flows](architecture/05-auth-flows.md) (只看 OIDC 时序图)
3. [API Spec](api/openapi.yaml)

**运维**：
1. [Docker Compose](deployment/docker-compose.md)
2. [Configuration](deployment/configuration.md)
3. [Production Checklist](operations/production-checklist.md)

**贡献代码**：
1. [Project Conventions](development/project-conventions.md)
2. [Contributing](development/contributing.md)
3. 相关 ADR
