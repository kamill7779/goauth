# Project Conventions

GoAuth identity-service 的开发规范。

## 目录结构

```
services/identity-service/
├── cmd/server/main.go           # 入口：启动、组装依赖、注册路由
├── internal/
│   ├── config/                  # 环境变量 → 强类型 Config
│   ├── http/                    # Gin Router、CORS、统一响应
│   ├── middleware/               # RequestID、StructuredLogger
│   ├── store/                   # GORM Models + Repository
│   ├── cache/                   # Redis 客户端 + Key 生成
│   ├── auth/                    # 认证：注册/登录/2FA/密码重置
│   ├── session/                 # 会话：Token 签发/刷新/中间件/Cookie
│   ├── oidc/                    # OIDC Provider 全部端点
│   ├── idp/                     # 外部 IdP 抽象 + GitHub 适配器
│   ├── rbac/                    # RBAC 权限查询 + 缓存
│   ├── tenant/                  # 租户/成员/角色管理
│   ├── user/                    # 用户管理
│   ├── admin/                   # Admin Console 后端
│   ├── account/                 # 用户个人中心
│   ├── invite/                  # 邀请码
│   ├── provisioning/            # 默认成员策略
│   ├── mailer/                  # 邮件发送
│   ├── lockout/                 # 登录锁定
│   ├── captcha/                 # CAPTCHA 验证
│   └── audit/                   # 审计日志
├── pkg/                         # 对外暴露的公共类型/客户端
├── cmd/server/docs/             # Swagger 文档源
└── .env.example                 # 环境变量模板
```

## 分层架构

```
Handler (HTTP)  →  Service (Business)  →  Repository (Data)  →  MySQL/Redis
```

**硬约束**:
- Handler 不直接调 Repository
- Service 不 import `gin` 包
- Redis key 统一在 `internal/cache/keys.go`

## 文件拆分准则

- **100-500 行**一个文件最佳
- 按**功能关注点**拆分，不是按类型
- 同一 struct 的方法可以跨文件（Go 语言特性）
- Handler struct + 路由注册留在 `handler.go`，具体功能拆到 `handler_<feature>.go`
- 小于 50 行的独立文件考虑合并到相关文件

## 命名约定

| 概念 | 命名 | 示例 |
|------|------|------|
| Handler struct | `Handler` | `auth.Handler` |
| Service struct | `Service` | `auth.Service` |
| Repository | `*gorm.DB` (直接注入) | `store.New(db)` |
| 路由注册方法 | `RegisterRoutes(router, authMW, sysMW)` | — |
| 依赖设置 | `SetDependencies(...)` | `SetLockoutManager(...)` |
| 私有辅助函数 | lowerCamelCase | `issueLoginTokens(ctx, ...)` |
| 常量 | UpperCamelCase 或 ALL_CAPS | `defaultBrowserSessionTTL` |

## 错误处理

- Handler 层: 调用 service，映射 error 到 HTTP 状态码 + 统一 JSON 响应
- Service 层: 返回自定义 error (如 `ErrProtectedUser`, `ErrInvalidCredentials`)
- 不要 panic——只在 `main.go` 的 fatal 前置条件中使用

## 日志

```go
slog.Info("action description", "key", value)
slog.Error("action description", "key", value, "error", err)
```

- Handler 层通过 `middleware.StructuredLogger` 自动记录请求
- Service 层在关键操作点记录 (登录成功、Token 撤销、权限变更)
- 审计事件不通过日志，走 `audit.Service.Record()`

## 注释原则

- 只在意图不直观的地方写注释
- 不给明显的 CRUD、赋值写逐行解说
- 复杂代码块上方写一条短注释
- 代码变更时更新注释

## 依赖方向

```
cmd/server
  └─ internal/*   (所有包)
       ├─ store   (无内部依赖，只有 GORM)
       ├─ config  (无内部依赖，只有 os.Getenv)
       ├─ cache   (无内部依赖，只有 Redis)
       ├─ auth    → store, cache, session, mailer
       ├─ session → store, cache
       ├─ oidc    → session, store
       ├─ tenant  → rbac, store
       ├─ user    → store, audit
       └─ rbac    → cache, store
```

**禁止**: 同级包互相引用 (如 `auth` import `oidc`), 下层 import 上层 (如 `store` import `auth`).
