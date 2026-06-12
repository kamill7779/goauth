# 重构计划：补抽象（克制版）

> 原则：只加**解决明确痛点**的抽象。不为抽象而抽象。每个抽象必须回答："它让什么变得更容易？"
> 预计工作量 10-15 天，分 5 个 Phase 独立交付。

---

## 当前问题诊断

### 🔴 严重

| # | 问题 | 证据 |
|---|---|---|
| 1 | `*gorm.DB` 裸传 — Service/Handler 直接持有 DB 句柄 | `auth/service.go:58`, `admin/handler.go:22` |
| 2 | GORM Model = 领域对象 = API 响应 — `store.User` 三重身份 | `auth/service.go:125` 返回 `*store.User` |
| 3 | Setter 注入 — 14+ 个 `Set*()` 方法，漏调就静默降级 | `auth/service.go:86-100`, `oidc/service.go:132-142` |
| 4 | God Config — 46 字段的 `config.Config` 传给几乎所有构造函数 | `session/token.go:79` 只用其中 5 个字段 |

### 🟡 中等

| # | 问题 | 证据 |
|---|---|---|
| 5 | Service 无接口 — Handler 依赖具体 `*auth.Service` | `auth/handler.go:18-20` |
| 6 | 错误只是字符串 — 不带结构化信息 | `auth/service.go:22-30` |
| 7 | 路由注册三种模式混用 | `main.go` 同时存在 `Registrar` / `EngineRegistrar` / 临时方法 |

---

## Phase 1 — Repository 接口层 🔑

**痛点**：Service 直接持 `*gorm.DB`，无法单测，数据库迁移需改业务代码。

**方案**：为 4 个核心聚合定义接口 + GORM 实现。

### 新增文件

```
internal/store/
  repository.go            ← UserRepository, SessionRepository, OAuthRepository, TenantRepository 接口
  user_repository.go       ← GORM 实现
  session_repository.go    ← GORM 实现
  oauth_repository.go      ← GORM 实现
  tenant_repository.go     ← GORM 实现
```

### 接口定义

```go
type UserRepository interface {
    FindByID(ctx context.Context, id int64) (*User, error)
    FindByEmail(ctx context.Context, email string) (*User, error)
    FindByUsername(ctx context.Context, username string) (*User, error)
    Create(ctx context.Context, user *User) error
    Update(ctx context.Context, user *User) error
    BumpTokenVersion(ctx context.Context, id int64) error
}

type SessionRepository interface {
    FindRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error)
    CreateLoginSession(ctx context.Context, session *LoginSession) error
    RevokeTokenFamily(ctx context.Context, familyID string) error
    RevokeRefreshToken(ctx context.Context, id int64) error
}

type OAuthRepository interface {
    FindClientByID(ctx context.Context, clientID string) (*OAuthClient, error)
    CreateAuthorizationCode(ctx context.Context, code *OAuthAuthorizationCode) error
    ConsumeAuthorizationCode(ctx context.Context, codeHash string) (*OAuthAuthorizationCode, error)
}

type TenantRepository interface {
    FindBySlug(ctx context.Context, slug string) (*Tenant, error)
    AddMember(ctx context.Context, member *TenantMember) error
    FindMemberRoles(ctx context.Context, memberID int64) ([]MemberRole, error)
}
```

### 不做的事

- **不为 16 张表每张建 Repository**。只给被 2+ 个 Service 跨包引用的聚合建。
- `PasswordHistory`、`AuditLog` 等只被一个 Service 用的表，继续由 Service 直接通过 GORM 访问。

### 影响的变更

所有 Service 构造函数从接受 `*gorm.DB` 改为接受对应的 Repository 接口。

---

## Phase 2 — 消灭 Setter 注入

**痛点**：14+ 个 `Set*()` 方法，漏调就静默降级，没有编译期保证。

**方案**：所有依赖进入构造函数，用 `Dependencies` struct 模式。

### 改造前

```go
s := auth.NewService(db, redis, mailSender)
s.SetLockoutManager(lockoutMgr)   // 忘了调用 → 静默降级
s.SetPasswordPolicy(pwPolicy)
s.SetAuditRecorder(auditService)
```

### 改造后

```go
s := auth.NewService(auth.Dependencies{
    DB:             db,
    Redis:          redis,
    MailSender:     mailSender,
    LockoutManager: lockoutMgr,    // 编译期保证必填
    PasswordPolicy: pwPolicy,
    AuditRecorder:  auditService,
})
```

### 处理可选依赖

CAPTCHA、RateLimiter 等"可能关闭"的依赖，在构造函数内判断 nil 并决定行为（如返回 noop 实现），而不是在运行时每处都 `if s.captcha != nil`。

### 不做的事

- 不引入 Wire 或任何 DI 框架。手动 `Dependencies` struct 足够清晰。

---

## Phase 3 — 配置拆分

**痛点**：`config.Config` 46 个字段，`session.NewService` 只用其中 5 个，测试时必须构造整个 struct。

**方案**：拆分 3-4 个聚焦子配置。

### 新增文件

```
internal/config/
  auth_config.go     ← TokenConfig + MailerConfig + LockoutConfig
  oidc_config.go     ← OIDC 相关
  http_config.go     ← CORS + 可信代理
```

### 子配置示例

```go
type TokenConfig struct {
    AccessTokenTTL    time.Duration
    RefreshTokenTTL   time.Duration
    BrowserSessionTTL time.Duration
    BrowserCookieName string
    JWTKeyID          string
}

type MailerConfig struct {
    Provider string
    SMTPHost string
    SMTPPort int
    From     string
}
```

### 做法

`config.Load()` 仍然加载完整 `Config`，在 `main.go` 中按需拆分为子配置传给各 Service 构造函数。各 Service 的测试可以直接构造子配置。

### 不做的事

- 不需要 10+ 个子配置。5 个以内够用。
- 零散字段（如 `BrandName`）继续随 `config.Config` 直接传。

---

## Phase 4 — 领域模型边界

**痛点**：`store.User` 带 GORM tag + `BeforeCreate` hook（里面调数据库！），同时被 Service 返回、JWT claims 嵌入、HTTP 响应使用。DB schema 变更会破坏 API 契约。

**方案**：只隔离最严重的泄漏点 — JWT claims + HTTP 响应。不改 Service 之间的传递。

### 新增文件

```
internal/domain/
  user.go      ← User{ID, Email, Username, Status, TokenVersion}  无 tag、无 hook
  session.go   ← TokenPair{AccessToken, RefreshToken}  无 tag
```

### 改造前

```go
// JWT claims 嵌入 store.User
type accessClaims struct {
    jwt.RegisteredClaims
    Email  string      `json:"email"`
    UserID int64       `json:"sub"`
    // ...直接从 store.User 字段赋值
}
```

### 改造后

```go
// JWT 签发时用 domain.User，显式赋值
func (s *Service) IssueTokens(ctx context.Context, user domain.User) (TokenPair, error) {
    claims := accessClaims{
        UserID: user.ID,
        Email:  user.Email,
        // 显式赋值，无隐式依赖
    }
}
```

### 不做的事

- 不引入 DTO 层（`api.UserResponse`）。Go 不是 Java，`gin.H{"id": user.ID}` 足够清晰。
- 不改变 Service 之间的 `store.User` 传递——内部可以继续用 GORM 模型。

---

## Phase 5 — 富化核心错误

**痛点**：`errors.New("account locked")` 不带 `RetryAfter` 信息，Handler 无法写 `Retry-After` 头。

**方案**：只给"跨层传递且需要携带数据"的错误建类型。3 个足够。

### 新增文件

```
internal/auth/errors.go
```

### 错误类型

```go
type LockoutError struct {
    RetryAfter time.Duration
}
func (e *LockoutError) Error() string {
    return fmt.Sprintf("account locked, retry after %s", e.RetryAfter)
}

type ValidationError struct {
    Field   string
    Message string
}
func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed: %s - %s", e.Field, e.Message)
}

type RateLimitError struct {
    RetryAfter time.Duration
}
func (e *RateLimitError) Error() string {
    return fmt.Sprintf("rate limited, retry after %s", e.RetryAfter)
}
```

### Handler 用法

```go
var lockoutErr *auth.LockoutError
if errors.As(err, &lockoutErr) {
    c.Header("Retry-After", strconv.Itoa(int(lockoutErr.RetryAfter.Seconds())))
    httpserver.Error(c, http.StatusTooManyRequests, lockoutErr.Error())
    return
}
```

### 不做的事

- `ErrInvalidCredential`、`ErrEmailAlreadyUsed` 等纯哨兵错误继续用 `errors.New`，不需要类型化。

---

## 明确不做的事（边界）

| 不做的 | 理由 |
|---|---|
| ❌ 引入 Wire / Dig 等 DI 框架 | 手动 DI 对于 26 个包的项目足够清晰，引入框架增加学习成本 |
| ❌ 每个 Service 都建接口 | 只在跨包边界处建（Session 被 11 个包依赖 → 要接口；Lockout 只被 Auth 用 → 不需要） |
| ❌ DDD 四层分层 | 当前 Handler → Service → GORM 三层够用，加第四层只加文件不加价值 |
| ❌ 引入 DTO / Response 对象 | `gin.H` + 手动序列化比 `api.LoginResponse{...}` 更 Go 更直接 |
| ❌ 改目录结构（domain/ usecase/ infra/） | 保持扁平 internal/ 结构 |

---

## 影响范围

| Phase | 新增文件 | 修改文件 | 核心价值 |
|---|---|---|---|
| 1. Repository 接口 | 4 | ~10 | 🔑 可单测 + 数据库解耦 |
| 2. 构造函数 DI | 0 | ~10 | 🛡️ 消除 14 个静默降级点 |
| 3. 配置拆分 | 3 | ~12 | 🧪 测试不再需要 46 字段 Config |
| 4. 领域模型边界 | 2 | ~5 | 🔒 防 DB schema 变更破坏 API |
| 5. 富化错误 | 1 | ~5 | 📡 支持 Retry-After / 字段级错误 |

**总计新增文件约 10 个，修改约 40 个文件，工作量约 10-15 天。**

---

## 执行顺序

```
Phase 1 (Repository 接口)     ← 从这里开始。基础依赖，后续都依赖它
    ↓
Phase 2 (构造函数 DI)          ← 依赖 Phase 1，需改所有 Service 构造函数
    ↓
Phase 3 (配置拆分)             ← 独立，可与 Phase 2 并行
    ↓
Phase 4 (领域模型边界)         ← 独立
    ↓
Phase 5 (富化错误)             ← 独立，最后做
```

每个 Phase 独立可提交，PR 粒度合理，不破坏现有功能。
