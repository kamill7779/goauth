# 清理计划：去冗余 & 死代码

> 目标：删除冗余代码、合并重复逻辑、统一不一致模式。不做架构变更，只做减法。
> 预计节约 ~540 行。

---

## Tier 1 — 立即可做（约 1 小时）

### 1.1 删除死包 `internal/idp/oidc/`

- **位置**：`internal/idp/oidc/provider.go` + `provider_test.go`
- **原因**：整个包实现了 `idp.Provider` 接口用于通用 OIDC Provider，但从未被任何生产代码引用。只有 `idp/github` 被 `buildRouterWithKeyring` 接入。
- **处理**：删除两个文件，约 350 行。
- **风险**：无。如果未来需要通用 OIDC Provider，从 git history 恢复即可。

### 1.2 运行 `go mod tidy`

- **位置**：`go.mod`
- **原因**：所有 63 个依赖都被标记为 `// indirect`，包括 gin、gorm、redis 等直接依赖。`go mod tidy` 从未运行过，可能导致直接/间接依赖分类错误。
- **处理**：在 `services/identity-service/` 下执行 `go mod tidy`。
- **风险**：低，为标准 Go 工具链操作。

### 1.3 新增 `httpserver.Error()` 辅助函数

- **位置**：`internal/http/response.go`
- **原因**：已有 `httpserver.Success(c, status, data)`，但缺少对偶的 error helper。全项目 ~150 处 `c.JSON(status, gin.H{"error": err.Error()})`。
- **处理**：
  ```go
  func Error(c *gin.Context, status int, message string) {
      c.JSON(status, gin.H{"error": message})
  }
  ```
  然后全局替换 `c.JSON(xxx, gin.H{"error": ...})` → `httpserver.Error(c, xxx, ...)`。
- **风险**：低，纯机械替换，错误响应格式不变（仍然是 `{"error": "..."}`）。
- **节约**：~100 行。

### 1.4 删除死函数 `loadSigningKey`

- **位置**：`cmd/server/main.go:115-121`
- **原因**：`loadSigningKey` 是对 `loadSigningKeyring` 的薄包装，但从未被调用。
- **处理**：删除函数，6 行。

### 1.5 删除死 cache key 函数

- **位置**：`internal/cache/keys.go`
- **原因**：`UserCacheKey`、`SessionKey`、`JtiDenylistKey`、`OIDCStateKey` 这 4 个函数只在 `keys_test.go` 中被调用，无生产代码引用。
- **处理**：删除 4 个函数及对应测试用例，约 25 行。

---

## Tier 2 — 去重合并（约 2 小时）

### 2.1 合并 `defaultString` 三份定义

- **位置**：`cmd/server/main.go:357`、`internal/auth/public_config.go:98`、`internal/account/handler.go:1703`
- **原因**：三份一模一样的 `func defaultString(val, fallback string) string`。
- **处理**：移到 `internal/http/response.go` 或新建 `internal/util/strings.go`，三处改为引用。

### 2.2 合并 `captchaActionSet` + `captchaActionEnabled`

- **位置**：`internal/auth/handler.go:74-101`、`internal/idp/handler.go:103-121`
- **原因**：两份完全相同的 CAPTCHA action 处理逻辑。
- **处理**：提取到 `captcha` 包作为公共方法。

### 2.3 合并 `githubIDPConfigured` 逻辑

- **位置**：`cmd/server/main.go:342`、`internal/auth/public_config.go:71`
- **原因**：相同的 GitHub 配置检查逻辑。
- **处理**：在 `config.Config` 上加 `IsGitHubConfigured() bool` 方法。

### 2.4 删除 `idp/service.go` 中的本地 `normalizeEmail`

- **位置**：`internal/idp/service.go:519-521`
- **原因**：与 `identity.NormalizeEmail` 完全重复。
- **处理**：删除本地版本，使用 `identity.NormalizeEmail`。

### 2.5 合并 `SetRateLimiter` + `setRetryAfterHeader` 三份重复

- **位置**：`internal/auth/rate_limit.go`、`internal/session/rate_limit.go`、`internal/oidc/rate_limit.go`
- **原因**：三个包中 `SetRateLimiter` 方法 + `setRetryAfterHeader` 逻辑完全相同。
- **处理**：提取到 `ratelimit` 包作为公共 helper。

---

## Tier 3 — 结构优化（约 2 小时）

### 3.1 拆分 `buildRouterWithKeyring`

- **位置**：`cmd/server/main.go:170-285`（116 行）
- **原因**：单一函数构造了整个应用的依赖图，难以阅读和测试。
- **处理**：提取 4-5 个子 builder：
  - `buildCoreServices(db, redis, keyring, cfg)`
  - `buildAuthGroup(router, services)`
  - `buildOIDCGroup(router, services)`
  - `buildAdminGroup(router, services)`
  - `buildAccountGroup(router, services)`
- **不改**：不引入 DI 框架，保持纯函数手动装配。

### 3.2 统一路由注册模式

- **位置**：`main.go` + 各 handler
- **原因**：三种注册模式并存（`Registrar` 接口、`EngineRegistrar` 接口、临时方法调用）。
- **处理**：统一到 `RouteRegistrar` 接口，所有 handler 实现同一个 `RegisterRoutes(gin.IRouter)`。

### 3.3 清理空目录

- **位置**：`cmd/server/data/avatars/`
- **处理**：加 `.gitkeep` 或确保运行时自动创建。

---

## 清理总览

| 层级 | 项目数 | 预计节约 |
|------|--------|----------|
| Tier 1 | 5 | ~480 行 |
| Tier 2 | 5 | ~57 行 |
| Tier 3 | 3 | 0 行（结构优化） |
| **合计** | **13** | **~540 行** |

## 执行顺序

```
Tier 1.2 (go mod tidy)        ← 先做，确保依赖正确
  → Tier 1.1 (删 idp/oidc)     ← 最大块死代码
  → Tier 1.4 + 1.5 (删死函数)  ← 小块清扫
  → Tier 1.3 (加 Error helper) ← 最大节约量
  → Tier 2 (去重合并)          ← 逐项处理
  → Tier 3 (结构优化)          ← 最后
```
