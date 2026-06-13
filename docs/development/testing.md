# Testing

GoAuth 的测试策略和运行方法。

## 测试层级

```
Unit Tests         → 纯函数，无外部依赖 (bcrypt, JWT 签名, RBAC 解析)
Integration Tests  → 依赖 MySQL/Redis (注册流程, OIDC 流程, 权限检查)
E2E Tests          → 浏览器自动化 (Playwright, Login → OIDC → SSO)
```

## 运行测试

```powershell
# 全部测试
cd services/identity-service
go test ./... -count=1

# 单个包
go test ./internal/auth/... -v

# 带覆盖率
go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out

# 跳过慢测试 (需要 DB/Redis)
go test -short ./...
```

## 单元测试

不需要外部依赖：

```
✅ 密码哈希/校验      — auth/password_test.go (或 service_test.go)
✅ JWT 签发/验证       — session/token_test.go
✅ Refresh Token 哈希  — session/refresh_test.go
✅ RBAC 权限解析       — rbac/service_test.go (mock store)
✅ GitHub profile 标准化 — idp/github/normalize_test.go
```

运行: `go test -short ./...`

## 集成测试

需要 MySQL + Redis:

```
✅ 注册 + 验证码流程     — auth/handler_integration_test.go
✅ 登录 + 刷新流程       — session/refresh_integration_test.go
✅ OIDC Auth Code + PKCE — oidc/token_integration_test.go
✅ 权限检查 + 缓存       — rbac/service_integration_test.go
✅ 租户 + 角色 + 成员    — tenant/service_integration_test.go
```

本地集成测试用 SQLite 内存库 (GORM driver)，Redis mock 或 Docker Redis:

```powershell
# 使用 Docker Redis
docker run -d -p 6379:6379 redis:7-alpine
go test ./... -run Integration

# 使用 SQLite 内存库
# MYSQL_DSN 留空时 GORM 自动用 SQLite
go test ./...
```

## 测试约定

- 测试文件命名: `<file>_test.go`
- 测试函数命名: `Test<Function>_<Scenario>` (如 `TestLogin_InvalidPassword`)
- 集成测试标记: `t.Skip("integration")` 或 build tag `//go:build integration`
- 每个 test 清理自己的数据 (defer delete)
- 不要依赖测试执行顺序

## CI 流程

`.github/workflows/ci.yml`:

1. `go test -short ./...` — 单元测试 (无外部依赖)
2. `docker compose up -d mysql redis` → `go test ./...` — 集成测试
3. `go vet ./...` — 静态分析
