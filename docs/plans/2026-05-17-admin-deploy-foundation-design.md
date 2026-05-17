# Admin Deploy Foundation Design

日期：2026-05-17

## 目标

把 GoAuth 打磨成更容易部署、更容易接入、更容易管理的轻量权限中心 SSO 服务。下一轮同时做两件事：配置与部署中枢、权限中心后台增强。

## 产品原则

- GoAuth 仍是独立身份服务，不成为下游业务系统的配置中心。
- 环境变量继续是运行配置事实源；后台只展示、诊断和指导，不在线编辑运行参数。
- 权限模型继续保持租户级 RBAC：User -> TenantMember -> Role -> Permission。
- 外部身份提供方保持可插拔，但不是产品主形态。
- 本地开源体验默认易启动，生产诊断明确指出必须收紧的项。

## 非目标

- 不做 MFA、passkeys、ABAC 策略语言。
- 不做数据库持久化运行设置。
- 不新增 Google/Microsoft 外部 IdP。
- 不把 New API、论坛或其他下游业务概念写进 GoAuth 源码。

## 方案

本轮采用“后台可视化 + 后端只读汇总 API”的方式，避免重平台化。

### 1. 配置与部署中枢

现有 `config.EnvDefinitions()` 已经是配置矩阵的代码来源，但 Admin Settings 还只是平铺字段。本轮增强为部署体检首页：

- 后端 `/v1/admin/runtime-config` 增加 summary，统计 ok/warning/error 数量。
- 每个配置项继续不返回 secret 原始值。
- 前端 Settings 顶部显示部署体检结果：环境、错误数、警告数、公开配置状态。
- Settings 继续按组展示详细诊断，优先突出 error/warning。
- 文档要求 `schema.go`、`.env.example`、`docs/configuration.md` 同步，并用测试防止漂移。

### 2. 权限中心后台增强

现有后台有用户、租户、角色、OAuth Client 分页，但缺少全局视图。本轮新增只读权限中心总览：

- 后端新增 `/v1/admin/access-overview`。
- 返回租户、成员、角色、权限、OAuth Client、自动入组客户端、默认成员租户配置的汇总。
- 返回租户访问地图：每个租户的成员数、角色数、权限覆盖数、OAuth Client 数。
- 返回默认入组配置解析结果：配置了哪些 slug、是否匹配到活跃租户。
- 返回权限风险提示，例如默认入组 slug 不存在、活跃租户没有角色、角色没有权限、启用自动入组的 OAuth Client 过多或指向不可用租户。
- 前端把 `SecurityPage` 从占位“邮件与安全”改成“权限中心”，展示这些真实数据。

## 数据流

```text
Admin Console
  GET /v1/admin/runtime-config
    -> config.EnvDefinitions + runtime Config
    -> summary + groups

  GET /v1/admin/access-overview
    -> MySQL store tables + Config.DefaultMemberTenantSlugs
    -> summary + tenant map + default membership + risks
```

`/v1/admin/*` 继续使用现有 auth middleware 和 system-admin middleware。

## UI 方向

后台是运维/权限工作台，不做营销式页面。页面应保持信息密度、可扫描、低装饰：

- 顶部是一排状态摘要。
- 中部展示需要处理的问题。
- 下方展示租户访问地图和 OAuth Client 自动入组状态。
- 不嵌套卡片，不做大 hero，不增加不必要动效。

## 风险与约束

- 配置诊断不能泄露 secret。
- 汇总查询不能引入重 SQL 或跨库特性，保持 SQLite/MySQL 测试兼容。
- 权限中心只读增强不改变现有授权行为。
- 所有风险提示必须是 GoAuth 通用概念，不出现具体业务系统名称。

## 验证

- 后端：`go test ./internal/admin ./cmd/server ./internal/config`
- 前端：`npm run test:admin`
- 构建：`npm run build`
- 全量：`go test ./...`
