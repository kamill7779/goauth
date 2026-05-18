# GitHub Verified Email Auto-Bind Design

## 背景

当前 GitHub OAuth 登录在以下路径工作正常：

- 浏览器可跳转 GitHub 授权页。
- GitHub App 权限已能返回 `/user` 与 `/user/emails`。
- 回调后端可以拿到 `ExternalProfile.Email` 与 `ExternalProfile.EmailVerified`。

当前阻塞点在 [services/identity-service/internal/idp/service.go](E:/Project/goauth/.worktrees/github-auto-bind-email/services/identity-service/internal/idp/service.go)：

- 如果外部身份尚未绑定。
- 且外部邮箱命中现有本地 `users.email`。
- 后端直接返回 `ErrLocalLoginRequired`。

这避免了静默接管，但也让“本地账号 + GitHub 同邮箱”这类正常用户第一次走 GitHub 登录时必然失败。

## 目标

在不放宽账户安全边界的前提下：

- 让 GitHub 登录可以对“已验证邮箱命中现有本地用户”的场景自动完成绑定并直接登录。
- 让第三方登录入口在 CAPTCHA 启用时，也必须先完成 challenge 才能发起外部跳转。

## 非目标

- 不支持无邮箱的 GitHub 账号自动建档。
- 不支持未验证邮箱自动绑定。
- 不支持用邮箱自动覆盖已有 GitHub 绑定。
- 不在这次改动里增加新的前端绑定页面或管理员配置项。

## 方案选型

### 方案 A：保持现状

优点：

- 风险最低。

缺点：

- 首次 GitHub 登录体验差。
- 用户必须理解“先本地登录再绑定”的内部模型。

### 方案 B：仅对已验证邮箱自动绑定

优点：

- 满足“邮箱是主身份键”的产品逻辑。
- 不依赖用户公开邮箱隐私，只依赖 GitHub App 的 `user:email` 能力。
- 风险边界清晰，可用测试覆盖。

缺点：

- 仍需为无邮箱、未验证邮箱、禁用用户保留失败路径。

### 方案 C：只要邮箱相同就自动绑定

优点：

- 实现最少。

缺点：

- 未验证邮箱也可触发绑定，存在明显接管风险。

选择：方案 B。

## 允许自动绑定的条件

必须同时满足：

1. 外部身份此前未绑定到任何用户。
2. `ExternalProfile.Email` 非空。
3. `ExternalProfile.EmailVerified == true`。
4. 归一化邮箱命中唯一的本地用户。
5. 本地用户 `status == active`。
6. 该本地用户当前没有绑定其他 GitHub 身份。

满足后：

- 在事务内创建 `user_identities` 记录。
- 继续当前登录流程，直接签发登录态。

## 必须拒绝自动绑定的条件

- 外部邮箱为空：返回 `ErrEmailRequired`。
- 外部邮箱未验证：返回 `ErrLocalLoginRequired`。
- 匹配到的本地用户被禁用：返回 `ErrUserDisabled`。
- 该本地用户已绑定另一个 GitHub 身份：返回 `ErrLocalLoginRequired`。
- 外部身份已绑定到其他用户：维持现有已绑定路径。

这些拒绝场景都保持“不能静默改绑”的原则。

## 后端实现

变更集中在 `services/identity-service/internal/idp/service.go`：

1. 保留现有“先按 provider_user_id 查 identity”的快速路径。
2. 当 identity 不存在时：
   - 先做邮箱归一化与空值校验。
   - 查本地用户。
   - 若本地用户不存在，走现有“新建用户 + 新建 identity”逻辑。
   - 若本地用户存在，进入新的“安全自动绑定”分支。
3. 自动绑定分支需要：
   - 校验 `profile.EmailVerified`。
   - 校验用户状态。
   - 查询 `user_id + provider` 是否已有其他 GitHub 绑定。
   - 事务创建 identity。

结果语义保持稳定：

- `result.Created` 仍只表示“创建了新用户”。
- 自动绑定现有用户时，`Created=false`。
- `WasLinked=false`，因为该 identity 不是预先存在的。

## 第三方登录 Challenge

当前 `/v1/external/github/start` 是浏览器直接 GET 后 302 跳 GitHub，这条路径无法安全携带 `X-Captcha-Token`。

本次改为双入口：

- `POST /v1/external/github/start`
  前端先完成 `login` challenge，再带 `X-Captcha-Token` 调这个接口。
  后端验证通过后写入 state cookie，并返回 `authorize_url`。
- `GET /v1/external/github/start`
  仅在未启用该 challenge 时保留原有 302 行为。
  一旦 `login` challenge 启用，GET 直接返回 `captcha token required`，防止绕过。

前端 `LoginPage` 中的 GitHub 按钮改为：

1. 调用现有 `getCaptchaToken(config, "login")`。
2. `POST /v1/external/github/start`。
3. 收到 `authorize_url` 后再 `window.location.assign(...)`。

## 审计

自动绑定是安全敏感动作，应补一条 `audit.ActionExternalIdentityChanged`，元数据与显式 `Bind()` 保持一致，并额外标注 `change=auto_bound`。

这样生产排障时可以区分：

- 用户显式绑定。
- 首次 GitHub 登录触发的邮箱自动绑定。

## 测试

核心测试放在 `services/identity-service/internal/idp/service_test.go`：

- 已验证邮箱命中现有用户时自动创建 identity 并登录成功。
- 自动绑定后 `Created=false`，且 identity 真实落库。
- 未验证邮箱命中现有用户时仍返回 `ErrLocalLoginRequired`。
- 命中禁用用户时返回 `ErrUserDisabled`。
- 自动绑定写入外部身份变更审计日志。

GitHub 启动 challenge 测试覆盖：

- `POST /v1/external/github/start` 返回 `authorize_url` 并写 state cookie。
- CAPTCHA 开启时，未带 token 的 `POST /start` 返回 403。
- CAPTCHA 开启时，`GET /start` 也返回 403，不能绕过 challenge。

## 发布与回归

1. 本地运行 `go test ./internal/idp` 验证红绿循环。
2. 再跑 `go test ./...` 做服务级回归。
3. 构建并部署 `identity-service` 到生产机。
4. 复测：
   - GitHub 首次登录同邮箱本地账号应直接成功。
   - 无邮箱或未验证邮箱账号仍应被拒绝。
