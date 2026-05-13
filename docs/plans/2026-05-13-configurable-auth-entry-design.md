# Configurable Auth Entry Design

## 背景

GoAuth 作为开源身份服务，登录注册能力不能只满足当前部署。接入者应该能通过 `.env` 或容器环境变量完成常见能力开关，不需要改源码，也不应该为了修改验证码、GitHub 登录或注册策略重新构建前端。

当前代码已经具备部分基础：

- 本地账号登录、注册、邮箱验证码、密码重置。
- 后端 CAPTCHA verifier，支持 Turnstile、hCaptcha、reCAPTCHA。
- 前端登录页预留 `window.__goauthCaptcha.getToken()`。
- GitHub OAuth Provider、外部身份绑定、首次外部登录创建用户。
- 默认租户入组策略 `DEFAULT_MEMBER_TENANT_SLUGS`。

缺口主要在产品化和开箱接入：

- 前端仍依赖构建期 `VITE_*` 决定验证码行为。
- 没有运行时 public config，部署后修改能力开关需要重构前端。
- GitHub 登录没有前端入口和浏览器友好的 callback 体验。
- 没有注册模式配置，开源默认应开放注册，但生产应可切到邀请制或关闭。
- 无 SMTP 时 `NoopSender` 会吞掉验证码，不利于本地开箱验证。
- 系统设置页还没有真实反映后端运行配置。

## 目标

第一阶段目标是做一个轻量、易配置、默认开箱可用的登录注册入口：

- 默认注册模式为 `open`。
- 本地账号登录/注册默认启用。
- 邮箱验证码本地可通过日志查看，生产可用 SMTP。
- CAPTCHA 可选启用，优先支持 Cloudflare Turnstile。
- GitHub 登录/注册可选启用。
- 前端通过后端运行时配置决定展示哪些登录方式和验证码组件。
- 文档提供最小启动、启用 GitHub、启用 CAPTCHA、生产建议配置。

## 非目标

第一阶段不实现：

- MFA/TOTP。
- Passkey/WebAuthn。
- Google、Microsoft、企业 OIDC 动态配置。
- 管理后台在线修改运行配置并热生效。
- 复杂风险引擎或设备指纹。

这些能力后续可以基于同一套 provider registry 和 public config 扩展。

## 设计原则

1. **Env first**
   开源部署优先使用环境变量。Docker Compose、systemd、Kubernetes 都能直接表达，排错成本最低。

2. **运行时前端配置**
   前端登录页启动时请求后端 `GET /v1/auth/public-config`，不再依赖构建期 `VITE_CAPTCHA_PROVIDER` 决定登录能力。

3. **默认可用，生产可收紧**
   默认 `REGISTRATION_MODE=open`，方便开源用户拉起就能注册。README 明确生产建议切换到 `invite_only`。

4. **Token 不进 URL**
   GitHub callback 不把 access token 或 refresh token 放入 query string。浏览器登录成功后使用短期一次性 exchange code 让前端换取 token。

5. **能力可发现**
   后端 public config 返回已启用的登录方式、注册模式、验证码 provider/site key、密码策略等非敏感信息。

6. **Secret 不外泄**
   public config 只能包含 site key、provider slug、显示名和公开 URL，不能包含 secret、SMTP 密码、private key。

## 配置模型

新增和整理后的核心配置：

```env
# Registration
REGISTRATION_MODE=open
# open / invite_only / disabled

# Local account
LOCAL_PASSWORD_LOGIN_ENABLED=true

# Mailer
MAILER_PROVIDER=console
# console / smtp / noop

# CAPTCHA
CAPTCHA_PROVIDER=
# turnstile / hcaptcha / recaptcha / empty
CAPTCHA_SITE_KEY=
CAPTCHA_SECRET_KEY=
CAPTCHA_ACTIONS=login,register,email_code,password_forgot

# GitHub OAuth
GITHUB_OAUTH_ENABLED=false
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=
```

保留现有：

```env
PUBLIC_ISSUER_URL=
BROWSER_LOGIN_URL=/login
BROWSER_COOKIE_SECURE=
DEFAULT_MEMBER_TENANT_SLUGS=
```

`GITHUB_REDIRECT_URI` 为空时默认推导：

```text
${PUBLIC_ISSUER_URL}/v1/external/github/callback
```

## Public Config

新增接口：

```text
GET /v1/auth/public-config
```

响应示例：

```json
{
  "registration": {
    "mode": "open"
  },
  "local_login": {
    "enabled": true
  },
  "captcha": {
    "provider": "turnstile",
    "site_key": "0x4AAAA...",
    "actions": ["login", "register", "email_code", "password_forgot"]
  },
  "external_providers": [
    {
      "slug": "github",
      "display_name": "GitHub",
      "start_url": "/v1/external/github/start"
    }
  ],
  "password_policy": {
    "min_length": 8,
    "require_uppercase": false,
    "require_lowercase": false,
    "require_digit": true,
    "require_special": false
  }
}
```

约束：

- 未配置或禁用 CAPTCHA 时 `captcha.provider` 为空，`site_key` 为空。
- GitHub 未启用时 `external_providers` 为空数组。
- `GITHUB_CLIENT_SECRET`、`CAPTCHA_SECRET_KEY`、SMTP 密码永不返回。
- 接口不需要认证，必须只暴露公开安全信息。

## 注册策略

注册模式：

```text
open        任何人可通过邮箱验证码注册
invite_only 仅邀请流程可注册
disabled    关闭自助注册
```

第一阶段行为：

- `open`：保持现有 `/v1/auth/register` 行为。
- `invite_only`：直接调用 `/register` 返回 403，后续应走 invite redeem。
- `disabled`：直接返回 403。
- GitHub 首次登录是否允许自动创建用户，也跟随 `REGISTRATION_MODE`：
  - `open`：允许创建新用户。
  - `invite_only`：第一阶段拒绝自动创建，后续可支持邀请链接绑定外部 IdP。
  - `disabled`：拒绝自动创建，只允许已绑定身份登录。

## Mailer

当前无 SMTP 时使用 `NoopSender`，会导致验证码不可见。新增 `console` sender：

```text
MAILER_PROVIDER=console
```

行为：

- `console`：把验证码邮件内容写入结构化日志，本地和 Compose 默认使用。
- `smtp`：使用现有 SMTP sender。
- `noop`：显式丢弃邮件，仅适合测试。

这样开源用户本地执行 `docker compose up` 后，不配置 SMTP 也能看到验证码并完成注册。

## CAPTCHA

优先实现 Turnstile 前端组件，后端沿用现有 verifier。

前端行为：

- 登录页读取 public config。
- 如果 `captcha.provider=turnstile` 且当前 action 在 `captcha.actions` 内，则渲染 Turnstile 或按需执行。
- 提交请求时带：

```text
X-Captcha-Token: <token>
```

后端行为：

- 只有配置的 action 才要求验证码。
- 未配置 CAPTCHA 时不拦截。
- 配置了 provider 但缺少 secret 时启动失败或 readiness 失败，避免生产误以为已启用。

第一阶段可以继续使用同一个 `captcha.Verifier`，但需要把“哪些接口需要验证码”从固定全量改成按 `CAPTCHA_ACTIONS` 判断。

## GitHub 登录/注册

浏览器流程：

```text
LoginPage
  -> GET /v1/auth/public-config
  -> 展示 GitHub 登录按钮
  -> 浏览器跳转 /v1/external/github/start?return_to=...
  -> GitHub 授权
  -> /v1/external/github/callback
  -> 后端验证 state/code
  -> 后端创建或查找 GoAuth 用户
  -> 后端签发 GoAuth token pair 并设置 OIDC SSO cookie
  -> 后端生成 60 秒一次性 exchange code
  -> 302 到 /external/callback?provider=github&code=...
  -> 前端 POST /v1/external/github/exchange
  -> 前端保存 access_token/refresh_token
  -> 跳转 return_to 或 /admin
```

一次性 exchange code 存 Redis：

```text
auth:external_login_exchange:<code>
```

TTL：60 秒。

存储内容：

```json
{
  "provider": "github",
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "session_id": "..."
  },
  "user": {
    "id": 123,
    "email": "member@example.com"
  },
  "return_to": "/oauth2/authorize?..."
}
```

安全约束：

- exchange code 使用高熵随机值。
- 兑换成功后立即删除。
- exchange code 只通过 HTTPS query 暴露，不包含 token 本身。
- `return_to` 复用现有前端白名单校验逻辑，只允许本站或 issuer 的 `/oauth2/authorize`。
- GitHub 返回邮箱已属于本地账号时，不自动绑定，继续返回“请先本地登录后绑定 GitHub”。

## 前端设计

新增 API：

```text
frontend/src/api/publicConfig.ts
```

新增类型：

```text
frontend/src/types/publicConfig.ts
```

登录页加载顺序：

1. 请求 `/v1/auth/public-config`。
2. 根据 `registration.mode` 判断是否显示注册 tab。
3. 根据 `local_login.enabled` 判断是否显示密码登录表单。
4. 根据 `external_providers` 渲染 GitHub 按钮。
5. 根据 `captcha` 初始化验证码 bridge。

注册 tab 显示规则：

- `open`：显示。
- `invite_only`：隐藏普通注册入口，后续显示“使用邀请链接注册”入口。
- `disabled`：隐藏。

新增回调页：

```text
/external/callback
```

职责：

- 读取 `provider` 和 `code`。
- 调用 exchange 接口。
- 保存 token 到 localStorage。
- 如果 exchange 响应带 `return_to`，跳转 return_to；否则跳转 `/admin`。

## 管理后台设置

第一阶段不做在线修改，只做真实状态展示：

- 注册模式。
- 本地密码登录是否启用。
- CAPTCHA provider 和启用 action。
- GitHub 是否启用。
- Mailer provider。

这能解决“系统设置页开关看起来可改但实际不生效”的问题。可编辑设置放到后续数据库配置阶段。

## 文档

需要更新：

- `README.md`
- `services/identity-service/README.md`
- `services/identity-service/.env.example`
- `services/identity-service/docker-compose.yml`

文档必须覆盖：

- 本地最小启动。
- 默认开放注册。
- 本地如何从日志读取验证码。
- 如何启用 GitHub OAuth。
- 如何启用 Turnstile。
- 生产建议配置。

生产建议：

```env
APP_ENV=production
REGISTRATION_MODE=invite_only
MAILER_PROVIDER=smtp
CAPTCHA_PROVIDER=turnstile
BROWSER_COOKIE_SECURE=true
TRUSTED_PROXIES=<your proxy cidr>
```

## 测试策略

后端：

- config defaults and parsing。
- public-config 响应不泄露 secret。
- registration mode enforcement。
- console mailer emits code to logger。
- CAPTCHA action gating。
- GitHub redirect URI default。
- GitHub callback creates exchange code and exchange endpoint consumes once。

前端：

- public config adapter。
- 登录页按配置显示/隐藏注册、本地登录、GitHub 按钮。
- CAPTCHA token 只在配置 action 上发送。
- external callback exchange 成功后保存 token 并跳转。
- GitHub 错误回调显示可读错误。

集成：

- `go test ./...`
- `npm run test:admin`
- `npm run build`

## 迁移与兼容

- 默认 `REGISTRATION_MODE=open`，不破坏现有注册行为。
- 默认 `LOCAL_PASSWORD_LOGIN_ENABLED=true`，不破坏现有登录行为。
- 默认 `MAILER_PROVIDER=console` 只影响未配置 SMTP 的开发环境；生产如果已配置 SMTP，应显式使用 `smtp` 或按 SMTP 配置自动选择。
- 保留现有 `VITE_API_BASE_URL`，但不再要求 `VITE_CAPTCHA_PROVIDER`。
- GitHub 老接口 `/v1/external/github/start` 和 `/callback` 保留，增加浏览器 redirect/exchange 行为。

## 后续扩展

- Google/Microsoft/企业 OIDC provider registry。
- MFA/TOTP。
- Passkey/WebAuthn。
- 邀请注册和外部 IdP 首次登录绑定邀请。
- 数据库配置覆盖 env，并由系统设置页在线修改。
