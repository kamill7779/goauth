# 05 — Authentication Flows

核心认证流程的时序图，基于真实代码路径。

## 1. 邮箱注册 + 验证码发送

```mermaid
sequenceDiagram
    actor U as User (Browser)
    participant SPA as SPA (Frontend)
    participant Auth as auth.Handler
    participant Svc as auth.Service
    participant Redis as Redis
    participant SMTP as SMTP Server
    participant DB as MySQL

    U->>SPA: 填写 email，点击"发送验证码"
    SPA->>Auth: POST /v1/auth/email/send-code {purpose, email}
    Auth->>Auth: 正则化 purpose (register/password_reset)
    Auth->>Svc: SendEmailCode(ctx, purpose, email)
    Svc->>DB: 检查 email 是否已注册 (仅 register)
    Svc->>Svc: generateEmailCode() → 6位数字
    Svc->>Redis: SET auth:email_code:<purpose>:<email> = code, EX 600
    Svc->>SMTP: 发送验证码邮件
    Auth-->>SPA: {"sent": true}
    SPA-->>U: "验证码已发送"

    Note over U,DB: 验证码 10 分钟有效
```

## 2. 密码登录 → Token 签发

```mermaid
sequenceDiagram
    actor U as User
    participant Auth as auth.Handler
    participant Lock as lockout.Manager
    participant Svc as auth.Service
    participant Sess as session.Service
    participant DB as MySQL
    participant Redis as Redis

    U->>Auth: POST /v1/auth/login {email, password}
    Auth->>Auth: 检查 localPasswordLoginEnabled
    Auth->>Lock: 检查是否锁定 (redis GET lockout key)
    alt 已锁定
        Auth-->>U: 429 Retry-After
    end
    Auth->>Svc: Login(ctx, input)
    Svc->>DB: SELECT * FROM users WHERE email=? AND status='active'
    Svc->>Svc: bcrypt.CompareHashAndPassword()
    alt 密码错误
        Svc->>Lock: 记录失败 (Redis INCR + EXPIRE)
        Auth-->>U: 401 Unauthorized
    end
    Svc->>Svc: 检查 2FA 是否启用
    alt 2FA 已启用
        Svc->>Redis: 创建 2FA challenge (TTL 5min)
        Auth-->>U: {"two_factor_required": true, "challenge_id": ..., "methods": ["totp","recovery_code"]}
    else 无 2FA
        Svc->>Sess: IssueTokens(ctx, user, tenantID, clientID)
        Sess->>Sess: 生成 sessionID + familyID
        Sess->>DB: INSERT login_sessions
        Sess->>Sess: signAccessToken (RS256 JWT, claims: sub,sid,tid,ver,jti,email…)
        Sess->>Sess: 生成 refreshToken (32字节随机)
        Sess->>DB: INSERT refresh_tokens (token_hash = SHA256(token))
        Sess->>Sess: IssueOIDCAuthorizeCookie (RS256 JWT cookie)
        Auth-->>U: {"access_token":"eyJ...", "refresh_token":"...", "session_id":"..."}
        Auth-->>Browser: Set-Cookie: goauth_oidc_session=...
    end
```

## 3. Token 刷新 + 复用检测

```mermaid
sequenceDiagram
    actor U as Client App
    participant Sess as session.Service
    participant DB as MySQL

    U->>Sess: POST /v1/auth/refresh {refresh_token}
    Sess->>Sess: SHA256(refresh_token)
    Sess->>DB: SELECT * FROM refresh_tokens WHERE token_hash=?
    alt Token 不存在
        Sess-->>U: 401 Invalid Token
    end
    Sess->>DB: 检查 revoked_at
    alt 已被撤销 (复用检测!)
        Sess->>DB: UPDATE login_sessions SET revoked_at=now WHERE id=?
        Sess->>DB: UPDATE refresh_tokens SET revoked_at=now WHERE family_id=?
        Note over Sess,DB: 整个 token family 全部撤销！
        Sess->>DB: INSERT audit_logs (action=refresh_token_reuse_detected)
        Sess-->>U: 401 Token Family Revoked
    end
    Sess->>DB: SELECT * FROM users WHERE id=? AND status='active'
    Sess->>DB: 检查 token_version 匹配
    alt 版本不匹配 (改密码/全登出)
        Sess-->>U: 401 Token Expired
    end
    Sess->>DB: SELECT * FROM tenant_members WHERE tenant_id=? AND user_id=? AND status='active'
    Sess->>DB: SELECT ... FOR UPDATE login_sessions (锁定会话)
    Sess->>DB: UPDATE refresh_tokens SET revoked_at=now WHERE id=? AND revoked_at IS NULL
    alt RowsAffected != 1 (并发冲突)
        Sess-->>U: 409 Token Reuse Detected
    end
    Sess->>Sess: 签发新 Access Token + Refresh Token (同一 familyID)
    Sess->>DB: INSERT refresh_tokens (新 token)
    Sess->>DB: UPDATE refresh_tokens SET replaced_by_token_id=? WHERE id=? (旧 token)
    Sess-->>U: {"access_token":"eyJ...", "refresh_token":"...", "session_id":"..."}
```

## 4. OIDC Authorization Code + PKCE

```mermaid
sequenceDiagram
    actor U as User (Browser)
    participant Biz as Business App
    participant OIDC as oidc.Handler
    participant DB as MySQL

    Note over U,OIDC: Step 1: 授权请求
    U->>Biz: 点击"使用 GoAuth 登录"
    Biz->>U: 302 → /oauth2/authorize?client_id=...&redirect_uri=...&code_challenge=...&state=...
    U->>OIDC: GET /oauth2/authorize?...
    OIDC->>DB: 验证 client_id (存在 + active + 支持 authorization_code)
    OIDC->>DB: 验证 redirect_uri 匹配注册值
    OIDC->>OIDC: 验证 code_challenge 存在 (PKCE 强制)
    OIDC->>Browser: 读取 goauth_oidc_session cookie

    alt 无有效 SSO Cookie
        OIDC->>U: 302 → /login?return_to=/oauth2/authorize?...
        U->>SPA: 登录页 → 完成登录
        SPA->>OIDC: 返回 /oauth2/authorize (带 cookie)
    end

    OIDC->>OIDC: 验证 cookie JWT 签名 (RS256)
    OIDC->>DB: 检查 LoginSession 活跃 + 用户 active
    OIDC->>DB: 检查租户成员身份
    OIDC->>OIDC: 生成 authorization_code (32字节随机)
    OIDC->>DB: INSERT oauth_authorization_codes (code_hash=SHA256(code), ...)
    OIDC->>U: 302 → redirect_uri?code=<code>&state=<state>

    Note over U,DB: Step 2: Token 交换
    U->>Biz: GET /callback?code=...&state=...
    Biz->>Biz: 验证 state 匹配 (防 CSRF)
    Biz->>OIDC: POST /oauth2/token {grant_type:"authorization_code", code, code_verifier, redirect_uri}
    OIDC->>DB: SELECT * FROM oauth_authorization_codes WHERE code_hash=SHA256(code)
    OIDC->>OIDC: 交叉验证: client_id, redirect_uri, tenant_id
    OIDC->>OIDC: 检查 consumed_at IS NULL + expires_at > now
    OIDC->>OIDC: PKCE 验证: S256 → SHA256(verifier) vs challenge; plain → 直接比较
    OIDC->>DB: 检查 user active + 租户成员身份
    OIDC->>DB: SELECT ... FOR UPDATE login_sessions
    OIDC->>DB: UPDATE oauth_authorization_codes SET consumed_at=now (原子消费)
    OIDC->>OIDC: signAccessToken (OIDC-scoped, token_use="oidc")
    OIDC->>OIDC: signIDToken (OIDC claims: sub,aud,nonce…)
    OIDC->>OIDC: 如果 scope 含 offline_access → 生成 RefreshToken
    OIDC-->>Biz: {"access_token":"...", "id_token":"...", "refresh_token":"...", "token_type":"Bearer"}
    Biz->>OIDC: GET /oauth2/userinfo (Authorization: Bearer access_token)
    OIDC-->>Biz: {"sub":"1", "email":"user@example.com", ...}
```

## 5. GitHub 外部登录

```mermaid
sequenceDiagram
    actor U as User (Browser)
    participant SPA as Frontend
    participant IDP as idp.Handler
    participant GH as GitHub OAuth
    participant DB as MySQL
    participant Prov as provisioning.Policy

    U->>SPA: 点击 "GitHub 登录"
    SPA->>IDP: GET /v1/external/github/start
    IDP->>IDP: 生成 OAuth state (32字节随机)
    IDP->>Redis: SET auth:external_oauth_state:<state> (TTL 10min)
    IDP-->>SPA: {"url": "https://github.com/login/oauth/authorize?..."}

    SPA->>GH: 重定向到 GitHub 授权页
    U->>GH: 授权
    GH->>IDP: GET /v1/external/github/callback?code=...&state=...
    IDP->>Redis: 验证 state 存在
    IDP->>GH: POST /login/oauth/access_token {code, client_id, client_secret}
    GH-->>IDP: access_token
    IDP->>GH: GET /user (获取 profile + emails)
    GH-->>IDP: GitHub user profile

    IDP->>DB: 查找 user_identities (provider="github", provider_user_id)
    alt 已有绑定
        IDP->>DB: 加载关联 user
    else 邮箱已存在
        IDP->>IDP: 要求用户先本地登录再绑定 (返回 error)
    else 新用户
        IDP->>DB: INSERT users (email, display_name, avatar_url from GitHub)
        IDP->>DB: INSERT user_identities
        IDP->>Prov: ApplyDefaultMembership(userID)
    end

    IDP->>IDP: 生成一次性 exchange_code (60s TTL)
    IDP->>Redis: SET auth:external_login_exchange:<code> = user_id EX 60
    IDP->>SPA: 302 → frontend?code=<exchange_code>

    SPA->>IDP: POST /v1/external/github/exchange {code}
    IDP->>Redis: GET exchange code → userID
    IDP->>IDP: IssueTokens + IssueOIDCAuthorizeCookie
    IDP-->>SPA: {"access_token":"...", "refresh_token":"..."}
```

## 6. 浏览器 SSO Cookie 流程

```mermaid
sequenceDiagram
    actor U as User (Browser)
    participant SPA as Frontend
    participant Session as session.Service
    participant OIDC as oidc.Handler

    Note over U,OIDC: 登录时签发 SSO Cookie
    U->>SPA: 成功登录
    SPA->>Session: IssueTokens
    Session->>Session: IssueOIDCAuthorizeCookie(user, tenantID, sessionID)
    Session->>Browser: Set-Cookie: goauth_oidc_session=<JWT>; SameSite=Lax; HttpOnly; Path=/
    Note over Session,Browser: Cookie JWT claims: purpose="oidc_authorize", sub=userID, sid=sessionID, tid=tenantID

    Note over U,OIDC: 后续 OIDC 授权自动通过
    U->>OIDC: GET /oauth2/authorize?client_id=...
    OIDC->>Browser: 自动附带 goauth_oidc_session cookie
    OIDC->>OIDC: ParseOIDCAuthorizeCookie (验证 RS256 签名 + purpose)
    OIDC->>OIDC: 提取 userID + sessionID
    OIDC->>DB: 验证 LoginSession 活跃 + user active
    OIDC->>OIDC: 生成 authorization_code (无需用户交互)
    OIDC->>U: 302 → redirect_uri?code=...

    Note over U,OIDC: 登出时清除
    U->>OIDC: POST /v1/auth/logout
    OIDC->>Session: ClearOIDCAuthorizeCookie()
    OIDC->>Browser: Set-Cookie: goauth_oidc_session=; Max-Age=0
```
