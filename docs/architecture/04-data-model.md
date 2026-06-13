# 04 — Data Model

GoAuth 的存储模型：MySQL 表结构（17 张表）+ Redis Key 体系。

## ER 图

```mermaid
erDiagram
    User ||--o{ UserIdentity : "has"
    User ||--o| UserTwoFactor : "configures"
    User ||--o{ TenantMember : "belongs to"
    User ||--o{ RefreshToken : "holds"
    User ||--o{ LoginSession : "has"
    User ||--o{ OAuthAuthorizationCode : "authorizes"
    User ||--o{ AuditLog : "triggers"
    User ||--o{ PasswordHistory : "tracks"

    Tenant ||--o{ TenantMember : "contains"
    Tenant ||--o{ Role : "defines"
    Tenant ||--o{ OAuthClient : "owns"
    Tenant ||--o{ Invite : "issues"

    TenantMember ||--o{ MemberRole : "assigned"
    TenantMember ||--o{ LoginSession : "scoped to"

    Role ||--o{ RolePermission : "grants"
    Role ||--o{ MemberRole : "assigned to"
    Role }o--|| Tenant : "belongs to"

    Permission ||--o{ RolePermission : "included in"

    OAuthClient ||--o{ OAuthAuthorizationCode : "requests"
    OAuthClient ||--o{ RefreshToken : "associated"

    LoginSession ||--o{ RefreshToken : "linked to"

    User {
        int64 ID PK
        string Email UK
        string Username UK
        string Nickname
        string Locale
        time EmailVerifiedAt
        string PasswordHash
        string DisplayName
        string AvatarURL
        string Status
        int TokenVersion
        time CreatedAt
        time UpdatedAt
        time DeletedAt
    }

    Tenant {
        int64 ID PK
        string Name
        string Slug UK
        string Status
        time CreatedAt
        time UpdatedAt
        time DeletedAt
    }

    TenantMember {
        int64 ID PK
        int64 TenantID FK
        int64 UserID FK
        string Status
        int PermissionVersion
        time CreatedAt
        time UpdatedAt
        time DeletedAt
    }

    Role {
        int64 ID PK
        int64 TenantID FK
        string Name
        string Code
        string Description
        bool IsSystem
        time CreatedAt
        time UpdatedAt
    }

    Permission {
        int64 ID PK
        string Resource
        string Action
        string Code UK
        string Description
        time CreatedAt
        time UpdatedAt
    }

    RolePermission {
        int64 RoleID PK_FK
        int64 PermissionID PK_FK
    }

    MemberRole {
        int64 MemberID PK_FK
        int64 RoleID PK_FK
    }

    OAuthClient {
        int64 ID PK
        int64 TenantID FK
        string ClientID UK
        string ClientSecretHash
        string Name
        json RedirectURIs
        json AllowedScopes
        json GrantTypes
        string TokenEndpointAuthMethod
        string Status
        time CreatedAt
        time UpdatedAt
    }

    OAuthAuthorizationCode {
        int64 ID PK
        string CodeHash UK
        int64 ClientID FK
        int64 UserID FK
        int64 TenantID FK
        string SessionID FK
        string RedirectURI
        string Scope
        string CodeChallenge
        string CodeChallengeMethod
        string Nonce
        time ExpiresAt
        time ConsumedAt
        time CreatedAt
    }

    RefreshToken {
        int64 ID PK
        string TokenHash UK
        string FamilyID FK
        string SessionID FK
        int64 UserID FK
        int64 TenantID FK
        int64 TokenVersion
        int64 ClientID FK
        string UserAgent
        string IPAddress
        time ExpiresAt
        time RevokedAt
        int64 ReplacedByTokenID
        time CreatedAt
    }

    LoginSession {
        string ID PK
        int64 UserID FK
        int64 TenantID FK
        int64 ClientID FK
        time RevokedAt
        time CreatedAt
    }

    UserIdentity {
        int64 ID PK
        int64 UserID FK
        string Provider
        string ProviderUserID
        string Email
        bool EmailVerified
        string Username
        string DisplayName
        string AvatarURL
        time CreatedAt
    }

    UserTwoFactor {
        int64 ID PK
        int64 UserID FK_UK
        bool Enabled
        string Secret
        json RecoveryCodeHashes
        time CreatedAt
        time UpdatedAt
    }

    AuditLog {
        int64 ID PK
        int64 ActorUserID FK
        int64 TenantID FK
        string Action
        string TargetType
        string TargetID
        string IPAddress
        string UserAgent
        json Metadata
        time CreatedAt
    }

    PasswordHistory {
        int64 ID PK
        int64 UserID FK
        string PasswordHash
        time CreatedAt
    }

    Invite {
        int64 ID PK
        string TokenHash UK
        int64 TenantID FK
        string TargetEmail
        string Status
        time ExpiresAt
        time CreatedAt
    }

    ExternalProviderConfig {
        int64 ID PK
        string Provider
        string Name
        string ClientID
        string ClientSecretCiphertext
        json Scopes
        bool Enabled
        time CreatedAt
        time UpdatedAt
    }
```

## 关键约束

| 约束 | 表 | 说明 |
|------|-----|------|
| `(email)` unique | users | 活跃用户邮箱唯一 |
| `(username)` unique | users | 用户名通过迁移后索引保证唯一 |
| `(tenant_id, user_id)` unique | tenant_members | 一个用户在一个租户最多一条成员记录 |
| `(tenant_id, code)` unique | roles | 租户内角色代码唯一 |
| `code` unique | permissions | 权限代码全局唯一 |
| `client_id` unique | oauth_clients | OAuth 客户端 ID 全局唯一 |
| `(provider, provider_user_id)` unique | user_identities | 外部身份唯一 |
| `(user_id, provider)` unique | user_identities | 一个用户一个 provider 一个绑定 |
| `Refresh Token` 只存 hash | refresh_tokens | SHA-256 哈希存储 |
| `Authorization Code` 只存 hash | oauth_authorization_codes | SHA-256 哈希存储 |
| `Client Secret` 只存 hash | oauth_clients | 不存明文 |

## Redis Key 体系

```
auth:email_code:<purpose>:<email>           → 验证码 (TTL: 10min)
auth:rate:<scope>:<key>                     → 限流计数 (滑动窗口)
auth:user:<user_id>                         → 用户缓存 (TTL: 5min)
auth:session:<session_id>                   → 会话状态
auth:permissions:<tenant_id>:<user_id>      → 权限缓存 (TTL: 2min)
auth:jti_denylist:<jti>                     → JTI 黑名单 (TTL: 到 token 过期)
auth:oidc_state:<state>                     → OIDC CSRF state (TTL: 10min)
auth:external_oauth_state:<state>           → GitHub OAuth state (TTL: 10min)
auth:external_login_exchange:<code>         → GitHub 交换码 (TTL: 60s)
auth:lockout:<email>                        → 登录锁定计数 (TTL: lockout_duration)
auth:two_factor_challenge:<challenge_id>    → 2FA 挑战 (TTL: 5min)
auth:two_factor_lock:<challenge_id>         → 2FA 并发锁 (TTL: 10s)
```

所有 Key 定义在 `services/identity-service/internal/cache/keys.go`。
