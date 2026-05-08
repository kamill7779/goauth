# GoAuth Design

Date: 2026-05-08

## Goal

Build GoAuth, a standalone, deployable identity service that can be used as a system scaffold for future projects. It should provide email-first account registration, login, token lifecycle management, tenant-scoped RBAC, user administration, and OAuth2/OpenID Connect provider capabilities out of the box.

The service is not a library embedded into the current gateway. It is an independent service that other systems integrate with over HTTP/OIDC.

## Non-Goals

- Do not move business concepts such as quota, billing, model groups, channel keys, subscriptions, or invitation rewards into the identity service.
- Do not implement a full ABAC policy engine in the first version.
- Do not implement DAC as the primary permission model.
- Do not require other systems to share the identity service database.
- Do not make third-party OAuth login the primary product shape. External OAuth providers are optional upstream identity sources.

## Product Shape

The service provides two OAuth-related capabilities that must remain separate in code and documentation:

1. OIDC Provider
   - The identity service is the authorization server and identity provider.
   - Business systems register as OAuth clients.
   - Business systems redirect users to this service for login.
   - This service returns authorization codes, ID tokens, access tokens, refresh tokens, JWKS, and userinfo.

2. External Identity Provider adapters
   - This service can also let users sign in through external providers.
   - The first external provider is GitHub.
   - External login only establishes or binds a local user identity. After that, this service still issues its own tokens and RBAC context to downstream business systems.

## Recommended Permission Model

Use tenant-scoped RBAC as the first version.

```text
User -> TenantMember -> Role -> Permission
```

Meaning:

- A user can belong to many tenants.
- A user becomes a tenant member inside each tenant.
- A member can have one or more roles.
- A role contains permissions.
- Permissions are named strings using `resource:action`, for example `user:read`, `member:invite`, or `project:create`.

RBAC is the right default because it is simple to configure, easy to reason about, easy to expose in an admin API, and suitable for most scaffolded systems. ABAC can be added later through a separate policy extension layer if a real product need appears.

## Architecture

```text
cmd/server
  main.go

internal/config
  Environment and typed config loading.

internal/http
  Gin router, middleware, request binding, response helpers.

internal/auth
  Email registration, password login, password reset, access token issuing.

internal/session
  Refresh token rotation, device sessions, logout, revocation.

internal/oidc
  OAuth2 authorization server and OpenID Connect provider endpoints.

internal/idp
  External identity provider abstraction.

internal/idp/github
  GitHub OAuth2 adapter.

internal/rbac
  Tenant-scoped role and permission checks.

internal/user
  User profile and admin user management.

internal/tenant
  Tenant and tenant member management.

internal/store
  GORM models and repositories.

internal/cache
  Redis client and typed cache keys.

internal/mailer
  SMTP email sender.

internal/audit
  Audit event recording.

pkg/client
  Optional Go client for business services.
```

Layering:

```text
router -> handler -> service -> repository -> database/cache
```

Handlers should only parse requests, call services, and return responses. Business rules belong in services. Repositories hide GORM details. Redis key names and TTLs are centralized in `internal/cache`.

## Storage

MySQL is the primary target. GORM should still be used so the schema remains portable enough for local SQLite tests and future PostgreSQL compatibility.

Recommended tables:

```text
users
  id
  email
  email_verified_at
  password_hash
  display_name
  avatar_url
  status
  token_version
  created_at
  updated_at
  deleted_at

user_identities
  id
  user_id
  provider
  provider_user_id
  email
  email_verified
  username
  display_name
  avatar_url
  created_at
  updated_at

tenants
  id
  name
  slug
  status
  created_at
  updated_at
  deleted_at

tenant_members
  id
  tenant_id
  user_id
  status
  created_at
  updated_at
  deleted_at

roles
  id
  tenant_id
  name
  code
  description
  is_system
  created_at
  updated_at

permissions
  id
  resource
  action
  code
  description
  created_at
  updated_at

role_permissions
  role_id
  permission_id

member_roles
  member_id
  role_id

oauth_clients
  id
  tenant_id
  client_id
  client_secret_hash
  name
  redirect_uris
  allowed_scopes
  grant_types
  token_endpoint_auth_method
  status
  created_at
  updated_at

oauth_authorization_codes
  id
  code_hash
  client_id
  user_id
  tenant_id
  redirect_uri
  scope
  code_challenge
  code_challenge_method
  nonce
  expires_at
  consumed_at
  created_at

refresh_tokens
  id
  token_hash
  family_id
  session_id
  user_id
  tenant_id
  client_id
  user_agent
  ip_address
  expires_at
  revoked_at
  replaced_by_token_id
  created_at

external_provider_configs
  id
  provider
  name
  client_id
  client_secret_ciphertext
  scopes
  enabled
  created_at
  updated_at

audit_logs
  id
  actor_user_id
  tenant_id
  action
  target_type
  target_id
  ip_address
  user_agent
  metadata
  created_at
```

Important constraints:

- `users.email` is unique for active users.
- `user_identities` has unique `(provider, provider_user_id)`.
- `user_identities` has unique `(user_id, provider)` for one identity per provider per local user.
- `tenants.slug` is unique.
- `roles` has unique `(tenant_id, code)`.
- `permissions.code` is unique.
- `oauth_clients.client_id` is unique.
- Refresh tokens are stored as hashes only.
- Authorization codes are stored as hashes only.

## Redis

Redis is used for hot paths and ephemeral state. MySQL remains the source of truth.

```text
auth:email_code:{purpose}:{email}
auth:rate:{scope}:{key}
auth:user:{user_id}
auth:session:{session_id}
auth:permissions:{tenant_id}:{user_id}
auth:jti_denylist:{jti}
auth:oidc_state:{state}
auth:pkce:{state}
```

Recommended TTLs:

- Email verification code: 10 minutes
- Password reset code: 10 minutes
- OIDC state: 10 minutes
- Authorization code: 5 minutes
- Access token denylist entry: until token expiry
- Permission cache: 1 to 5 minutes
- User cache: 1 to 5 minutes

## Token Design

Access tokens are JWTs. Refresh tokens are opaque random strings.

Default lifetimes:

- Access token: 15 minutes
- Refresh token: 30 days
- Authorization code: 5 minutes

Access token claims:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user_id",
  "aud": "client_id",
  "tid": "tenant_id",
  "sid": "session_id",
  "email": "user@example.com",
  "email_verified": true,
  "roles": ["admin"],
  "permissions": ["user:read", "member:invite"],
  "ver": 3,
  "iat": 1710000000,
  "exp": 1710000900,
  "jti": "random_id"
}
```

ID token claims should follow OIDC expectations and include `iss`, `sub`, `aud`, `exp`, `iat`, `nonce` when requested, `email`, `email_verified`, `name`, and `picture` when available.

Refresh token rules:

- Store only a hash of the token.
- Rotate refresh tokens on every refresh.
- Track token family ID for reuse detection.
- If an old refresh token is reused after rotation, revoke the whole token family.
- Support single-session logout and all-session logout.
- Increment `users.token_version` to invalidate all existing access tokens for a user.

## OIDC Provider Endpoints

```text
GET  /.well-known/openid-configuration
GET  /oauth2/authorize
POST /oauth2/token
GET  /oauth2/userinfo
GET  /oauth2/jwks
POST /oauth2/introspect
POST /oauth2/revoke
GET  /oauth2/logout
```

Required flows for the first version:

- Authorization Code + PKCE
- Refresh Token

Optional first-version flow:

- Client Credentials for service-to-service clients if a concrete use case exists.

Do not support implicit flow.

## Auth and User API

```text
POST /v1/auth/email/send-code
POST /v1/auth/register
POST /v1/auth/login
POST /v1/auth/refresh
POST /v1/auth/logout
POST /v1/auth/logout-all
POST /v1/auth/password/forgot
POST /v1/auth/password/reset
GET  /v1/auth/me
```

## External Provider API

```text
GET    /v1/external/github/start
GET    /v1/external/github/callback
POST   /v1/external/github/bind
DELETE /v1/external/github/bind
GET    /v1/me/identities
```

External provider behavior:

- If a GitHub identity already exists, login as the bound local user.
- If a GitHub identity does not exist but its verified email already belongs to a local user, require local login before binding.
- If neither identity nor email exists, create a local user and bind the identity.
- If the request is made by a logged-in user, bind the GitHub identity to that user unless it is already bound elsewhere.

## RBAC and Tenant API

```text
POST /v1/authz/check
POST /v1/authz/check-batch
GET  /v1/tenants/:tenant_id/my-permissions

GET    /v1/admin/tenants
POST   /v1/admin/tenants
PATCH  /v1/admin/tenants/:id
POST   /v1/admin/tenants/:id/members
DELETE /v1/admin/tenants/:id/members/:user_id

GET    /v1/admin/roles
POST   /v1/admin/roles
PATCH  /v1/admin/roles/:id
DELETE /v1/admin/roles/:id
POST   /v1/admin/roles/:id/permissions
DELETE /v1/admin/roles/:id/permissions/:permission_id
POST   /v1/admin/members/:member_id/roles
DELETE /v1/admin/members/:member_id/roles/:role_id
```

`/v1/authz/check` should accept:

```json
{
  "user_id": 1,
  "tenant_id": 10,
  "permission": "project:create"
}
```

and return:

```json
{
  "allowed": true
}
```

## CORS

Use an allowlist. Do not combine wildcard origins with credentials.

Configuration:

```text
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
CORS_ALLOWED_METHODS=GET,POST,PUT,PATCH,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Tenant-ID
CORS_ALLOW_CREDENTIALS=true
```

## Configuration

Use `.env` for local and Docker Compose deployments.

Required configuration:

```text
APP_ENV
HTTP_ADDR
PUBLIC_ISSUER_URL
MYSQL_DSN
REDIS_URL
JWT_PRIVATE_KEY_PATH
JWT_KEY_ID
ACCESS_TOKEN_TTL
REFRESH_TOKEN_TTL
SMTP_HOST
SMTP_PORT
SMTP_USERNAME
SMTP_PASSWORD
SMTP_FROM
CORS_ALLOWED_ORIGINS
```

GitHub external provider configuration:

```text
GITHUB_OAUTH_ENABLED
GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET
GITHUB_REDIRECT_URI
```

## Security Requirements

- Passwords are hashed with bcrypt or argon2id.
- Client secrets are stored as hashes.
- Refresh tokens and authorization codes are stored as hashes.
- Access token signing keys support rotation through JWKS.
- Login, email code, password reset, token refresh, and authorization endpoints are rate limited.
- OIDC state and PKCE are required.
- CSRF protection is required for browser session endpoints if cookie sessions are used.
- Audit logs are written for login, logout, password changes, role changes, tenant membership changes, client changes, and token revocation.

## Deployment

The first delivery should include Docker Compose:

```text
auth-service
mysql
redis
```

The service should start from:

```bash
docker compose up -d
```

Local development should support:

```bash
go run ./cmd/server
```

## Testing Strategy

Unit tests:

- Password hashing and validation.
- JWT creation and validation.
- Refresh token hashing, rotation, and reuse detection.
- RBAC permission resolution.
- GitHub profile normalization.

Integration tests:

- Registration with email verification.
- Login and refresh.
- Logout and token revocation.
- Authorization code + PKCE flow.
- Userinfo with access token.
- Tenant role assignment and permission checks.

Compatibility tests:

- MySQL as the primary integration database.
- SQLite for fast local tests where possible.
- Redis-backed verification codes and rate limits.

## Implementation Order

1. Project skeleton and configuration.
2. Store models and migrations.
3. Redis cache wrapper.
4. Email registration and password login.
5. Access token and refresh token lifecycle.
6. Tenant-scoped RBAC.
7. OIDC provider endpoints.
8. External provider abstraction and GitHub adapter.
9. Admin APIs.
10. Docker Compose and sample client documentation.
