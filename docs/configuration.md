# Configuration Matrix

GoAuth reads runtime configuration from environment variables at startup. This page is the human-readable companion to `services/identity-service/internal/config/schema.go`; keep the code schema, `.env.example`, Docker Compose defaults, and this document in sync.

## Rules

- Local defaults favor a fast open-source trial: registration is open, mail uses `console`, CAPTCHA and GitHub login are disabled.
- Production must provide persistent MySQL, Redis, and JWT signing key material.
- Values marked secret must never be returned by `GET /v1/auth/public-config` or `GET /v1/admin/runtime-config`.
- `GET /v1/auth/public-config` exposes only browser-safe values for rendering the login/register experience.
- `GET /v1/admin/runtime-config` exposes read-only diagnostic status, not raw secret values.

## Matrix

| Variable | Group | Default | Production | Secret | Public config | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `APP_ENV` | core | `development` | optional | no | no | Set `production` to enable production diagnostics. |
| `HTTP_ADDR` | core | `:8080` | optional | no | no | Container listens on `:8080`; use Compose port mapping for host port. |
| `PUBLIC_ISSUER_URL` | core | `http://127.0.0.1:8080` | required | no | yes | Must be the externally reachable issuer; production must use HTTPS. |
| `BROWSER_LOGIN_URL` | core | `/login` | optional | no | no | Browser login page used by OIDC redirects. |
| `BROWSER_COOKIE_SECURE` | core | derived | optional | no | no | Defaults from `PUBLIC_ISSUER_URL` scheme. |
| `MYSQL_DSN` | storage | empty | required | yes | no | Empty uses in-memory SQLite only for local tests/dev. |
| `REDIS_URL` | storage | empty | required | yes | no | Empty defaults to local Redis in code paths that require Redis. |
| `JWT_PRIVATE_KEY_PATH` | tokens | empty | required | yes | no | Empty generates an ephemeral local key; do not use empty in production. |
| `JWT_KEY_ID` | tokens | empty | required | no | no | Stable `kid` for JWKS and token headers. |
| `ACCESS_TOKEN_TTL` | tokens | `15m` | optional | no | no | Access token lifetime. |
| `BROWSER_SESSION_TTL` | tokens | `12h` | optional | no | no | Browser SSO session lifetime. |
| `REFRESH_TOKEN_TTL` | tokens | `720h` | optional | no | no | Refresh token lifetime. |
| `TRUSTED_PROXIES` | network | empty | conditional | no | no | Required behind controlled proxies when real client IP matters. |
| `CORS_ALLOWED_ORIGINS` | network | empty | conditional | no | no | Required for separated frontend origins. |
| `CORS_ALLOWED_METHODS` | network | `GET,POST,PUT,PATCH,DELETE` | optional | no | no | CORS methods. |
| `CORS_ALLOWED_HEADERS` | network | `Authorization,Content-Type,X-Captcha-Token` | optional | no | no | Must include `X-Captcha-Token` when CAPTCHA is used cross-origin. |
| `CORS_ALLOW_CREDENTIALS` | network | derived | optional | no | no | Defaults true for explicit origins, false for wildcard/empty. |
| `MAILER_PROVIDER` | mailer | `console` | required | no | yes | `console`, `smtp`, or `noop`; production should use `smtp`. |
| `SMTP_HOST` | mailer | empty | conditional | no | no | Required when `MAILER_PROVIDER=smtp`. |
| `SMTP_PORT` | mailer | `587` | optional | no | no | Use `465` with `SMTP_SSL=true` for SMTPS. |
| `SMTP_USERNAME` | mailer | empty | conditional | no | no | Optional only for unauthenticated SMTP relays. |
| `SMTP_PASSWORD` | mailer | empty | conditional | yes | no | SMTP password. |
| `SMTP_FROM` | mailer | empty | conditional | no | no | Required when `MAILER_PROVIDER=smtp`. |
| `SMTP_SSL` | mailer | `false` | optional | no | no | Enables SMTPS direct TLS. |
| `SMTP_AUTH_LOGIN` | mailer | `false` | optional | no | no | Enables `AUTH LOGIN`; default is `AUTH PLAIN`. |
| `REGISTRATION_MODE` | auth_entry | `open` | optional | no | yes | `open`, `invite_only`, or `disabled`; production usually uses `invite_only`. |
| `LOCAL_PASSWORD_LOGIN_ENABLED` | auth_entry | `true` | optional | no | yes | Controls password login form and endpoint availability. |
| `BRAND_NAME` | branding | `GoAuth` | optional | no | yes | Public product/tenant display name. |
| `BRAND_TAGLINE` | branding | empty | optional | no | yes | Public brand tagline. |
| `BRAND_ICON_TEXT` | branding | `G` | optional | no | yes | Fallback text icon when no icon URL is set. |
| `BRAND_ICON_URL` | branding | empty | optional | no | yes | Same-origin or CDN icon URL. |
| `GITHUB_OAUTH_ENABLED` | external_login | `false` | optional | no | yes | Public config only exposes GitHub when the full provider config is valid. |
| `GITHUB_CLIENT_ID` | external_login | empty | conditional | no | no | Required when GitHub login is enabled. |
| `GITHUB_CLIENT_SECRET` | external_login | empty | conditional | yes | no | Required when GitHub login is enabled. |
| `GITHUB_REDIRECT_URI` | external_login | derived | conditional | no | no | Defaults to `${PUBLIC_ISSUER_URL}/v1/external/github/callback`. |
| `CAPTCHA_PROVIDER` | captcha | empty | optional | no | yes | Browser frontend currently supports Turnstile. |
| `CAPTCHA_SITE_KEY` | captcha | empty | conditional | no | yes | Public CAPTCHA site key. |
| `CAPTCHA_SECRET_KEY` | captcha | empty | conditional | yes | no | Required with provider and site key. |
| `CAPTCHA_ACTIONS` | captcha | `login,register,email_code,password_forgot` | optional | no | yes | Lowercase action allowlist. |
| `DEFAULT_MEMBER_TENANT_SLUGS` | tenancy | empty | optional | no | no | Auto-join slugs for newly created users. |
| `BOOTSTRAP_ADMIN_EMAIL` | bootstrap | empty | optional | no | no | Must be paired with bootstrap password. |
| `BOOTSTRAP_ADMIN_PASSWORD` | bootstrap | empty | optional | yes | no | Remove after first admin is created. |
| `BOOTSTRAP_ADMIN_USERNAME` | bootstrap | empty | optional | no | no | Optional username for bootstrap admin. |
| `BOOTSTRAP_ADMIN_NICKNAME` | bootstrap | empty | optional | no | no | Preferred display name field. |
| `BOOTSTRAP_ADMIN_DISPLAY_NAME` | bootstrap | empty | optional | no | no | Compatibility alias for nickname. |
| `BOOTSTRAP_ADMIN_ROLE` | bootstrap | `root` | optional | no | no | Role code assigned to bootstrap admin. |
| `LOCKOUT_THRESHOLD` | security | `5` | optional | no | no | Failed attempts before lockout. |
| `LOCKOUT_DURATION` | security | `15m` | optional | no | no | Lockout duration. |
| `PASSWORD_MIN_LENGTH` | security | `8` | optional | no | yes | Public password policy. |
| `PASSWORD_REQUIRE_UPPERCASE` | security | `false` | optional | no | yes | Public password policy. |
| `PASSWORD_REQUIRE_LOWERCASE` | security | `false` | optional | no | yes | Public password policy. |
| `PASSWORD_REQUIRE_DIGIT` | security | `true` | optional | no | yes | Public password policy. |
| `PASSWORD_REQUIRE_SPECIAL` | security | `false` | optional | no | yes | Public password policy. |
| `PASSWORD_HISTORY_COUNT` | security | `3` | optional | no | yes | Public password policy. |
| `METRICS_ENABLED` | observability | `true` | optional | no | no | Enables `/metrics`. |
| `DEFAULT_LOCALE` | i18n | `en` | optional | no | no | Default email template locale. |

## Production Checklist

1. Set `APP_ENV=production`.
2. Set HTTPS `PUBLIC_ISSUER_URL` and verify `/.well-known/openid-configuration` uses the same issuer.
3. Provide persistent `MYSQL_DSN`, `REDIS_URL`, `JWT_PRIVATE_KEY_PATH`, and `JWT_KEY_ID`.
4. Configure `MAILER_PROVIDER=smtp`, `SMTP_HOST`, `SMTP_FROM`, and verify a real email flow.
5. Configure CAPTCHA only as a complete provider/site-key/secret-key set.
6. Remove bootstrap admin secrets after the first administrator is created.
7. Open Admin Console Settings and confirm runtime diagnostics have no `error` items.
