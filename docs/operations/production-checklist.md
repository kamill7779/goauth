# Production Checklist

Use this checklist before exposing GoAuth to public traffic.

## Runtime

- Set `APP_ENV=production`.
- Set `PUBLIC_ISSUER_URL` to the externally reachable HTTPS origin, for example `https://auth.example.com`.
- Confirm discovery returns that exact issuer:

```powershell
curl https://auth.example.com/.well-known/openid-configuration
```

- Set `BROWSER_COOKIE_SECURE=true`.
- Configure `TRUSTED_PROXIES` when GoAuth runs behind a controlled reverse proxy and rate limits rely on the real client IP.

## Storage

- Use persistent MySQL:

```env
MYSQL_DSN=<user>:<password>@tcp(<host>:3306)/goauth_identity?charset=utf8mb4&parseTime=True&loc=Local
```

- Use persistent Redis:

```env
REDIS_URL=redis://:<password>@<host>:6379/0
```

- Back up MySQL.
- Persist or back up avatar storage if account avatars are enabled.

## Signing Keys

Do not use local ephemeral signing keys in production.

Recommended keyset mode:

```env
JWT_KEYSET_DIR=/run/secrets/goauth-jwt-keys
JWT_ACTIVE_KEY_ID=2026-05-prod
```

Alternative legacy single-key mode:

```env
JWT_PRIVATE_KEY_PATH=/run/secrets/goauth-jwt.pem
JWT_KEY_ID=2026-05-prod
```

Business apps cache JWKS. During rotation, keep old verification keys in JWKS until old tokens expire.

## Registration And Login

- Set `REGISTRATION_MODE=invite_only` or `disabled` before public traffic.
- Keep `LOCAL_PASSWORD_LOGIN_ENABLED=true` only when local password login is intended.
- Enable CAPTCHA for exposed registration, login, email code, and password reset flows:

```env
CAPTCHA_PROVIDER=turnstile
CAPTCHA_SITE_KEY=<public-site-key>
CAPTCHA_SECRET_KEY=<secret-key>
CAPTCHA_ACTIONS=login,register,email_code,password_forgot
```

- Enable the self-hosted slider human check for open registration:

```env
HUMAN_CHECK_PROVIDER=slider
HUMAN_CHECK_ACTIONS=register
HUMAN_CHECK_CHALLENGE_TTL=2m
HUMAN_CHECK_TOKEN_TTL=3m
```

## Email

- Set `MAILER_PROVIDER=smtp`.
- Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`.
- Verify a real registration email.
- Verify a real password reset email.
- Store SMTP password or authorization code in a secret manager.

See [SMTP Configuration](../deployment/smtp.md).

## Bootstrap Admin

Bootstrap admin is for first setup only:

```env
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=<temporary-password>
BOOTSTRAP_ADMIN_ROLE=root
```

After creating real administrators:

- Remove `BOOTSTRAP_ADMIN_PASSWORD`.
- Restart the service.
- Confirm Admin Console runtime diagnostics no longer warn about bootstrap password.

## OAuth Clients

For each business app:

- Use exact redirect URIs.
- Use HTTPS redirect URIs outside local development.
- Allow only required scopes.
- Allow `refresh_token` only when the app needs long-lived sessions.
- Store client secrets server-side only.
- Rotate client secrets when leaked or when ownership changes.

## Reverse Proxy

Proxy these paths to identity-service:

- `/.well-known/*`
- `/oauth2/*`
- `/v1/*`
- `/metrics` if exposed internally

Serve the frontend static app for:

- `/`
- `/login`
- `/account`
- `/admin`
- `/external/callback`

See [Docker Compose Deployment](../deployment/docker-compose.md).

## Runtime Diagnostics

Open Admin Console Settings and verify:

- No `error` diagnostics.
- No unexpected `warning` diagnostics.
- Registration mode is not accidentally `open`.
- Public config does not expose secrets.

Useful checks:

```powershell
curl https://auth.example.com/readyz
curl https://auth.example.com/v1/auth/public-config
```

## Observability

- Keep structured logs.
- Restrict `/metrics` to internal networks.
- Alert on repeated SMTP failures, Redis failures, database readiness failures, and high authentication error rates.

## Final Go-Live Test

Run the black-box OIDC test against the production-like deployment:

```powershell
$env:GOAUTH_BASE_URL="https://auth.example.com"
$env:GOAUTH_TEST_EMAIL="oidc-smoke@example.com"
$env:GOAUTH_TEST_PASSWORD="<password>"
$env:GOAUTH_CLIENT_ID="smoke-client"
$env:GOAUTH_CLIENT_SECRET="<client-secret>"
$env:GOAUTH_REDIRECT_URI="https://app.example.com/callback"
node scripts/oidc-e2e.mjs --check-config
node scripts/oidc-e2e.mjs
```
