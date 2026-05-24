# Troubleshooting

This page maps common symptoms to the part of GoAuth to check first.

## `/login` Or `/admin` Returns 404

Likely cause: only the backend Compose stack is running. The current backend container does not serve the React frontend.

Local fix:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:3000/login`.

Production fix: serve `frontend/dist` through a static server and reverse proxy API paths to identity-service. See [Docker Compose Deployment](deployment/docker-compose.md).

## `/readyz` Fails

`/readyz` checks MySQL and Redis.

Check:

```powershell
cd services/identity-service
docker compose ps
docker compose logs -f identity-service
docker compose logs -f mysql
docker compose logs -f redis
```

Common causes:

- MySQL still starting.
- Wrong `MYSQL_DSN`.
- Redis not reachable through `REDIS_URL`.
- Production secrets not injected.

## Discovery Issuer Is Wrong

Symptom:

- Business app rejects tokens.
- ID Token verification says issuer mismatch.

Check:

```powershell
curl http://127.0.0.1:8080/.well-known/openid-configuration
```

Fix `PUBLIC_ISSUER_URL` to the exact URL business apps use. In production it must be HTTPS.

## Browser Login Does Not Continue Back To App

Check:

- `BROWSER_LOGIN_URL` points to a reachable frontend login page.
- The login URL keeps the `return_to` query parameter.
- Frontend and issuer origins are trusted by the login page.
- Browser cookies are not blocked.

For local HTTP, `BROWSER_COOKIE_SECURE` should derive to `false` from an HTTP `PUBLIC_ISSUER_URL`. For HTTPS production, use `BROWSER_COOKIE_SECURE=true`.

## `invalid_request` On `/oauth2/authorize`

Likely causes:

- Missing `response_type=code`.
- Missing `redirect_uri`.
- Redirect URI does not exactly match the OAuth Client.
- Missing `code_challenge`.
- Unsupported `code_challenge_method`.

Use `S256` PKCE.

## `invalid_scope`

The requested scopes are not all in the OAuth Client allowed scopes.

Check the client in Admin Console. For normal login, allow:

```text
openid
profile
email
```

Add `offline_access` only when the app needs refresh tokens.

## `login_required`

For browser navigations, GoAuth should redirect to the login page. If you receive JSON:

- The request may not look like browser navigation.
- `Accept` headers may not include HTML.
- `BROWSER_LOGIN_URL` may be empty.
- The SSO cookie may be missing or invalid.

Start the flow from a browser redirect, not from backend HTTP code.

## `access_denied`

The authenticated user is not an active member of the OAuth Client tenant.

Fix one of:

- Add the user to the tenant.
- Enable `auto_provision_members` for public trusted clients.
- Configure `DEFAULT_MEMBER_TENANT_SLUGS` for new-user default membership.

## `invalid_grant` On Token Exchange

Common causes:

- Authorization code expired.
- Authorization code was already used.
- Wrong `redirect_uri`.
- Wrong `code_verifier`.
- Client does not allow the requested grant.
- Refresh token was already rotated or revoked.

Authorization codes and refresh tokens are single-use on their happy path.

## JWKS Or Token Verification Fails

Check:

- Your app accepts only `RS256`.
- `iss` equals discovery `issuer`.
- `aud` contains your `client_id`.
- JWKS cache includes the token header `kid`.
- Local development did not restart with an ephemeral signing key.

Production fix: use `JWT_KEYSET_DIR` + `JWT_ACTIVE_KEY_ID` or persistent `JWT_PRIVATE_KEY_PATH` + `JWT_KEY_ID`.

## SMTP Authentication Fails

Check:

- `MAILER_PROVIDER=smtp`.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`.
- Provider-specific SMTP or app authorization code is used.
- `SMTP_FROM` is the authenticated mailbox or allowed alias.
- `SMTP_SSL=true` for port `465` implicit TLS providers such as 126 Mail.

GoAuth currently does not perform STARTTLS upgrade for port `587`, so providers that require STARTTLS need that code change first.

See [SMTP Configuration](config/smtp.md).

## CORS Fails

For separated frontend/backend origins:

```env
CORS_ALLOWED_ORIGINS=http://127.0.0.1:3000,http://localhost:3000
CORS_ALLOW_CREDENTIALS=true
CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Captcha-Token
```

Do not combine wildcard `*` with credentials.

## CAPTCHA Blocks Requests

Check:

- `CAPTCHA_PROVIDER`, `CAPTCHA_SITE_KEY`, and `CAPTCHA_SECRET_KEY` are set together.
- Frontend supports the provider. Current frontend supports Turnstile.
- `CAPTCHA_ACTIONS` contains the action being performed.
- Cross-origin requests allow `X-Captcha-Token`.

## Admin Console Says Forbidden

The user is authenticated but not a system user.

Use bootstrap admin once:

```env
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=<temporary-password>
BOOTSTRAP_ADMIN_ROLE=root
```

Restart the service, sign in, create real administrators, then remove the bootstrap password.

## Where To Look Next

- [Quickstart](quickstart.md)
- [SSO Quickstart](integration/sso-quickstart.md)
- [Docker Compose Deployment](deployment/docker-compose.md)
- [Configuration Matrix](configuration.md)
- [Production Checklist](production-checklist.md)
