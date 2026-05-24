# Quickstart

This guide gets GoAuth running locally, opens the login/Admin UI, and creates the first OAuth Client for SSO testing.

## Prerequisites

- Docker Desktop or Docker Engine with Compose.
- Go 1.26+ if you want to run backend tests locally.
- Node.js 20+ if you want to run the frontend login page and Admin Console.

## 1. Start The Backend Stack

```powershell
cd services/identity-service
Copy-Item .env.example .env
docker compose up --build
```

Compose starts:

- `identity-service` on `http://127.0.0.1:8080`
- MySQL on port `3306`
- Redis on port `6379`

Check the service:

```powershell
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/.well-known/openid-configuration
curl http://127.0.0.1:8080/v1/auth/public-config
```

Expected:

- `/healthz` returns `status=ok`.
- `/readyz` returns `status=ready`.
- Discovery returns an issuer matching `http://localhost:8080` when using the default Compose port.
- Public config returns local registration and login settings without secrets.

## 2. Start The Frontend UI

The current Compose file does not serve the React frontend. Run it separately for local UI testing:

```powershell
cd frontend
npm install
npm run dev
```

Open:

- Login page: `http://127.0.0.1:3000/login`
- Account center: `http://127.0.0.1:3000/account`
- Admin Console: `http://127.0.0.1:3000/admin`

The Vite dev server proxies `/.well-known`, `/v1`, and `/oauth2` to `http://127.0.0.1:8080`.

## 3. Register A Local User

By default:

- `REGISTRATION_MODE=open`
- `MAILER_PROVIDER=console`
- CAPTCHA and GitHub login are disabled

Use the login page registration tab. When it asks for an email code, watch the backend logs:

```powershell
cd services/identity-service
docker compose logs -f identity-service
```

Find `mailbox_path` in the log output and open that file to read the verification code.

## 4. Create The First Admin

For local Admin Console access, set a bootstrap admin before starting or restarting the backend.

Edit `services/identity-service/.env`:

```env
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=ChangeMe123!
BOOTSTRAP_ADMIN_NICKNAME=Initial Admin
BOOTSTRAP_ADMIN_ROLE=root
```

Restart only the service:

```powershell
cd services/identity-service
docker compose up -d --force-recreate identity-service
```

Then sign in at `http://127.0.0.1:3000/login` with the bootstrap admin and open `http://127.0.0.1:3000/admin`.

After creating your real administrator, remove `BOOTSTRAP_ADMIN_PASSWORD` from `.env` and restart the service.

## 5. Create A Tenant And OAuth Client

In Admin Console:

1. Open `Tenants`.
2. Create a tenant, for example:
   - Name: `Demo App`
   - Slug: `demo-app`
   - Status: `active`
3. Note the tenant ID.
4. Open `OAuth Clients`.
5. Register a client:
   - Tenant ID: the tenant ID from step 3
   - Client ID: `demo-web`
   - Client Secret: generate and store a strong secret
   - Redirect URIs: `http://localhost:3000/callback` or your app callback
   - Scopes: `openid`, `profile`, `email`, `offline_access`
   - Auth method: `client_secret_post` for simple local testing
   - Auto member creation: enabled for public demo apps

Save the one-time client secret immediately. GoAuth stores only the hash.

## 6. Configure A Business App

Use these values in your app:

```env
OIDC_ISSUER=http://localhost:8080
OIDC_CLIENT_ID=demo-web
OIDC_CLIENT_SECRET=<secret shown once in Admin Console>
OIDC_REDIRECT_URI=http://localhost:3000/callback
OIDC_SCOPES=openid profile email offline_access
```

Then follow [SSO Quickstart](integration/sso-quickstart.md) for the Authorization Code + PKCE flow.

## 7. Optional Smoke Test Against A Real Deployment

The repository includes an OIDC black-box script for a configured deployment:

```powershell
$env:GOAUTH_BASE_URL="http://localhost:8080"
$env:GOAUTH_TEST_EMAIL="admin@example.com"
$env:GOAUTH_TEST_PASSWORD="ChangeMe123!"
$env:GOAUTH_CLIENT_ID="demo-web"
$env:GOAUTH_CLIENT_SECRET="<client-secret>"
$env:GOAUTH_REDIRECT_URI="http://localhost:3000/callback"
node scripts/oidc-e2e.mjs --check-config
```

Run the full script only after the test user and OAuth Client exist:

```powershell
node scripts/oidc-e2e.mjs
```

## Next Steps

- Configure SMTP: [SMTP Configuration](config/smtp.md)
- Deploy behind a reverse proxy: [Docker Compose Deployment](deployment/docker-compose.md)
- Prepare production: [Production Checklist](production-checklist.md)
- Debug common errors: [Troubleshooting](troubleshooting.md)
