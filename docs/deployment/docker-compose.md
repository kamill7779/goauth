# Docker Compose Deployment

GoAuth currently ships a backend Compose stack under `services/identity-service/`. It starts the identity API and runtime dependencies. The React login page and Admin Console are built separately and must be served by Vite in development or by a static file server/reverse proxy in deployment.

## Local Backend Stack

```powershell
cd services/identity-service
Copy-Item .env.example .env
docker compose up --build
```

Services:

| Service | Purpose | Default host port |
| --- | --- | --- |
| `identity-service` | GoAuth API, OIDC Provider, Admin API | `8080` |
| `mysql` | Persistent identity database | `3306` |
| `redis` | Email codes, rate limits, sessions, caches | `6379` |

Useful commands:

```powershell
docker compose ps
docker compose logs -f identity-service
docker compose down -v
```

Change host ports through Compose variables:

```powershell
$env:IDENTITY_HTTP_PORT="18080"
docker compose up --build
```

The default Compose issuer follows the exposed identity port:

```text
PUBLIC_ISSUER_URL=http://localhost:${IDENTITY_HTTP_PORT:-8080}
```

## Local Full UI

Start the frontend in another terminal:

```powershell
cd frontend
npm install
npm run dev
```

The Vite dev server listens on `http://127.0.0.1:3000` and proxies:

- `/.well-known`
- `/v1`
- `/oauth2`

to `http://127.0.0.1:8080`.

## Production Reverse Proxy Shape

In production, serve the built frontend and reverse proxy API/OIDC paths to the backend.

Required route split:

| Path | Target |
| --- | --- |
| `/`, `/login`, `/account`, `/admin`, `/external/callback` | Frontend static app |
| `/.well-known/*` | identity-service |
| `/oauth2/*` | identity-service |
| `/v1/*` | identity-service |
| `/metrics` | identity-service, usually restricted |

Example Nginx shape:

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    root /var/www/goauth;
    index index.html;

    location /.well-known/ {
        proxy_pass http://identity-service:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /oauth2/ {
        proxy_pass http://identity-service:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /v1/ {
        proxy_pass http://identity-service:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        try_files $uri /index.html;
    }
}
```

Production identity configuration:

```env
APP_ENV=production
PUBLIC_ISSUER_URL=https://auth.example.com
BROWSER_LOGIN_URL=/login
BROWSER_COOKIE_SECURE=true
TRUSTED_PROXIES=<proxy cidr or proxy IP>
CORS_ALLOWED_ORIGINS=https://auth.example.com,https://app.example.com
```

`PUBLIC_ISSUER_URL` must be the externally reachable HTTPS issuer. Business applications validate tokens against this issuer.

## Frontend Build

```powershell
cd frontend
npm install
npm run build
```

Serve `frontend/dist` from your static host or image. If frontend and backend are not same-origin, set CORS on the identity service:

```env
CORS_ALLOWED_ORIGINS=https://auth-ui.example.com
CORS_ALLOW_CREDENTIALS=true
```

Same-origin deployment is simpler because the login page, SSO cookie, and OIDC authorize endpoint share one origin.

## Persistent Data

The Compose stack uses named volumes:

- `mysql-data`
- `redis-data`
- `avatar-data`

For production, replace demo passwords and either keep these volumes backed up or use managed MySQL/Redis.

```env
MYSQL_DSN=<user>:<password>@tcp(<mysql-host>:3306)/goauth_identity?charset=utf8mb4&parseTime=True&loc=Local
REDIS_URL=redis://:<password>@<redis-host>:6379/0
AVATAR_STORAGE_DIR=/app/data/avatars
```

## Follow-Up Engineering Task

The next deployment improvement should be a top-level Compose profile that builds the frontend, serves it through Nginx/Caddy, and proxies API paths to `identity-service`. Until that exists, docs and examples should describe the current two-process local experience honestly.
