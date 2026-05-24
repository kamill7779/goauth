# SSO Quickstart

This guide shows how a business application connects to GoAuth through OpenID Connect Authorization Code + PKCE.

## Integration Model

GoAuth is the OIDC Provider. Your application is an OAuth Client.

```text
Browser -> Business App -> GoAuth /oauth2/authorize
Browser -> GoAuth Login Page
GoAuth -> Business App callback with code
Business App backend -> GoAuth /oauth2/token
Business App backend -> GoAuth JWKS / UserInfo
```

Use this flow for web apps, admin tools, SaaS consoles, and backend-rendered apps. Do not use implicit flow.

## 1. Create An OAuth Client

In GoAuth Admin Console:

1. Create or choose a tenant.
2. Open `OAuth Clients`.
3. Create a client:

```text
Client ID: demo-web
Redirect URI: http://localhost:3000/auth/callback
Scopes: openid profile email offline_access
Grant Types: authorization_code, refresh_token
Token Endpoint Auth Method: client_secret_post
Auto Provision Members: enabled for public demo apps
```

Store the one-time client secret. GoAuth stores only a hash and cannot show it again.

## 2. Configure Your App

```env
OIDC_ISSUER=http://localhost:8080
OIDC_CLIENT_ID=demo-web
OIDC_CLIENT_SECRET=<client-secret>
OIDC_REDIRECT_URI=http://localhost:3000/auth/callback
OIDC_SCOPES=openid profile email offline_access
```

In production, `OIDC_ISSUER` must be the HTTPS `PUBLIC_ISSUER_URL`, for example `https://auth.example.com`.

## 3. Read Discovery

At startup, read:

```http
GET {OIDC_ISSUER}/.well-known/openid-configuration
```

Important fields:

| Field | Use |
| --- | --- |
| `issuer` | Must match token `iss`. |
| `authorization_endpoint` | Browser redirect target. |
| `token_endpoint` | Backend code exchange target. |
| `userinfo_endpoint` | Fetch profile with access token. |
| `jwks_uri` | Fetch public keys for JWT verification. |

Cache discovery and JWKS, but refresh JWKS when token verification sees an unknown `kid`.

## 4. Start Login

Generate:

- `state`: random value stored in the user browser session.
- `nonce`: random value stored in the user browser session.
- `code_verifier`: random PKCE verifier.
- `code_challenge`: `BASE64URL(SHA256(code_verifier))`.

Redirect the browser:

```http
GET {authorization_endpoint}?response_type=code
  &client_id=demo-web
  &redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback
  &scope=openid%20profile%20email%20offline_access
  &state=<state>
  &nonce=<nonce>
  &code_challenge=<challenge>
  &code_challenge_method=S256
```

GoAuth requires:

- Exact redirect URI match.
- Scope includes `openid`.
- PKCE challenge.
- Active browser SSO session.
- Active tenant membership, unless the client allows auto provisioning.

If the user is not logged in, GoAuth redirects the browser to `BROWSER_LOGIN_URL`, normally `/login?return_to=...`.

## 5. Handle Callback

Your callback receives:

```text
http://localhost:3000/auth/callback?code=<code>&state=<state>
```

Validate `state` before exchanging the code. Reject the callback if it does not match the value stored before redirect.

## 6. Exchange Code For Tokens

Use your backend, not browser JavaScript, to call:

```http
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
client_id=demo-web&
client_secret=<client-secret>&
code=<authorization-code>&
redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fcallback&
code_verifier=<raw-code-verifier>
```

Expected response:

```json
{
  "access_token": "...",
  "id_token": "...",
  "refresh_token": "...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile email offline_access"
}
```

`refresh_token` is returned only when both conditions are true:

- The authorization request included `offline_access`.
- The OAuth Client allows the `refresh_token` grant.

## 7. Verify ID Token

Verify:

- Signature algorithm is `RS256`.
- JWT `kid` exists in `jwks_uri`.
- `iss` equals discovery `issuer`.
- `aud` contains your `client_id`.
- `exp`, `nbf`, and `iat` are valid.
- `nonce` equals the original login nonce.

Then create your own application session. Do not use the ID Token as a browser session cookie.

## 8. Fetch UserInfo

```http
GET {userinfo_endpoint}
Authorization: Bearer <access_token>
```

Scopes control returned fields:

- `openid`: `sub`
- `email`: `email`, `email_verified`
- `profile`: `name`, `picture` when available

## 9. Refresh Tokens

```http
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
client_id=demo-web&
client_secret=<client-secret>&
refresh_token=<refresh-token>
```

GoAuth rotates refresh tokens. Always replace the stored refresh token with the new one. If an old refresh token is reused, GoAuth revokes the family.

## 10. Logout

Clear your application session first. Then redirect the browser to GoAuth logout if you also want to end the GoAuth browser SSO session:

```http
GET {OIDC_ISSUER}/oauth2/logout?client_id=demo-web&post_logout_redirect_uri=<registered-uri>
```

If the request has an active GoAuth SSO cookie, GoAuth returns a confirmation page before revoking the browser session.

## 11. Permission Checks

For service-side authorization, call GoAuth from a trusted backend with a system-capable token:

```http
POST /v1/authz/check
Authorization: Bearer <system-access-token>
Content-Type: application/json

{
  "user_id": 123,
  "tenant_id": 1,
  "permission": "project:read"
}
```

For a user checking their own permissions:

```http
GET /v1/tenants/{tenant_id}/my-permissions
Authorization: Bearer <user-access-token>
```

## Common Integration Failures

| Symptom | Likely cause |
| --- | --- |
| `invalid_request` at authorize | Redirect URI mismatch or missing PKCE. |
| `invalid_scope` | Client allowed scopes do not include the requested scope. |
| `login_required` JSON | Non-browser request or missing GoAuth SSO cookie. |
| `access_denied` | User is not a tenant member and auto provisioning is disabled. |
| `invalid_grant` at token endpoint | Code expired, reused, wrong redirect URI, or wrong PKCE verifier. |
| ID Token verification fails | Wrong issuer, stale JWKS cache, or wrong client ID. |

For endpoint-level details, read [OIDC Integration Details](../../services/identity-service/docs/oidc-integration.md).
