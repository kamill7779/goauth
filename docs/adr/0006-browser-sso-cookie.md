# ADR 0006: Browser SSO Cookie with RS256 JWT

**Status:** Accepted  
**Date:** 2026-05-14

## Context

When a user logs into one business app and then navigates to another, they should not need to re-enter credentials. This "Single Sign-On" experience within the browser requires GoAuth to recognize returning users on the `/oauth2/authorize` endpoint.

## Decision

**Use a SameSite=Lax HttpOnly cookie containing a signed RS256 JWT.**

Cookie specification:
- **Name**: `goauth_oidc_session`
- **Claims**: `{ purpose: "oidc_authorize", sub: userID, sid: sessionID, tid: tenantID, iat, nbf, exp }`
- **Signature**: RS256, same key as access tokens
- **Attributes**: `SameSite=Lax; HttpOnly; Path=/; Secure` (Secure follows `PUBLIC_ISSUER_URL` protocol)

The cookie is set after every successful login, 2FA verification, and token refresh. The `/oauth2/authorize` endpoint reads it, verifies the signature, extracts `userID + sessionID`, validates the session is still active, and skips the login redirect.

## Consequences

**Positive:**
- Zero additional network calls for SSO — the cookie comes with the browser request
- `SameSite=Lax` provides CSRF protection for GET-based OIDC redirects while allowing top-level navigation
- Purpose-scoped (`oidc_authorize`): can't be confused with other cookie types
- Session-scoped: revoking a login session also invalidates the SSO cookie (since authorize checks session liveness)

**Negative:**
- Cookie size: JWT adds ~300 bytes to every request to the authorize endpoint
- Key rotation: must verify with keyring (not single public key) during rotation windows
- Cookie TTL (default 12h) is shorter than refresh token TTL (30 days) — long-lived browser sessions still need re-auth after 12h

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| Opaque session ID in cookie | Requires a Redis lookup on every authorize request — high latency |
| `SameSite=None` + CSRF token | More complex implementation; additional token to manage |
| No browser SSO | Forces re-login on every OIDC authorization, degrading UX |
| Third-party SSO (e.g. Auth0) | Adds external vendor dependency; defeats self-hosting goal |
