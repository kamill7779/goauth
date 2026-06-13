# ADR 0002: JWT Access Tokens + Opaque Refresh Tokens

**Status:** Accepted  
**Date:** 2026-05-09

## Context

The service needs an access token format that downstream business apps can validate without calling back to GoAuth on every request. At the same time, refresh tokens must support instant revocation and reuse detection.

## Decision

**Access Tokens are signed JWTs (RS256). Refresh Tokens are opaque random strings stored as hashes in MySQL.**

Access Token claims (signed, stateless validation):

```json
{
  "iss": "https://auth.example.com",
  "sub": "1",
  "aud": "goauth-web",
  "tid": 10,
  "sid": "a1b2c3...",
  "email": "user@example.com",
  "email_verified": true,
  "token_use": "session",
  "ver": 3,
  "iat": 1710000000,
  "exp": 1710000900,
  "jti": "d4e5f6..."
}
```

Refresh Token workflow:
- 32 random bytes → hex-encoded → returned to client
- Server stores `SHA256(token)` in `refresh_tokens.token_hash`
- Each token is part of a `family_id` chain for reuse detection
- On refresh: old token atomically revoked, new token issued with same `family_id`

## Consequences

**Positive:**
- Business apps validate access tokens without network calls (just verify RS256 signature + expiry)
- `token_version` embedded in JWT enables O(1) global session invalidation (logout-all, password change)
- JTI (JWT ID) enables targeted token revocation via Redis denylist
- Refresh token reuse is detectable: if a revoked token in the family is used, the entire family dies

**Negative:**
- JWT access tokens can't be revoked instantly — only at next expiry or via JTI denylist lookup
- RS256 key rotation requires both old and new public keys to be simultaneously available
- JWT payload size grows with role/permission claims (mitigated by RBAC caching on the check endpoint)

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| Opaque access tokens | Every downstream API call requires a network round-trip to GoAuth for introspection |
| Symmetric (HS256) | Would expose signing key to every service that needs to validate tokens |
| JWT-only (no refresh) | Long-lived JWTs are not revocable; short-lived JWTs degrade user experience |
