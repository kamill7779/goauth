# ADR 0005: Refresh Token Family-Based Rotation with Reuse Detection

**Status:** Accepted  
**Date:** 2026-05-12

## Context

When a refresh token is used to get new tokens, the old token should be invalidated (rotation). If a stolen refresh token is used after the legitimate user has already rotated it, the system must detect the theft and revoke the entire token chain.

## Decision

**Use a family-ID chain with atomic revocation and reuse detection.**

Each refresh operation:

1. `SELECT ... FOR UPDATE` locks the login session (serializing concurrent refresh)
2. Atomically revokes the old token: `UPDATE refresh_tokens SET revoked_at=now WHERE id=? AND revoked_at IS NULL`
3. `RowsAffected != 1` means a race (another process already consumed it) → `ErrRefreshTokenReuse`
4. Issues a new token with the **same `family_id`** as the old one
5. Links the old token: `UPDATE refresh_tokens SET replaced_by_token_id=? WHERE id=?`

If a revoked token is ever presented:

1. `token.RevokedAt != nil` detected
2. `rejectRefreshTokenReuse()` is called:
   - Revokes the entire login session
   - Revokes ALL tokens in the family: `UPDATE refresh_tokens SET revoked_at=now WHERE family_id=?`
   - Writes an audit log entry (`ActionRefreshTokenReuseDetected`)
   - Returns `ErrRefreshTokenReuse` → user must re-authenticate

## Consequences

**Positive:**
- Theft is detectable with high probability (adversary using stolen token after legitimate user refreshed)
- Family-wide revocation is a strong signal — the entire device session is compromised, not just one token
- Atomic `UPDATE WHERE revoked_at IS NULL` + `RowsAffected` check prevents race conditions

**Negative:**
- Family revocation means a false positive (e.g., network retry) could log out a legitimate user
- Refresh token must be stored in MySQL (not just Redis) for family tracking
- `SELECT ... FOR UPDATE` creates row-level locks on each refresh — high refresh frequency could cause contention

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| No rotation (long-lived refresh tokens) | Stolen token grants indefinite access; no detection |
| Rotation without reuse detection | Stolen token can still be rotated by attacker, effectively two devices sharing access silently |
| JWT refresh tokens | Can't be revoked individually without a denylist; too large for cookie/header transport |
