# ADR 0003: Redis for Ephemeral State + Hot Cache

**Status:** Accepted  
**Date:** 2026-05-10

## Context

The service needs several categories of ephemeral state:
1. Email verification codes (10-minute TTL)
2. Rate-limiting counters (sliding window per scope/key)
3. 2FA login challenges (5-minute TTL + distributed lock)
4. RBAC permission cache (2-minute TTL)
5. JTI denylist (TTL until token expiry)
6. OIDC/OAuth state tokens (10-minute TTL)

All of this data must survive the identity-service process restart but doesn't need the durability guarantees of MySQL.

## Decision

**Use Redis for all ephemeral state and hot-path caches. Redis is a hard runtime dependency — if unavailable, the service fails to start.**

Redis key naming is centralized in `internal/cache/keys.go` with type-safe key generators like:

```go
func EmailCodeKey(purpose, email string) string {
    return fmt.Sprintf("auth:email_code:%s:%s", purpose, email)
}
func PermissionCacheKey(tenantID, userID int64) string {
    return fmt.Sprintf("auth:permissions:%d:%d", tenantID, userID)
}
```

## Consequences

**Positive:**
- All TTL-based data naturally expires without cleanup jobs
- `SET NX` enables distributed locking for 2FA challenge serialization
- Atomic `INCR` + `EXPIRE` gives precise rate-limit windows
- RBAC permission cache with version-based invalidation achieves ~99% hit rate, keeping `/v1/authz/check` latency under 5ms

**Negative:**
- Adding an operational dependency; Redis must be provisioned and monitored
- No fallback to in-memory-only if Redis is down (by design — fail-fast beats inconsistent state)
- Two data stores increases cognitive load for debugging (is the data in MySQL or Redis?)

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| MySQL-only | Rate limits and email codes would hammer the DB; no TTL support in MySQL before 8.0.28 |
| In-memory (Go `map`) | Lost on restart; no sharing between replicas; no atomic `INCR` for distributed counters |
| Memcached | No built-in Lua scripting; weaker atomicity guarantees for rate-limit sliding windows |
