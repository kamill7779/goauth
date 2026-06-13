# ADR 0004: bcrypt for Password Hashing

**Status:** Accepted  
**Date:** 2026-05-11

## Context

The service stores password hashes for local email/password authentication. The hashing algorithm must be memory-hard to resist GPU/ASIC brute-force attacks and must be well-supported in the Go ecosystem.

## Decision

**Use bcrypt via `golang.org/x/crypto/bcrypt` with `bcrypt.DefaultCost` (cost=10).**

```go
// services/identity-service/internal/auth/password.go (merged into service.go)
func HashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hash), err
}

func CheckPassword(hash, password string) error {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
```

## Consequences

**Positive:**
- bcrypt is the standard library recommendation for Go password hashing (`x/crypto/bcrypt`)
- Cost factor 10 gives ~100ms hash time per password, balancing UX and brute-force resistance
- Simple API: two functions, no configuration needed beyond cost
- Widely audited; no known cryptanalytic weaknesses

**Negative:**
- bcrypt is not memory-hard — ASIC-based attacks are theoretically possible (scrypt/argon2 are stronger here)
- 72-byte maximum input length (passwords longer than 72 bytes are truncated)
- No built-in parameter upgrade path (if we want to increase cost factor, we need a migration strategy)

## Future Consideration

If memory-hardness becomes a requirement (e.g., compliance), migrate to argon2id. The abstraction at `internal/auth/service.go` makes this a one-file change.

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| argon2id | More complex tuning (memory, iterations, parallelism); fewer Go ecosystem examples |
| scrypt | Slower than bcrypt for equivalent strength; `x/crypto/scrypt` less actively used |
| SHA-256 (salted) | Trivially parallelizable on GPU; not acceptable for password storage |
| PBKDF2 | Weaker against GPU attacks; older standard |
