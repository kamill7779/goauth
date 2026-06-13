# ADR 0001: MySQL as Primary Store with GORM Abstraction

**Status:** Accepted  
**Date:** 2026-05-08

## Context

GoAuth needs a durable, transactional store for user identities, tenant definitions, role assignments, OAuth client registrations, and audit logs. The store must support multi-table transactions (e.g., login → create session + refresh token atomically) and survive process restarts without data loss.

## Decision

**Use MySQL as the primary authoritative store, accessed via GORM v2.**

- GORM provides `AutoMigrate` for schema management and database-agnostic query building
- SQLite is supported for local development and CI via GORM's driver abstraction
- Raw SQL is used where GORM's query builder is insufficient (e.g., `SELECT ... FOR UPDATE`, subqueries with `IN`)

## Consequences

**Positive:**
- MySQL is battle-tested, widely deployed, and well-understood by ops teams
- GORM's `AutoMigrate` eliminates manual migration scripts during rapid iteration
- The `store.OpenDB(cfg)` function opens either MySQL (when `MYSQL_DSN` is set) or in-memory SQLite (when empty), enabling zero-config local dev
- 17 models auto-migrated via `store/db.go:39-57`

**Negative:**
- GORM's query generation is opaque; hard queries need raw SQL fallback
- SQLite's concurrent write limitations don't match MySQL — tests that pass locally can fail under MySQL's stricter locking
- No PostgreSQL support yet (GORM makes it possible, but untested)

## Alternatives Considered

| Alternative | Rejected Because |
|-------------|------------------|
| PostgreSQL only | Smaller ops community; GORM PostgreSQL support untested in this project |
| Raw SQL only | Too much boilerplate for simple CRUD; GORM reduces code volume ~60% |
| MongoDB | Unsuitable for relational RBAC data (many-to-many joins); no transaction guarantees for multi-table operations |
