# User Identity Fields Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the overloaded `display_name` model with explicit `username`, `nickname`, and `email`, where `username` and `email` are globally unique and login accepts either username or email plus password.

**Architecture:** Add first-class `users.username` and `users.nickname` columns, keep `users.display_name` as a temporary compatibility alias, and update all auth/admin/OIDC/frontend contracts to prefer the new fields. Existing users are backfilled deterministically so migration is safe for production and forum SSO provisioning can use `username` as the stable account name.

**Tech Stack:** Go, Gin, GORM, MySQL/SQLite tests, Redis-backed email codes, React 19, Vite, TypeScript, Tailwind CSS.

---

### Task 1: Data Model And Migration

**Files:**
- Modify: `services/identity-service/internal/store/models.go`
- Modify: `services/identity-service/internal/store/db.go`
- Test: `services/identity-service/internal/store/db_test.go`

**Step 1: Write failing migration tests**

Add tests that start from a legacy `users` table with only `email` and `display_name`, then run `AutoMigrate` and assert:
- `users.username` exists.
- `users.nickname` exists.
- `users.username` has a unique index.
- Existing users get deterministic usernames.
- Duplicate email local parts are deconflicted, for example `alice`, `alice2`, `alice3`.

Run:

```bash
go test ./internal/store -run 'TestAutoMigrateBackfillsUserIdentityFields|TestUserUsernameUniqueIndexRejectsDuplicates' -count=1
```

Expected before implementation: fail because columns and index do not exist.

**Step 2: Extend the model**

Add to `store.User`:

```go
Username string `gorm:"size:64;not null;uniqueIndex"`
Nickname string `gorm:"size:255;not null"`
```

Keep `DisplayName` for compatibility during rollout. Do not remove it in this phase.

**Step 3: Backfill legacy users**

In `store.AutoMigrate`, after schema migration, backfill empty usernames and nicknames:
- `nickname = display_name` when present.
- `nickname = email local-part` when `display_name` is blank.
- `username = sanitized email local-part`.
- If sanitized username is invalid or too short, use `user<ID>`.
- If username collides, append an incrementing suffix within the 64-character column limit.

**Step 4: Verify**

Run:

```bash
go test ./internal/store -count=1
```

Expected: store tests pass.

**Step 5: Commit**

```bash
git add services/identity-service/internal/store/models.go services/identity-service/internal/store/db.go services/identity-service/internal/store/db_test.go
git commit -m "feat(identity): add username and nickname fields"
```

---

### Task 2: Shared Normalization And Validation

**Files:**
- Create: `services/identity-service/internal/identity/identity.go`
- Test: `services/identity-service/internal/identity/identity_test.go`
- Modify: `services/identity-service/internal/auth/service.go`
- Modify: `services/identity-service/internal/user/service.go`

**Step 1: Write failing validator tests**

Cover:
- Email is trimmed and lowercased.
- Username is trimmed, lowercased, and accepts only `a-z0-9_-`.
- Username length is `3-32` for public input.
- Nickname is trimmed and allows Chinese.
- Blank nickname falls back to username.
- Invalid usernames are rejected before database insert.

Run:

```bash
go test ./internal/identity -count=1
```

Expected before implementation: package does not exist.

**Step 2: Implement identity helpers**

Expose helpers:
- `NormalizeEmail(email string) string`
- `NormalizeUsername(username string) (string, error)`
- `NormalizeNickname(nickname, fallback string) string`
- `UsernameFromEmail(email string) string`
- `IsUsernameLikeIdentifier(identifier string) bool`

Return explicit errors for invalid username and blank email.

**Step 3: Replace duplicated normalization**

Use the shared helpers in auth and admin user service code. Preserve old behavior where needed, but no new code should call local ad-hoc email normalizers.

**Step 4: Verify**

Run:

```bash
go test ./internal/identity ./internal/auth ./internal/user -count=1
```

Expected: tests pass.

**Step 5: Commit**

```bash
git add services/identity-service/internal/identity services/identity-service/internal/auth/service.go services/identity-service/internal/user/service.go
git commit -m "refactor(identity): centralize user field normalization"
```

---

### Task 3: Registration And Login Contract

**Files:**
- Modify: `services/identity-service/internal/auth/service.go`
- Modify: `services/identity-service/internal/auth/handler.go`
- Test: `services/identity-service/internal/auth/service_test.go`
- Test: `services/identity-service/internal/auth/handler_test.go`
- Modify: `frontend/src/types/auth.ts`
- Modify: `frontend/src/api/auth.ts`
- Modify: `frontend/src/pages/LoginPage.tsx`

**Step 1: Write failing auth tests**

Add tests for:
- Register requires unique `username`.
- Register rejects duplicate username even with different email.
- Register keeps email uniqueness.
- Register stores `nickname` separately from `username`.
- Login accepts `{ "identifier": "username", "password": "..." }`.
- Login accepts `{ "identifier": "email@example.com", "password": "..." }`.
- Login temporarily still accepts legacy `{ "email": "email@example.com", "password": "..." }`.
- Audit metadata records `identifier_type` and never stores password.

Run:

```bash
go test ./internal/auth -run 'TestRegister.*Username|TestLoginAcceptsUsernameOrEmailIdentifier' -count=1
```

Expected before implementation: fail.

**Step 2: Update backend input structs**

Change register input to include:

```go
Username string
Nickname string
Email string
Password string
EmailCode string
CodePurpose string
```

Change login input to include:

```go
Identifier string
Email string // legacy fallback only
Password string
```

Login lookup rule:
- If `identifier` contains `@`, lookup normalized email.
- Otherwise lookup normalized username.
- If `identifier` is blank, fallback to legacy `email`.

**Step 3: Update frontend login/register**

Register form fields:
- username
- nickname
- email
- password
- email code

Login form label:
- `用户名或邮箱`

Payloads:

```ts
login({ identifier, password })
register({ username, nickname, email, password, email_code })
```

Keep no hosted UI coupling. This remains pure frontend calling API.

**Step 4: Verify**

Run:

```bash
go test ./internal/auth -count=1
cd frontend && npm run build && npm run test:admin
```

Expected: auth tests and frontend build pass.

**Step 5: Commit**

```bash
git add services/identity-service/internal/auth frontend/src/types/auth.ts frontend/src/api/auth.ts frontend/src/pages/LoginPage.tsx
git commit -m "feat(auth): login with username or email"
```

---

### Task 4: Admin User Management API

**Files:**
- Modify: `services/identity-service/internal/user/service.go`
- Modify: `services/identity-service/internal/user/handler.go`
- Test: `services/identity-service/internal/user/service_test.go`
- Test: `services/identity-service/cmd/server/main_test.go`
- Modify: `frontend/src/types/admin.ts`
- Modify: `frontend/src/api/adminAdapters.ts`
- Modify: `frontend/src/pages/Admin/UsersPage.tsx`

**Step 1: Write failing admin tests**

Cover:
- Admin list payload includes `username`, `nickname`, and `email`.
- Search matches username, nickname, and email.
- Sort supports `username_asc`, `username_desc`, `email_asc`, `email_desc`, `created_desc`.
- Create user requires username and email uniqueness.
- Update user can change nickname.
- Update username is either disallowed or requires explicit endpoint. Recommended: disallow for now to avoid breaking forum mapping.

Run:

```bash
go test ./internal/user ./cmd/server -run 'TestAdmin.*User|TestListUsers.*Username' -count=1
```

Expected before implementation: fail.

**Step 2: Update backend user DTOs**

Admin user response should include:

```json
{
  "id": 1,
  "username": "kamuii",
  "nickname": "卡密",
  "email": "xykamuii04@gmail.com",
  "display_name": "卡密",
  "status": "active",
  "email_verified": true
}
```

`display_name` remains an alias of `nickname` during compatibility window.

**Step 3: Update frontend users page**

Display primary identity as:
- first line: `username`
- second line: `nickname`
- third line: `email`

Search placeholder:

```text
搜索 username、昵称或邮箱...
```

Add sort options for username.

**Step 4: Verify**

Run:

```bash
go test ./internal/user ./cmd/server -count=1
cd frontend && npm run build
```

Expected: tests and build pass.

**Step 5: Commit**

```bash
git add services/identity-service/internal/user services/identity-service/cmd/server/main_test.go frontend/src/types/admin.ts frontend/src/api/adminAdapters.ts frontend/src/pages/Admin/UsersPage.tsx
git commit -m "feat(admin): expose username and nickname"
```

---

### Task 5: OIDC Claims, UserInfo, And Forum Bridge

**Files:**
- Modify: `services/identity-service/internal/oidc/service.go`
- Modify: `services/identity-service/internal/oidc/token.go`
- Modify: `services/identity-service/internal/oidc/userinfo.go`
- Test: `services/identity-service/internal/oidc/oidc_test.go`
- Modify: `services/identity-service/docs/client-integration.md`
- Modify: `services/identity-service/docs/oidc-integration.md`

**Step 1: Write failing OIDC tests**

Assert that `profile` scope returns:
- `preferred_username`
- `username`
- `nickname`
- `name`

Assert that `email` scope still gates:
- `email`
- `email_verified`

Run:

```bash
go test ./internal/oidc -run 'TestUserInfo|TestIDToken' -count=1
```

Expected before implementation: fail because claims are missing.

**Step 2: Update claims**

For `profile` scope:
- `preferred_username = user.Username`
- `username = user.Username`
- `nickname = user.Nickname`
- `name = user.Nickname`

For `email` scope:
- keep `email`
- keep `email_verified`

**Step 3: Update integration docs**

Document forum bridge mapping:
- forum username = `preferred_username` or `username`
- forum nickname/display name = `nickname`
- forum email = `email`
- forum stable remote id = `sub`

State that forum services must not derive username from email after this rollout.

**Step 4: Verify**

Run:

```bash
go test ./internal/oidc -count=1
```

Expected: OIDC tests pass.

**Step 5: Commit**

```bash
git add services/identity-service/internal/oidc services/identity-service/docs/client-integration.md services/identity-service/docs/oidc-integration.md
git commit -m "feat(oidc): expose username and nickname claims"
```

---

### Task 6: Bootstrap Admin And Production Migration Safety

**Files:**
- Modify: `services/identity-service/cmd/server/main.go`
- Modify: `services/identity-service/internal/config/config.go`
- Test: `services/identity-service/internal/user/service_test.go`
- Modify: `services/identity-service/README.md`
- Modify: `services/identity-service/docker-compose.yml`

**Step 1: Write failing bootstrap tests**

Cover:
- Bootstrap admin can set `BOOTSTRAP_ADMIN_USERNAME`.
- Existing bootstrap admin gets username backfilled.
- Existing admin password rotation does not overwrite username unless explicitly configured.

Run:

```bash
go test ./internal/user -run TestBootstrapAdmin -count=1
```

Expected before implementation: fail.

**Step 2: Add config**

Add:
- `BOOTSTRAP_ADMIN_USERNAME`
- keep `BOOTSTRAP_ADMIN_DISPLAY_NAME` as compatibility alias for nickname
- optionally add `BOOTSTRAP_ADMIN_NICKNAME`

Recommended precedence:
- nickname uses `BOOTSTRAP_ADMIN_NICKNAME`
- fallback to `BOOTSTRAP_ADMIN_DISPLAY_NAME`
- fallback to username

**Step 3: Document production migration**

Before production deploy:
- Backup MySQL.
- Run migration on staging copy.
- Confirm no duplicate generated usernames.
- Confirm `admin@example.com` gets expected username.
- Confirm forum can create SSO user from `preferred_username`.

**Step 4: Verify**

Run:

```bash
go test ./internal/user ./cmd/server -count=1
```

Expected: tests pass.

**Step 5: Commit**

```bash
git add services/identity-service/cmd/server/main.go services/identity-service/internal/config/config.go services/identity-service/internal/user/service_test.go services/identity-service/README.md services/identity-service/docker-compose.yml
git commit -m "feat(identity): configure bootstrap username"
```

---

### Task 7: Full Verification And Release Gate

**Files:**
- No code changes expected.

**Step 1: Run backend tests**

```bash
cd services/identity-service
go test ./... -count=1
```

Expected: all backend tests pass.

**Step 2: Run frontend tests and build**

```bash
cd frontend
npm run test:admin
npm run build
```

Expected: admin tests pass and Vite build succeeds.

**Step 3: Run migration test against configured MySQL**

Use the existing MySQL migration test path used by the project. Confirm:
- `users.username` exists.
- unique index works.
- production-like legacy users are backfilled.

**Step 4: Local functional checks**

Verify manually or with a smoke script:
- Register with username, nickname, email, password, email code.
- Login with username.
- Login with email.
- `/oauth2/userinfo` returns username/nickname/email according to scopes.
- Admin users page searches username, nickname, and email.
- Forum bridge creates new user with username from GoAuth.

**Step 5: Final commit or release tag**

Only after verification is clean:

```bash
git status --short
git log --oneline -5
```

Expected: clean working tree and all planned commits present.

