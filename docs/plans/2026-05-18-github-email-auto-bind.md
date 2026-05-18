# GitHub Verified Email Auto-Bind Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow GitHub OAuth login to auto-bind an existing local account when the GitHub email is verified and safely matches the local user, while also requiring CAPTCHA challenge before third-party login can start.

**Architecture:** Keep the external-login callback and exchange flow intact. Change `idp.Service.Authenticate` to add a guarded auto-bind branch for existing users, and change the GitHub start endpoint so the frontend gets a CAPTCHA token first, then POSTs for an `authorize_url` instead of redirecting immediately.

**Tech Stack:** Go, GORM, Gin, existing GoAuth identity-service tests and audit models.

---

### Task 1: Lock the expected auto-bind behavior in tests

**Files:**
- Modify: `services/identity-service/internal/idp/service_test.go`

**Steps:**

1. Write a test proving `Authenticate()` auto-binds an active existing user when the GitHub email is verified.
2. Run `go test ./internal/idp -run TestAuthenticateAutoBindsExistingUserWhenEmailVerified` and confirm it fails.
3. Write a test proving unverified GitHub email still returns `ErrLocalLoginRequired`.
4. Run `go test ./internal/idp -run TestAuthenticateRequiresLocalLoginWhenEmailUnverified` and confirm it fails or the suite stays red on missing behavior.
5. Write a test proving a disabled local user returns `ErrUserDisabled`.
6. Run `go test ./internal/idp -run TestAuthenticateRejectsDisabledExistingUserDuringAutoBind` and confirm it fails or the suite stays red.
7. Write a test proving auto-bind records `audit.ActionExternalIdentityChanged` with `change=auto_bound`.
8. Run `go test ./internal/idp` and confirm the suite fails only on the new missing behavior.

### Task 2: Implement the guarded auto-bind branch

**Files:**
- Modify: `services/identity-service/internal/idp/service.go`

**Steps:**

1. Add a helper to load an identity by `user_id + provider`.
2. Add an `auto-bind existing user` branch inside `Authenticate()`.
3. Reject auto-bind when `profile.EmailVerified` is false.
4. Reject auto-bind when the matched user is disabled.
5. Reject auto-bind when the matched user already has another GitHub identity.
6. Create the new `user_identities` row in a transaction.
7. Keep `AuthenticateResult.Created` reserved for newly created users only.
8. Record an external identity audit entry for successful auto-bind.

### Task 3: Protect GitHub start with CAPTCHA challenge

**Files:**
- Modify: `services/identity-service/internal/idp/handler.go`
- Modify: `services/identity-service/internal/idp/handler_test.go`
- Modify: `services/identity-service/cmd/server/main.go`
- Modify: `services/identity-service/internal/captcha/verifier.go`
- Modify: `services/identity-service/internal/auth/handler.go`
- Modify: `frontend/src/api/auth.ts`
- Modify: `frontend/src/pages/LoginPage.tsx`
- Modify: `frontend/tests/authApi.test.mjs`

**Steps:**

1. Write a handler test proving `POST /v1/external/github/start` returns `authorize_url` and sets the OAuth state cookie.
2. Run `go test ./internal/idp` and confirm it fails because POST start support is missing.
3. Write a handler test proving CAPTCHA-protected start rejects `POST /start` without token.
4. Write a handler test proving CAPTCHA-protected start also rejects `GET /start`.
5. Add CAPTCHA support to `idp.Handler` and wire it from `cmd/server/main.go`.
6. Keep GET redirect behavior only when the `login` CAPTCHA action is not enabled.
7. Write a frontend API test proving GitHub start is initiated with `apiPostV1('/external/github/start', ..., { captchaToken })`.
8. Update `LoginPage` so the GitHub button gets a `login` CAPTCHA token before redirecting.

### Task 4: Verify regressions and deployment readiness

**Files:**
- No source changes expected unless verification exposes an issue.

**Steps:**

1. Run `go test ./internal/idp` and confirm all tests pass.
2. Run `go test ./...` and confirm the full identity-service suite passes.
3. Review the diff to confirm the change is limited to design docs and identity-service logic/tests.
4. Commit on `feat/github-auto-bind-email`.
5. Build and deploy the updated identity-service to production.
6. Re-test the GitHub login flow against `https://auth.kmsoft.top`.
