# Register Slider Human Check Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a second, self-hosted slider human-check to GoAuth registration, layered with existing Turnstile CAPTCHA.

**Architecture:** Implement a Go backend `humancheck` package using Redis-backed challenges and one-time tokens. Expose `/v1/auth/human-check/slider` and `/v1/auth/human-check/slider/verify`, surface public config, require `X-Human-Token` on registration, and add a React slider UI on the registration form.

**Tech Stack:** Go/Gin/Redis, React/Vite/TypeScript, existing Turnstile CAPTCHA, optional `github.com/wenlng/go-captcha/v2` for future image generation.

---

### Task 1: Backend human-check core

**Files:**
- Create: `services/identity-service/internal/humancheck/service.go`
- Create: `services/identity-service/internal/humancheck/service_test.go`

**Steps:**
1. Write tests for challenge creation, wrong answer rejection, valid answer token issuance, one-time token consumption, expiry handling.
2. Run `go test ./internal/humancheck` and verify tests fail because package is missing.
3. Implement minimal Redis-backed service with generated challenge id, target offset, nonce, short TTL, signed/random token hash storage.
4. Run `go test ./internal/humancheck` and verify pass.

### Task 2: Backend HTTP endpoints and registration middleware

**Files:**
- Create: `services/identity-service/internal/humancheck/handler.go`
- Create: `services/identity-service/internal/humancheck/handler_test.go`
- Modify: `services/identity-service/internal/auth/handler.go`
- Modify: `services/identity-service/internal/auth/handler_test.go`

**Steps:**
1. Write tests for missing `X-Human-Token` blocking register when enabled and allowing when disabled.
2. Write handler tests for challenge and verify endpoints.
3. Implement handler and middleware integration.
4. Run targeted Go tests.

### Task 3: Config/public-config/main wiring

**Files:**
- Modify: `services/identity-service/internal/config/config.go`
- Modify: `services/identity-service/internal/config/schema.go`
- Modify: `services/identity-service/internal/auth/public_config.go`
- Modify: `services/identity-service/cmd/server/main.go`
- Modify: `services/identity-service/.env.example`
- Modify: docs.

**Steps:**
1. Write config/public-config tests for `HUMAN_CHECK_PROVIDER=slider` and actions.
2. Implement config parsing and safe public output.
3. Wire service/handler in main.
4. Run targeted Go tests.

### Task 4: Frontend API and slider UI

**Files:**
- Create: `frontend/src/api/humanCheck.ts`
- Create: `frontend/src/components/auth/SliderHumanCheck.tsx`
- Modify: `frontend/src/api/auth.ts`
- Modify: `frontend/src/api/client.ts`
- Modify: `frontend/src/types/publicConfig.ts`
- Modify: `frontend/src/api/publicConfig.ts`
- Modify: `frontend/src/pages/LoginPage.tsx`
- Create/modify frontend tests.

**Steps:**
1. Write frontend tests for public config normalization, auth API `X-Human-Token`, and slider verify flow helpers.
2. Implement minimal accessible slider component matching current auth page style.
3. Wire registration submit to obtain human token before register.
4. Run `npm run test:admin` and `npm run build`.

### Task 5: Full verification

Run:
- `go test ./...` in `services/identity-service`
- `npm run test:admin` in `frontend`
- `npm run build` in `frontend`
- `git diff --stat` review
