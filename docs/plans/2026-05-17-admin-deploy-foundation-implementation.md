# Admin Deploy Foundation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a lightweight deployment diagnostics and permission-center foundation for GoAuth Admin Console.

**Architecture:** Keep environment variables as the runtime configuration source of truth. Add read-only backend summaries for runtime config and access topology, then render them in Admin Settings and Security pages without making runtime settings editable.

**Tech Stack:** Go, Gin, GORM, SQLite/MySQL-compatible queries, React, Vite, Axios, existing GoAuth admin and frontend test utilities.

---

### Task 1: Add Runtime Config Summary

**Files:**
- Modify: `services/identity-service/internal/admin/runtime_config.go`
- Modify: `services/identity-service/internal/admin/runtime_config_test.go`
- Modify: `frontend/src/types/admin.ts`
- Modify: `frontend/src/pages/Admin/SettingsPage.tsx`
- Modify: `frontend/tests/adminPageState.test.mjs`

**Steps:**

1. Write a Go test proving `/v1/admin/runtime-config` returns a `summary` with `total`, `ok`, `warning`, and `error`.
2. Run `go test ./internal/admin` and confirm the test fails because summary is missing.
3. Implement summary counting while building runtime config groups.
4. Run `go test ./internal/admin` and confirm it passes.
5. Write a frontend test proving SettingsPage derives summary cards from runtime config.
6. Run `npm run test:admin` and confirm the test fails.
7. Implement `RuntimeConfigSummary` types and SettingsPage summary rendering helpers.
8. Run `npm run test:admin` and confirm it passes.

### Task 2: Add Access Overview API

**Files:**
- Create: `services/identity-service/internal/admin/access_overview.go`
- Modify: `services/identity-service/internal/admin/handler.go`
- Create or modify: `services/identity-service/internal/admin/access_overview_test.go`
- Modify: `frontend/src/types/admin.ts`
- Modify: `frontend/src/api/admin.ts`

**Steps:**

1. Write a Go test for `GET /v1/admin/access-overview` with tenants, roles, permissions, OAuth clients, and default membership slugs.
2. Confirm the test fails because the route is missing.
3. Implement route registration and a read-only overview handler.
4. Return `summary`, `default_memberships`, `tenants`, `oauth_clients`, and `risks`.
5. Keep all queries SQLite/MySQL compatible.
6. Run `go test ./internal/admin` and confirm it passes.
7. Write frontend API/type tests proving `getAccessOverview()` uses `/admin/access-overview`.
8. Run `npm run test:admin` and confirm it passes.

### Task 3: Replace Security Placeholder With Permission Center

**Files:**
- Modify: `frontend/src/pages/Admin/SecurityPage.tsx`
- Modify: `frontend/src/components/admin/Sidebar.tsx`
- Modify: `frontend/src/components/admin/Header.tsx`
- Modify: `frontend/tests/adminPageState.test.mjs`

**Steps:**

1. Write frontend tests for pure helpers that map access overview payloads into summary cards, tenant rows, and risk rows.
2. Confirm tests fail because helpers are missing.
3. Implement helpers and render `SecurityPage` as “权限中心”.
4. Rename sidebar label from “邮件与安全” to “权限中心”.
5. Keep UI dense, utilitarian, and readable in light/dark themes.
6. Run `npm run test:admin` and confirm it passes.

### Task 4: Add Configuration Drift Guards

**Files:**
- Modify: `services/identity-service/internal/config/schema_test.go`
- Modify: `services/identity-service/.env.example`
- Modify: `docs/configuration.md`

**Steps:**

1. Write tests that parse `.env.example` and `docs/configuration.md` and compare keys with `config.EnvDefinitions()`.
2. Confirm tests fail only if current docs drift; if they already pass, keep them as guards.
3. Fix any drift discovered by the tests.
4. Run `go test ./internal/config`.

### Task 5: Final Verification

**Commands:**

```powershell
cd services/identity-service
$env:GOMAXPROCS='2'; go test -p 1 ./...

cd ../../frontend
npm run test:admin
npm run build
```

**Expected:** all commands pass.

