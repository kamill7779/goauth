# Documentation Onboarding Experience Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make GoAuth documentation guide a new user from clone to local login and first SSO client integration without reading source code.

**Architecture:** Keep the root README short and route detailed topics into focused docs under `docs/`. Document the current deployment shape honestly: backend Compose starts the identity service and dependencies, while the frontend is run separately for local UI until a unified reverse-proxy Compose is implemented.

**Tech Stack:** Markdown documentation, Docker Compose, Go identity-service, Vite React frontend, OAuth2/OIDC Authorization Code + PKCE, SMTP.

---

### Task 1: Root README

**Files:**
- Modify: `README.md`

**Steps:**
1. Replace the broad capability list with product positioning.
2. Add a 5-minute backend quickstart command.
3. Add links to Quickstart, SSO integration, deployment, SMTP, production checklist, and troubleshooting docs.
4. Keep production warnings short and point to deeper docs.

**Verify:** Read `README.md` and confirm every linked doc path exists.

### Task 2: Quickstart

**Files:**
- Create: `docs/quickstart.md`

**Steps:**
1. Document prerequisites.
2. Document backend Compose startup.
3. Document health, readiness, discovery, and public config checks.
4. Document frontend dev startup for `/login` and `/admin`.
5. Document local console mail verification and first admin bootstrap.
6. Add the shortest path to creating a tenant and OAuth client.

**Verify:** Commands match existing `services/identity-service/docker-compose.yml`, `frontend/package.json`, and backend routes.

### Task 3: Deployment

**Files:**
- Create: `docs/deployment/docker-compose.md`

**Steps:**
1. Explain current backend Compose services and ports.
2. Explain frontend hosting requirement and reverse-proxy paths.
3. Provide local and production environment examples.
4. Call out the follow-up need for a unified Compose profile.

**Verify:** Environment names match `docs/configuration.md` and `.env.example`.

### Task 4: SSO Integration

**Files:**
- Create: `docs/integration/sso-quickstart.md`

**Steps:**
1. Define the minimal OIDC client setup.
2. Walk through discovery, authorize, token, JWKS, userinfo, refresh, and logout.
3. Include copyable environment variables for a business app.
4. Link to existing detailed OIDC docs.

**Verify:** Endpoint paths match `services/identity-service/internal/oidc/service.go`.

### Task 5: SMTP Configuration

**Files:**
- Create: `docs/config/smtp.md`

**Steps:**
1. Explain `console`, `smtp`, and `noop`.
2. Provide a verified 126 Mail 465 implicit TLS recipe.
3. Provide Outlook/Microsoft 365 notes and current STARTTLS limitation.
4. Add troubleshooting guidance for auth, sender, firewall, and provider restrictions.

**Verify:** Variables match `services/identity-service/.env.example` and `internal/mailer/smtp.go`.

### Task 6: Production And Troubleshooting

**Files:**
- Create: `docs/production-checklist.md`
- Create: `docs/troubleshooting.md`

**Steps:**
1. Document production go-live checks.
2. Document common errors and likely fixes.
3. Link back to Quickstart, deployment, SSO, and configuration docs.

**Verify:** No secret values are included and guidance matches current runtime diagnostics.

### Task 7: Link Existing Docs

**Files:**
- Modify: `docs/configuration.md`
- Modify: `services/identity-service/README.md`

**Steps:**
1. Add recipe links near the top of the configuration matrix.
2. Add links from the service README to the new root docs.

**Verify:** Run a link/path check with `rg` and shell existence checks.
