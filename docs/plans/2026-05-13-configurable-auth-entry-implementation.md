# Configurable Auth Entry Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make GoAuth login and registration lightweight, configurable, and open-source friendly, with runtime public config, default open registration, optional CAPTCHA, optional GitHub login, and a local console mailer.

**Architecture:** Keep environment variables as the source of truth for the MVP. Add a public auth config endpoint consumed by the frontend at runtime, enforce registration/CAPTCHA/login provider settings in backend handlers, and use Redis-backed short-lived exchange codes for GitHub browser login.

**Tech Stack:** Go 1.24+, Gin, GORM, Redis, React, Vite, Axios, existing GoAuth session/idp/auth packages.

---

## Implementation Notes

- Do not implement MFA, passkeys, Google/Microsoft providers, or editable database-backed settings in this plan.
- Default registration mode is `open`.
- Do not expose secrets in public config.
- Do not put access tokens or refresh tokens in URLs.
- Keep changes scoped to auth entry, config, docs, and focused tests.

## Task 1: Extend Backend Config

**Files:**

- Modify: `services/identity-service/internal/config/config.go`
- Modify: `services/identity-service/internal/config/config_test.go`
- Modify: `services/identity-service/.env.example`
- Modify: `services/identity-service/docker-compose.yml`

**Step 1: Write failing config tests**

Add tests covering defaults and explicit values:

```go
func TestLoadAuthEntryDefaults(t *testing.T) {
    resetConfigEnv(t)

    cfg, err := Load()
    if err != nil {
        t.Fatal(err)
    }

    if cfg.RegistrationMode != "open" {
        t.Fatalf("RegistrationMode = %q, want open", cfg.RegistrationMode)
    }
    if !cfg.LocalPasswordLoginEnabled {
        t.Fatalf("LocalPasswordLoginEnabled = false, want true")
    }
    if cfg.MailerProvider != "console" {
        t.Fatalf("MailerProvider = %q, want console", cfg.MailerProvider)
    }
}

func TestLoadCaptchaActionsAndDefaultGitHubRedirect(t *testing.T) {
    resetConfigEnv(t)
    t.Setenv("PUBLIC_ISSUER_URL", "https://auth.example.com")
    t.Setenv("CAPTCHA_ACTIONS", "login, register, email_code")
    t.Setenv("GITHUB_OAUTH_ENABLED", "true")
    t.Setenv("GITHUB_CLIENT_ID", "client-id")
    t.Setenv("GITHUB_CLIENT_SECRET", "secret")
    t.Setenv("GITHUB_REDIRECT_URI", "")

    cfg, err := Load()
    if err != nil {
        t.Fatal(err)
    }

    assertStringSlice(t, cfg.CaptchaActions, []string{"login", "register", "email_code"})
    if cfg.GitHubRedirectURI != "https://auth.example.com/v1/external/github/callback" {
        t.Fatalf("GitHubRedirectURI = %q", cfg.GitHubRedirectURI)
    }
}
```

**Step 2: Run tests to verify failure**

Run:

```powershell
cd services/identity-service
go test ./internal/config
```

Expected: FAIL because the new config fields do not exist.

**Step 3: Implement config fields**

Add fields:

```go
RegistrationMode          string
LocalPasswordLoginEnabled bool
MailerProvider            string
CaptchaActions            []string
```

Add parsing:

```go
registrationMode := envOrDefault("REGISTRATION_MODE", "open")
if registrationMode != "open" && registrationMode != "invite_only" && registrationMode != "disabled" {
    return Config{}, fmt.Errorf("invalid REGISTRATION_MODE: %s", registrationMode)
}

localPasswordLoginEnabled, err := parseBoolEnv("LOCAL_PASSWORD_LOGIN_ENABLED", true)
if err != nil {
    return Config{}, err
}

mailerProvider := strings.ToLower(strings.TrimSpace(envOrDefault("MAILER_PROVIDER", "console")))
if mailerProvider != "console" && mailerProvider != "smtp" && mailerProvider != "noop" {
    return Config{}, fmt.Errorf("invalid MAILER_PROVIDER: %s", mailerProvider)
}

captchaActions := splitUniqueCSV(envOrDefault("CAPTCHA_ACTIONS", "login,register,email_code,password_forgot"))
```

Default GitHub redirect:

```go
githubRedirectURI := strings.TrimSpace(os.Getenv("GITHUB_REDIRECT_URI"))
if githubOAuthEnabled && githubRedirectURI == "" {
    githubRedirectURI = strings.TrimRight(publicIssuerURL, "/") + "/v1/external/github/callback"
}
```

**Step 4: Update env examples**

Add to `.env.example` and `docker-compose.yml`:

```env
REGISTRATION_MODE=open
LOCAL_PASSWORD_LOGIN_ENABLED=true
MAILER_PROVIDER=console
CAPTCHA_ACTIONS=login,register,email_code,password_forgot
```

**Step 5: Run tests**

Run:

```powershell
cd services/identity-service
go test ./internal/config
```

Expected: PASS.

## Task 2: Add Public Auth Config Endpoint

**Files:**

- Create: `services/identity-service/internal/auth/public_config.go`
- Create: `services/identity-service/internal/auth/public_config_test.go`
- Modify: `services/identity-service/internal/auth/handler.go`
- Modify: `services/identity-service/cmd/server/main.go`

**Step 1: Write failing tests**

Test that public config returns enabled capabilities and hides secrets:

```go
func TestPublicConfigDoesNotExposeSecrets(t *testing.T) {
    h := NewPublicConfigHandler(config.Config{
        RegistrationMode:          "open",
        LocalPasswordLoginEnabled: true,
        CaptchaProvider:           "turnstile",
        CaptchaSiteKey:            "site-key",
        CaptchaSecretKey:          "secret-key",
        CaptchaActions:            []string{"login", "register"},
        GitHubOAuthEnabled:        true,
        GitHubClientID:            "client-id",
        GitHubClientSecret:        "client-secret",
        PasswordMinLength:         8,
        PasswordRequireDigit:      true,
    })

    router := gin.New()
    h.RegisterRoutes(router.Group("/v1/auth"))

    rec := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/v1/auth/public-config", nil)
    router.ServeHTTP(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("status = %d", rec.Code)
    }
    body := rec.Body.String()
    if strings.Contains(body, "secret-key") || strings.Contains(body, "client-secret") {
        t.Fatalf("public config leaked secret: %s", body)
    }
}
```

**Step 2: Run test to verify failure**

Run:

```powershell
cd services/identity-service
go test ./internal/auth -run PublicConfig
```

Expected: FAIL because handler does not exist.

**Step 3: Implement handler**

Create a small handler:

```go
type PublicConfigHandler struct {
    cfg config.Config
}

func NewPublicConfigHandler(cfg config.Config) *PublicConfigHandler {
    return &PublicConfigHandler{cfg: cfg}
}

func (h *PublicConfigHandler) RegisterRoutes(router gin.IRoutes) {
    router.GET("/public-config", h.get)
}
```

Response shape:

```go
gin.H{
    "registration": gin.H{"mode": h.cfg.RegistrationMode},
    "local_login": gin.H{"enabled": h.cfg.LocalPasswordLoginEnabled},
    "captcha": gin.H{
        "provider": h.cfg.CaptchaProvider,
        "site_key": h.cfg.CaptchaSiteKey,
        "actions": h.cfg.CaptchaActions,
    },
    "external_providers": providers,
    "password_policy": gin.H{
        "min_length": h.cfg.PasswordMinLength,
        "require_uppercase": h.cfg.PasswordRequireUpper,
        "require_lowercase": h.cfg.PasswordRequireLower,
        "require_digit": h.cfg.PasswordRequireDigit,
        "require_special": h.cfg.PasswordRequireSpecial,
    },
}
```

Only include GitHub provider when `GitHubOAuthEnabled` is true and `GitHubClientID` is not empty.

**Step 4: Register route**

In `cmd/server/main.go`, register:

```go
authPublicConfigHandler := auth.NewPublicConfigHandler(cfg)
authPublicConfigHandler.RegisterRoutes(authGroup)
```

This must be registered even when Redis is nil.

**Step 5: Run tests**

Run:

```powershell
cd services/identity-service
go test ./internal/auth -run PublicConfig
```

Expected: PASS.

## Task 3: Add Console Mailer

**Files:**

- Modify: `services/identity-service/internal/mailer/mailer.go`
- Create: `services/identity-service/internal/mailer/console_test.go`
- Modify: `services/identity-service/cmd/server/main.go`

**Step 1: Write failing tests**

```go
func TestConsoleSenderWritesMessage(t *testing.T) {
    var buf bytes.Buffer
    sender := mailer.NewConsoleSender(slog.New(slog.NewTextHandler(&buf, nil)))

    err := sender.Send(context.Background(), mailer.Message{
        To:      "member@example.com",
        Subject: "GoAuth verification code",
        Body:    "123456",
    })
    if err != nil {
        t.Fatal(err)
    }

    out := buf.String()
    if !strings.Contains(out, "member@example.com") || !strings.Contains(out, "123456") {
        t.Fatalf("console mail output = %q", out)
    }
}
```

**Step 2: Run test to verify failure**

Run:

```powershell
cd services/identity-service
go test ./internal/mailer -run Console
```

Expected: FAIL because `NewConsoleSender` does not exist.

**Step 3: Implement console sender**

Add:

```go
type ConsoleSender struct {
    logger *slog.Logger
}

func NewConsoleSender(logger *slog.Logger) ConsoleSender {
    if logger == nil {
        logger = slog.Default()
    }
    return ConsoleSender{logger: logger}
}

func (s ConsoleSender) Send(ctx context.Context, message Message) error {
    s.logger.InfoContext(ctx, "mail message",
        "to", message.To,
        "subject", message.Subject,
        "body", message.Body,
    )
    return nil
}
```

**Step 4: Wire `MAILER_PROVIDER`**

Update `buildMailSender`:

```go
switch cfg.MailerProvider {
case "noop":
    return mailer.NoopSender{}
case "smtp":
    return mailer.NewSMTPSender(...)
case "console":
    return mailer.NewConsoleSender(nil)
default:
    return mailer.NewConsoleSender(nil)
}
```

If `MAILER_PROVIDER=smtp` but SMTP required fields are missing, return `NoopSender` only if that is existing behavior, or prefer failing startup in a follow-up task. For MVP, document that `console` is default and `smtp` requires SMTP variables.

**Step 5: Run tests**

Run:

```powershell
cd services/identity-service
go test ./internal/mailer
```

Expected: PASS.

## Task 4: Enforce Registration and Local Login Settings

**Files:**

- Modify: `services/identity-service/internal/auth/handler.go`
- Modify: `services/identity-service/internal/auth/handler_test.go`
- Modify: `services/identity-service/cmd/server/main.go`

**Step 1: Write failing handler tests**

Add tests:

```go
func TestRegisterRejectsWhenRegistrationDisabled(t *testing.T) {
    handler := NewHandler(service, nil)
    handler.SetRegistrationMode("disabled")

    // POST /register with valid-looking JSON
    // Expected: 403
}

func TestLoginRejectsWhenLocalPasswordLoginDisabled(t *testing.T) {
    handler := NewHandler(service, nil)
    handler.SetLocalPasswordLoginEnabled(false)

    // POST /login with valid-looking JSON
    // Expected: 403
}
```

**Step 2: Run tests to verify failure**

Run:

```powershell
cd services/identity-service
go test ./internal/auth -run "RegisterRejects|LoginRejects"
```

Expected: FAIL because settings are not implemented.

**Step 3: Implement handler fields**

Add to `Handler`:

```go
registrationMode string
localPasswordLoginEnabled bool
```

Defaults in `NewHandler`:

```go
registrationMode: "open",
localPasswordLoginEnabled: true,
```

Setters:

```go
func (h *Handler) SetRegistrationMode(mode string) { ... }
func (h *Handler) SetLocalPasswordLoginEnabled(enabled bool) { ... }
```

Enforce:

```go
if h.registrationMode != "open" {
    c.JSON(http.StatusForbidden, gin.H{"error": "registration disabled"})
    return
}
```

```go
if !h.localPasswordLoginEnabled {
    c.JSON(http.StatusForbidden, gin.H{"error": "local password login disabled"})
    return
}
```

**Step 4: Wire from config**

In `cmd/server/main.go`:

```go
authHandler.SetRegistrationMode(cfg.RegistrationMode)
authHandler.SetLocalPasswordLoginEnabled(cfg.LocalPasswordLoginEnabled)
```

**Step 5: Run tests**

Run:

```powershell
cd services/identity-service
go test ./internal/auth
```

Expected: PASS.

## Task 5: Gate CAPTCHA by Configured Actions

**Files:**

- Modify: `services/identity-service/internal/auth/handler.go`
- Modify: `services/identity-service/internal/auth/handler_test.go`
- Modify: `services/identity-service/internal/captcha/verifier.go` if needed

**Step 1: Write failing tests**

Test that CAPTCHA is required only for configured actions:

```go
func TestCaptchaOnlyAppliesToConfiguredActions(t *testing.T) {
    handler := NewHandler(service, nil)
    handler.SetCaptchaVerifier(fakeVerifier)
    handler.SetCaptchaActions([]string{"login"})

    // /login without captcha -> 403
    // /register without captcha -> does not fail at captcha layer
}
```

**Step 2: Run tests to verify failure**

Run:

```powershell
cd services/identity-service
go test ./internal/auth -run Captcha
```

Expected: FAIL because all auth routes currently use the same captcha middleware.

**Step 3: Implement action-aware middleware**

Add:

```go
func (h *Handler) captchaMWFor(action string) gin.HandlerFunc {
    if !h.captchaActionEnabled(action) {
        return func(c *gin.Context) { c.Next() }
    }
    return h.captchaMW()
}
```

Register:

```go
router.POST("/email/send-code", h.captchaMWFor("email_code"), h.sendCode)
router.POST("/register", h.captchaMWFor("register"), h.register)
router.POST("/login", h.captchaMWFor("login"), h.login)
router.POST("/password/forgot", h.captchaMWFor("password_forgot"), h.forgotPassword)
```

**Step 4: Wire from config**

In `cmd/server/main.go`:

```go
authHandler.SetCaptchaActions(cfg.CaptchaActions)
```

**Step 5: Run tests**

Run:

```powershell
cd services/identity-service
go test ./internal/auth ./internal/captcha
```

Expected: PASS.

## Task 6: Add External Login Exchange Service

**Files:**

- Create: `services/identity-service/internal/idp/exchange.go`
- Create: `services/identity-service/internal/idp/exchange_test.go`
- Modify: `services/identity-service/internal/cache/keys.go`

**Step 1: Write failing tests**

```go
func TestExchangeStoreConsumesCodeOnce(t *testing.T) {
    redis := miniredis.RunT(t)
    client := redisclient.NewClient(&redisclient.Options{Addr: redis.Addr()})
    store := idp.NewExchangeStore(client)

    code, err := store.Save(context.Background(), idp.ExchangePayload{
        Provider: "github",
        Tokens: session.TokenPair{
            AccessToken: "access",
            RefreshToken: "refresh",
            SessionID: "sid",
        },
        ReturnTo: "/admin",
    })
    if err != nil {
        t.Fatal(err)
    }

    payload, err := store.Consume(context.Background(), code)
    if err != nil {
        t.Fatal(err)
    }
    if payload.Provider != "github" {
        t.Fatalf("provider = %q", payload.Provider)
    }
    if _, err := store.Consume(context.Background(), code); !errors.Is(err, idp.ErrExchangeCodeInvalid) {
        t.Fatalf("second consume err = %v", err)
    }
}
```

**Step 2: Run test to verify failure**

Run:

```powershell
cd services/identity-service
go test ./internal/idp -run Exchange
```

Expected: FAIL because exchange store does not exist.

**Step 3: Implement cache key**

Add:

```go
func ExternalLoginExchangeKey(code string) string {
    return fmt.Sprintf("auth:external_login_exchange:%s", code)
}
```

**Step 4: Implement exchange store**

Use:

- 32 random bytes hex/base64url code.
- TTL 60 seconds.
- `SET key payload EX 60s`.
- `GETDEL` if available through Redis client, or `GET` then `DEL`.

Expose:

```go
type ExchangeStore struct { client *redis.Client }
func NewExchangeStore(client *redis.Client) *ExchangeStore
func (s *ExchangeStore) Save(ctx context.Context, payload ExchangePayload) (string, error)
func (s *ExchangeStore) Consume(ctx context.Context, code string) (*ExchangePayload, error)
```

**Step 5: Run tests**

Run:

```powershell
cd services/identity-service
go test ./internal/idp -run Exchange
```

Expected: PASS.

## Task 7: Productize GitHub Browser Callback

**Files:**

- Modify: `services/identity-service/internal/idp/handler.go`
- Modify: `services/identity-service/internal/idp/handler_test.go`
- Modify: `services/identity-service/cmd/server/main.go`

**Step 1: Write failing tests**

Add tests for:

- `/start?return_to=/oauth2/authorize?...` preserves return target in state storage.
- `/callback` creates exchange code and redirects to `/external/callback?provider=github&code=...`.
- `/exchange` consumes code and returns token pair once.
- JSON fallback remains available for non-browser tests if needed.

Example assertion:

```go
if rec.Code != http.StatusFound {
    t.Fatalf("status = %d, want 302", rec.Code)
}
location := rec.Header().Get("Location")
if !strings.HasPrefix(location, "/external/callback?provider=github&code=") {
    t.Fatalf("Location = %q", location)
}
```

**Step 2: Run tests to verify failure**

Run:

```powershell
cd services/identity-service
go test ./internal/idp -run "Callback|Exchange|Start"
```

Expected: FAIL because browser exchange flow does not exist.

**Step 3: Extend handler dependencies**

Add optional exchange store:

```go
exchangeStore *ExchangeStore
frontendCallbackPath string
```

Constructor may accept options or use setters:

```go
func (h *Handler) SetExchangeStore(store *ExchangeStore)
func (h *Handler) SetFrontendCallbackPath(path string)
```

Default callback path:

```text
/external/callback
```

**Step 4: Preserve `return_to`**

Store `return_to` alongside OAuth state. Prefer Redis if available through exchange store, otherwise encode a signed/HttpOnly state cookie. For MVP with Redis available, add state payload storage:

```text
auth:external_oauth_state:<state>
```

TTL: 10 minutes.

Payload:

```json
{"return_to": "..."}
```

Keep the existing state cookie check for CSRF.

**Step 5: Redirect callback with exchange code**

After `IssueTokens` succeeds:

```go
code, err := h.exchangeStore.Save(ctx, ExchangePayload{
    Provider: "github",
    Tokens: *pair,
    User: result.User,
    ReturnTo: returnTo,
})
```

Then:

```go
c.Redirect(http.StatusFound, "/external/callback?provider=github&code="+url.QueryEscape(code))
```

**Step 6: Add exchange route**

Register:

```go
external.POST("/exchange", h.exchange)
```

Request:

```json
{"code":"..."}
```

Response:

```json
{
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "session_id": "..."
  },
  "return_to": "/oauth2/authorize?...",
  "user": {
    "id": 1,
    "email": "member@example.com"
  }
}
```

**Step 7: Wire exchange store**

In `cmd/server/main.go`, when GitHub is configured and Redis is available:

```go
idpHandler := idp.NewHandler(...)
idpHandler.SetExchangeStore(idp.NewExchangeStore(redisClient))
```

If Redis is nil, browser exchange should return 503 rather than leaking tokens in URLs.

**Step 8: Run tests**

Run:

```powershell
cd services/identity-service
go test ./internal/idp
```

Expected: PASS.

## Task 8: Add Frontend Public Config Client

**Files:**

- Create: `frontend/src/types/publicConfig.ts`
- Create: `frontend/src/api/publicConfig.ts`
- Create: `frontend/tests/publicConfig.test.mjs`

**Step 1: Write failing adapter tests**

```js
test('normalizePublicConfig fills safe defaults', () => {
  const cfg = normalizePublicConfig({})
  assert.equal(cfg.registration.mode, 'open')
  assert.equal(cfg.local_login.enabled, true)
  assert.deepEqual(cfg.external_providers, [])
})
```

**Step 2: Run test to verify failure**

Run:

```powershell
cd frontend
npm run test:admin -- --test-name-pattern publicConfig
```

If the test runner does not support a name pattern, run the project test command after adding the test.

Expected: FAIL because files do not exist.

**Step 3: Implement types and client**

Types:

```ts
export interface PublicAuthConfig {
  registration: { mode: 'open' | 'invite_only' | 'disabled' }
  local_login: { enabled: boolean }
  captcha: { provider: string; site_key: string; actions: string[] }
  external_providers: Array<{ slug: string; display_name: string; start_url: string }>
  password_policy: {
    min_length: number
    require_uppercase: boolean
    require_lowercase: boolean
    require_digit: boolean
    require_special: boolean
  }
}
```

Client should call:

```text
GET ${API_BASE_URL}/v1/auth/public-config
```

**Step 4: Run tests**

Run:

```powershell
cd frontend
npm run test:admin
```

Expected: PASS.

## Task 9: Add Turnstile Runtime Bridge

**Files:**

- Create: `frontend/src/components/auth/TurnstileCaptcha.tsx`
- Modify: `frontend/src/pages/LoginPage.tsx`
- Create or modify: `frontend/tests/authApi.test.mjs`

**Step 1: Write failing tests**

Cover that CAPTCHA token is requested only when config enables the action. Use existing API tests where possible:

```js
test('login forwards captcha token when runtime config enables login captcha', async () => {
  // mock bridge returns captcha-proof
  // call login submit path or direct auth API with options
  // assert X-Captcha-Token
})
```

**Step 2: Run test to verify failure**

Run:

```powershell
cd frontend
npm run test:admin
```

Expected: FAIL until runtime config wiring exists.

**Step 3: Implement Turnstile component**

Load script when provider is `turnstile`:

```text
https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit
```

Expose a bridge compatible with current login page:

```ts
window.__goauthCaptcha = {
  getToken: async ({ action }) => {
    // return cached or newly executed token for action
  },
}
```

For hCaptcha/reCAPTCHA, keep provider unsupported in UI for MVP unless already easy to implement. Public config can expose provider, but frontend should show a clear error if provider is not implemented client-side.

**Step 4: Use public config in LoginPage**

Replace build-time CAPTCHA decision with runtime config:

```ts
const captchaEnabled = authConfig.captcha.provider && authConfig.captcha.actions.includes(action)
```

**Step 5: Run tests**

Run:

```powershell
cd frontend
npm run test:admin
npm run build
```

Expected: PASS.

## Task 10: Add GitHub Login Button and Callback Page

**Files:**

- Modify: `frontend/src/pages/LoginPage.tsx`
- Modify: `frontend/src/App.tsx`
- Create: `frontend/src/pages/ExternalCallbackPage.tsx`
- Modify: `frontend/src/api/auth.ts`
- Create: `frontend/tests/externalCallback.test.mjs`

**Step 1: Write failing tests**

Test:

- GitHub button is hidden when `external_providers` is empty.
- GitHub button uses `start_url` and preserves `return_to`.
- Callback page exchanges code, stores tokens, and redirects.

**Step 2: Run tests to verify failure**

Run:

```powershell
cd frontend
npm run test:admin
```

Expected: FAIL because callback page and config-driven button do not exist.

**Step 3: Add exchange API**

```ts
export async function exchangeGitHubLogin(code: string): Promise<{
  tokens: LoginResponse
  return_to: string
  user: { id: number; email: string }
}> {
  return apiPostV1('/external/github/exchange', { code })
}
```

Add `apiPostV1` or an equivalent generic helper in `frontend/src/api/client.ts`, because the existing `apiPost` helper is scoped to `/v1/auth`. The final URL must be:

```text
/v1/external/github/exchange
```

**Step 4: Add callback route**

In `App.tsx`:

```tsx
<Route path="/external/callback" element={<ExternalCallbackPage />} />
```

**Step 5: Implement callback page**

Behavior:

- Missing code: show error and link back to login.
- Exchange success: save `access_token` and `refresh_token`.
- Redirect to sanitized `return_to` if present, else `/admin`.
- Exchange failure: show readable error.

**Step 6: Add GitHub button**

Render from public config:

```tsx
const github = authConfig.external_providers.find(p => p.slug === 'github')
```

On click:

```ts
const url = new URL(github.start_url, API_BASE_URL)
if (returnTo) url.searchParams.set('return_to', returnTo)
window.location.assign(url.toString())
```

**Step 7: Run tests**

Run:

```powershell
cd frontend
npm run test:admin
npm run build
```

Expected: PASS.

## Task 11: Replace Fake Settings With Read-Only Runtime Status

**Files:**

- Modify: `frontend/src/pages/Admin/SettingsPage.tsx`
- Modify: `frontend/tests/adminPageState.test.mjs` or create focused settings test

**Step 1: Write failing tests**

Test that settings page displays public config values and does not render fake toggles for settings that are not writable.

**Step 2: Run test to verify failure**

Run:

```powershell
cd frontend
npm run test:admin
```

Expected: FAIL until SettingsPage uses real config.

**Step 3: Implement read-only settings**

Display:

- Registration mode.
- Local password login enabled.
- CAPTCHA provider/actions.
- GitHub provider enabled.
- Password policy.

Remove local-only toggles or mark them explicitly read-only.

**Step 4: Run tests**

Run:

```powershell
cd frontend
npm run test:admin
```

Expected: PASS.

## Task 12: Update Documentation

**Files:**

- Modify: `README.md`
- Modify: `services/identity-service/README.md`
- Modify: `docs/design.md` if it still describes old required config only
- Modify: `services/identity-service/.env.example`

**Step 1: Add docs for local quick start**

Document:

```powershell
cd services/identity-service
docker compose up --build
```

Explain that default registration is open and verification codes are printed to logs when `MAILER_PROVIDER=console`.

**Step 2: Add GitHub setup docs**

Document:

```env
GITHUB_OAUTH_ENABLED=true
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

Callback URL:

```text
https://your-auth-domain.example.com/v1/external/github/callback
```

**Step 3: Add Turnstile setup docs**

Document:

```env
CAPTCHA_PROVIDER=turnstile
CAPTCHA_SITE_KEY=...
CAPTCHA_SECRET_KEY=...
CAPTCHA_ACTIONS=login,register,email_code,password_forgot
```

**Step 4: Add production recommendations**

Document:

```env
APP_ENV=production
REGISTRATION_MODE=invite_only
MAILER_PROVIDER=smtp
CAPTCHA_PROVIDER=turnstile
BROWSER_COOKIE_SECURE=true
```

**Step 5: Validate docs references**

Run:

```powershell
rg -n "REGISTRATION_MODE|MAILER_PROVIDER|CAPTCHA_ACTIONS|public-config|GitHub" README.md services/identity-service/README.md docs
```

Expected: New config keys and flows are documented.

## Task 13: Full Verification

**Files:**

- No new files.

**Step 1: Run backend tests**

Run:

```powershell
cd services/identity-service
go test ./...
```

Expected: PASS.

**Step 2: Run frontend tests**

Run:

```powershell
cd frontend
npm run test:admin
```

Expected: PASS.

**Step 3: Run frontend build**

Run:

```powershell
cd frontend
npm run build
```

Expected: PASS.

**Step 4: Manual smoke test**

Run local service and verify:

```text
GET /v1/auth/public-config
POST /v1/auth/email/send-code
POST /v1/auth/register
POST /v1/auth/login
GET /v1/external/github/start
```

Expected:

- Public config has no secrets.
- Console mailer prints code locally.
- Open registration works.
- GitHub start redirects when configured.
- CAPTCHA blocks only configured actions.

## Implementation Handoff Prompt

Use this prompt in a fresh implementation session:

```text
You are implementing the GoAuth configurable auth entry MVP on branch docs/configurable-auth-entry.

Read:
- docs/plans/2026-05-13-configurable-auth-entry-design.md
- docs/plans/2026-05-13-configurable-auth-entry-implementation.md

Required skill:
- Use superpowers:executing-plans and execute the implementation plan task by task.

Goal:
Make login/registration open-source friendly and configurable:
- REGISTRATION_MODE defaults to open.
- LOCAL_PASSWORD_LOGIN_ENABLED defaults to true.
- MAILER_PROVIDER defaults to console so local users can see verification codes in logs.
- Add GET /v1/auth/public-config with no secrets.
- Make CAPTCHA action-gated and driven by runtime public config.
- Add optional GitHub browser login using a Redis-backed 60-second exchange code. Never put tokens in URLs.
- Make the frontend login page render login/register/GitHub/CAPTCHA from public config instead of build-time VITE_CAPTCHA_PROVIDER.
- Replace fake SettingsPage toggles with read-only runtime status for this MVP.
- Update README and service docs.

Constraints:
- Do not implement MFA, passkeys, Google/Microsoft providers, or editable database settings.
- Keep changes small and match existing GoAuth patterns.
- Use tests first for each task.
- Run final verification:
  cd services/identity-service; go test ./...
  cd frontend; npm run test:admin
  cd frontend; npm run build

Report changed files, test results, and any intentionally deferred work.
```
