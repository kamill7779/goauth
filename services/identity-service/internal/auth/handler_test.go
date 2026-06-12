package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/cache"
	"goauth/services/identity-service/internal/captcha"
	"goauth/services/identity-service/internal/config"
	"goauth/services/identity-service/internal/ratelimit"
	"goauth/services/identity-service/internal/session"
	"goauth/services/identity-service/internal/store"
	"gorm.io/datatypes"
)

type failingAuditRecorder struct{}

func (failingAuditRecorder) Record(_ context.Context, _ audit.Entry) error {
	return errors.New("audit unavailable")
}

func TestRegisterRejectsWhenRegistrationDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHandler(nil, nil)
	handler.SetRegistrationMode("disabled")

	router := gin.New()
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body := strings.NewReader(`{"email":"member@example.com","password":"p@ssw0rd!","email_code":"123456"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", body)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "registration disabled") {
		t.Fatalf("expected registration disabled error, got %s", recorder.Body.String())
	}
}

func TestSendCodeRejectsRegisterPurposeWhenRegistrationDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, purpose := range []string{"register", ""} {
		t.Run("purpose="+purpose, func(t *testing.T) {
			handler := NewHandler(nil, nil)
			handler.SetRegistrationMode("invite_only")

			router := gin.New()
			handler.RegisterRoutes(router.Group("/v1/auth"))

			body := `{"purpose":"` + purpose + `","email":"member@example.com"}`
			request := httptest.NewRequest(http.MethodPost, "/v1/auth/email/send-code", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()

			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "registration disabled") {
				t.Fatalf("expected registration disabled error, got %s", recorder.Body.String())
			}
		})
	}
}

func TestLoginRejectsWhenLocalPasswordLoginDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewHandler(nil, nil)
	handler.SetLocalPasswordLoginEnabled(false)

	router := gin.New()
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body := strings.NewReader(`{"email":"member@example.com","password":"p@ssw0rd!"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", body)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "local password login disabled") {
		t.Fatalf("expected local password login disabled error, got %s", recorder.Body.String())
	}
}

func TestCaptchaOnlyAppliesToConfiguredActions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	handler.SetCaptchaVerifier(captcha.NewVerifier(captcha.ProviderTurnstile, "secret"))
	handler.SetCaptchaActions([]string{"login"})

	router := gin.New()
	handler.RegisterRoutes(router.Group("/v1/auth"))

	loginReq := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"member@example.com","password":"p@ssw0rd!"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	router.ServeHTTP(loginRec, loginReq)

	if loginRec.Code != http.StatusForbidden {
		t.Fatalf("login status = %d, want %d body=%s", loginRec.Code, http.StatusForbidden, loginRec.Body.String())
	}
	if !strings.Contains(loginRec.Body.String(), "captcha token required") {
		t.Fatalf("expected login captcha error, got %s", loginRec.Body.String())
	}

	registerReq := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{"email":"member@example.com","password":"p@ssw0rd!","email_code":"123456"}`))
	registerReq.Header.Set("Content-Type", "application/json")
	registerRec := httptest.NewRecorder()
	router.ServeHTTP(registerRec, registerReq)

	if registerRec.Code == http.StatusForbidden && strings.Contains(registerRec.Body.String(), "captcha") {
		t.Fatalf("register should not be blocked by captcha when action disabled: %s", registerRec.Body.String())
	}
}

func TestLoginSetsOIDCAuthorizeCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	sessionService := session.NewService(service.db, config.Config{
		JWTKeyID:            "test-key",
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     30 * 24 * time.Hour,
		BrowserCookieSecure: true,
	}, privateKey)

	hash, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	now := time.Now().UTC()
	user := store.User{
		Email:           "login@example.com",
		DisplayName:     "Login User",
		PasswordHash:    hash,
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	router := gin.New()
	NewHandler(service, sessionService).RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "p@ssw0rd!",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	found := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == session.OIDCAuthorizeCookieName {
			found = true
			if cookie.Value == "" {
				t.Fatal("oidc authorize cookie is empty")
			}
			if !cookie.Secure {
				t.Fatal("expected oidc authorize cookie to be secure")
			}
			if !cookie.HttpOnly {
				t.Fatal("expected oidc authorize cookie to be httpOnly")
			}
		}
	}
	if !found {
		t.Fatal("expected oidc authorize cookie to be set")
	}
}

func TestLoginReturnsTwoFactorChallengeWithoutTokensWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	sessionService := newTestSessionService(t, service, true)
	user := createPasswordUser(t, service, "mfa-login@example.com", "p@ssw0rd!")
	enableTestTwoFactor(t, service, user.ID, "JBSWY3DPEHPK3PXP", nil)

	router := gin.New()
	NewHandler(service, sessionService).RegisterRoutes(router.Group("/v1/auth"))

	recorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login", map[string]string{
		"email":    user.Email,
		"password": "p@ssw0rd!",
	})

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var data map[string]any
	decodeSuccessData(t, recorder.Body.Bytes(), &data)
	if data["two_factor_required"] != true {
		t.Fatalf("two_factor_required = %v, want true in %v", data["two_factor_required"], data)
	}
	if challengeID, ok := data["challenge_id"].(string); !ok || challengeID == "" {
		t.Fatalf("challenge_id missing from response: %v", data)
	}
	if _, ok := data["access_token"]; ok {
		t.Fatalf("login response must not include access_token before 2FA: %v", data)
	}
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == session.OIDCAuthorizeCookieName {
			t.Fatal("OIDC authorize cookie must not be set before 2FA")
		}
	}
}

func TestLoginTwoFactorVerifyIssuesTokensAndConsumesChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	sessionService := newTestSessionService(t, service, true)
	secret := "JBSWY3DPEHPK3PXP"
	user := createPasswordUser(t, service, "mfa-verify@example.com", "p@ssw0rd!")
	enableTestTwoFactor(t, service, user.ID, secret, nil)

	router := gin.New()
	NewHandler(service, sessionService).RegisterRoutes(router.Group("/v1/auth"))

	loginRecorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login", map[string]string{
		"email":    user.Email,
		"password": "p@ssw0rd!",
	})
	challengeID := challengeIDFromLoginResponse(t, loginRecorder)

	verifyRecorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login/2fa/verify", map[string]string{
		"challenge_id": challengeID,
		"code":         testTOTPCode(t, secret, time.Now().UTC()),
	})
	if verifyRecorder.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want %d body=%s", verifyRecorder.Code, http.StatusOK, verifyRecorder.Body.String())
	}

	var tokens session.TokenPair
	decodeSuccessData(t, verifyRecorder.Body.Bytes(), &tokens)
	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.SessionID == "" {
		t.Fatalf("expected token pair after 2FA verification, got %+v", tokens)
	}
	foundCookie := false
	for _, cookie := range verifyRecorder.Result().Cookies() {
		if cookie.Name == session.OIDCAuthorizeCookieName && cookie.Value != "" {
			foundCookie = true
		}
	}
	if !foundCookie {
		t.Fatal("expected OIDC authorize cookie after 2FA verification")
	}

	replayRecorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login/2fa/verify", map[string]string{
		"challenge_id": challengeID,
		"code":         testTOTPCode(t, secret, time.Now().UTC()),
	})
	if replayRecorder.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want %d body=%s", replayRecorder.Code, http.StatusBadRequest, replayRecorder.Body.String())
	}
}

func TestLoginTwoFactorVerifyRejectsChallengeAlreadyBeingVerified(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	sessionService := newTestSessionService(t, service, true)
	secret := "JBSWY3DPEHPK3PXP"
	user := createPasswordUser(t, service, "mfa-locked@example.com", "p@ssw0rd!")
	enableTestTwoFactor(t, service, user.ID, secret, nil)

	router := gin.New()
	NewHandler(service, sessionService).RegisterRoutes(router.Group("/v1/auth"))

	loginRecorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login", map[string]string{
		"email":    user.Email,
		"password": "p@ssw0rd!",
	})
	challengeID := challengeIDFromLoginResponse(t, loginRecorder)
	if err := service.redis.Set(context.Background(), cache.LoginTwoFactorChallengeLockKey(challengeID), "held", time.Minute).Err(); err != nil {
		t.Fatalf("set challenge lock: %v", err)
	}

	verifyRecorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login/2fa/verify", map[string]string{
		"challenge_id": challengeID,
		"code":         testTOTPCode(t, secret, time.Now().UTC()),
	})
	if verifyRecorder.Code != http.StatusConflict {
		t.Fatalf("verify status = %d, want %d body=%s", verifyRecorder.Code, http.StatusConflict, verifyRecorder.Body.String())
	}
}

func TestLoginTwoFactorChallengeLockReleaseRequiresOwnerToken(t *testing.T) {
	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	key := cache.LoginTwoFactorChallengeLockKey("challenge-owner")
	if err := service.redis.Set(context.Background(), key, "new-owner", time.Minute).Err(); err != nil {
		t.Fatalf("set challenge lock: %v", err)
	}

	handler.releaseLoginTwoFactorChallengeLock(context.Background(), "challenge-owner", "old-owner")
	if got, err := service.redis.Get(context.Background(), key).Result(); err != nil || got != "new-owner" {
		t.Fatalf("lock after stale release = %q, %v; want new-owner", got, err)
	}

	handler.releaseLoginTwoFactorChallengeLock(context.Background(), "challenge-owner", "new-owner")
	if service.redis.Exists(context.Background(), key).Val() != 0 {
		t.Fatal("lock should be deleted by owning token")
	}
}

func TestLoginTwoFactorVerifyConsumesRecoveryCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	sessionService := newTestSessionService(t, service, true)
	recoveryCode := "ABCD-EFGH-IJKL"
	user := createPasswordUser(t, service, "mfa-recovery@example.com", "p@ssw0rd!")
	enableTestTwoFactor(t, service, user.ID, "JBSWY3DPEHPK3PXP", []string{testRecoveryCodeHash(recoveryCode)})

	router := gin.New()
	NewHandler(service, sessionService).RegisterRoutes(router.Group("/v1/auth"))

	loginRecorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login", map[string]string{
		"email":    user.Email,
		"password": "p@ssw0rd!",
	})
	challengeID := challengeIDFromLoginResponse(t, loginRecorder)

	verifyRecorder := performJSONRequest(router, http.MethodPost, "/v1/auth/login/2fa/verify", map[string]string{
		"challenge_id":  challengeID,
		"recovery_code": recoveryCode,
	})
	if verifyRecorder.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want %d body=%s", verifyRecorder.Code, http.StatusOK, verifyRecorder.Body.String())
	}

	var record store.UserTwoFactor
	if err := service.db.Where("user_id = ?", user.ID).First(&record).Error; err != nil {
		t.Fatalf("reload two-factor record: %v", err)
	}
	var hashes []string
	if err := json.Unmarshal(record.RecoveryCodeHashes, &hashes); err != nil {
		t.Fatalf("decode recovery hashes: %v", err)
	}
	if len(hashes) != 0 {
		t.Fatalf("recovery hashes = %v, want consumed code removed", hashes)
	}
}

func TestLoginReturnsServerErrorWhenPostAuthWorkFails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	service.audit = failingAuditRecorder{}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	sessionService := session.NewService(service.db, config.Config{
		JWTKeyID:        "test-key",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
	}, privateKey)

	hash, err := HashPassword("p@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	now := time.Now().UTC()
	user := store.User{
		Email:           "audit-failure@example.com",
		DisplayName:     "Audit Failure",
		PasswordHash:    hash,
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	router := gin.New()
	NewHandler(service, sessionService).RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    user.Email,
		"password": "p@ssw0rd!",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusInternalServerError, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "login unavailable") {
		t.Fatalf("expected generic login unavailable error, got %s", recorder.Body.String())
	}
}

func newTestSessionService(t *testing.T, service *Service, secureCookie bool) *session.Service {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return session.NewService(service.db, config.Config{
		JWTKeyID:            "test-key",
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     30 * 24 * time.Hour,
		BrowserCookieSecure: secureCookie,
	}, privateKey)
}

func createPasswordUser(t *testing.T, service *Service, email, password string) store.User {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	now := time.Now().UTC()
	user := store.User{
		Email:           email,
		DisplayName:     "Login User",
		PasswordHash:    hash,
		Status:          store.UserStatusActive,
		EmailVerifiedAt: &now,
	}
	if err := service.db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return user
}

func enableTestTwoFactor(t *testing.T, service *Service, userID int64, secret string, recoveryHashes []string) {
	t.Helper()
	now := time.Now().UTC()
	recoveryPayload, err := json.Marshal(recoveryHashes)
	if err != nil {
		t.Fatalf("json.Marshal(recoveryHashes) error = %v", err)
	}
	if err := service.db.Create(&store.UserTwoFactor{
		UserID:             userID,
		Method:             "totp",
		Secret:             secret,
		Enabled:            true,
		RecoveryCodeHashes: datatypes.JSON(recoveryPayload),
		EnabledAt:          &now,
		LastVerifiedAt:     &now,
	}).Error; err != nil {
		t.Fatalf("create two-factor record: %v", err)
	}
}

func performJSONRequest(router http.Handler, method, path string, payload any) *httptest.ResponseRecorder {
	body, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func decodeSuccessData(t *testing.T, body []byte, out any) {
	t.Helper()
	var envelope struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode success envelope: %v body=%s", err, string(body))
	}
	if !envelope.Success {
		t.Fatalf("success = false body=%s", string(body))
	}
	if err := json.Unmarshal(envelope.Data, out); err != nil {
		t.Fatalf("decode success data: %v body=%s", err, string(body))
	}
}

func challengeIDFromLoginResponse(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var data struct {
		TwoFactorRequired bool   `json:"two_factor_required"`
		ChallengeID       string `json:"challenge_id"`
	}
	decodeSuccessData(t, recorder.Body.Bytes(), &data)
	if !data.TwoFactorRequired || data.ChallengeID == "" {
		t.Fatalf("expected 2FA challenge, got %+v body=%s", data, recorder.Body.String())
	}
	return data.ChallengeID
}

func testTOTPCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode TOTP secret: %v", err)
	}
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", binaryCode%1000000)
}

func testRecoveryCodeHash(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func TestLoginRateLimitReturnsTooManyRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	handler.SetRateLimiter(ratelimit.NewService(service.redis))

	router := gin.New()
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    "missing@example.com",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for i := 0; i < loginRateLimitLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d body=%s", i+1, recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
	}
	if recorder.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header")
	}
	if !strings.Contains(recorder.Body.String(), "rate_limited") {
		t.Fatalf("expected rate_limited error, got %s", recorder.Body.String())
	}
}

func TestLoginRateLimitIgnoresSpoofedForwardedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	handler.SetRateLimiter(ratelimit.NewService(service.redis))

	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatalf("SetTrustedProxies(nil) error = %v", err)
	}
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    "missing@example.com",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for i := 0; i < loginRateLimitLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		request.RemoteAddr = "10.0.0.8:12345"
		request.Header.Set("X-Forwarded-For", "203.0.113."+strconv.Itoa(i+1))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d body=%s", i+1, recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
	}
}

func TestLoginRateLimitUsesTrustedForwardedIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service, _, _ := newTestService(t)
	handler := NewHandler(service, nil)
	handler.SetRateLimiter(ratelimit.NewService(service.redis))

	router := gin.New()
	if err := router.SetTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxies(...) error = %v", err)
	}
	handler.RegisterRoutes(router.Group("/v1/auth"))

	body, err := json.Marshal(map[string]string{
		"email":    "missing@example.com",
		"password": "wrong-password",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for i := 0; i < loginRateLimitLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		request.RemoteAddr = "10.0.0.8:12345"
		request.Header.Set("X-Forwarded-For", "203.0.113.50")
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d body=%s", i+1, recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	request.RemoteAddr = "10.0.0.8:12345"
	request.Header.Set("X-Forwarded-For", "203.0.113.50")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d body=%s", recorder.Code, http.StatusTooManyRequests, recorder.Body.String())
	}
}
