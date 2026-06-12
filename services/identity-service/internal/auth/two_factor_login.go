package auth

import (
	"context"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	encodingjson "encoding/json"
	"errors"
	"fmt"
	stdhttp "net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"goauth/services/identity-service/internal/cache"
	httpserver "goauth/services/identity-service/internal/http"
	"goauth/services/identity-service/internal/store"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	loginTwoFactorChallengeTTL         = 5 * time.Minute
	loginTwoFactorChallengeLockTTL     = 10 * time.Second
	loginTwoFactorMaxFailedAttempts    = 5
	loginTwoFactorTOTPPeriodSeconds    = 30
	loginTwoFactorTOTPDigits           = 6
	loginTwoFactorMethodTOTP           = "totp"
	loginTwoFactorRecoveryCodeJSONNull = "[]"
)

var (
	errLoginTwoFactorChallengeInvalid = errors.New("two-factor challenge invalid")
	errLoginTwoFactorChallengeBusy    = errors.New("two-factor challenge is already being verified")
	errLoginTwoFactorCodeInvalid      = errors.New("invalid two-factor code")
	errLoginTwoFactorCodeRequired     = errors.New("two-factor code required")
	errLoginTwoFactorCodeMalformed    = errors.New("code must be a 6-digit TOTP code")
)

type loginTwoFactorChallenge struct {
	ID        string
	ExpiresIn int
}

type loginTwoFactorChallengePayload struct {
	UserID   int64 `json:"user_id"`
	Attempts int   `json:"attempts"`
}

func (h *Handler) startLoginTwoFactorChallengeIfRequired(ctx context.Context, userID int64) (*loginTwoFactorChallenge, error) {
	required, err := h.loginTwoFactorRequired(ctx, userID)
	if err != nil || !required {
		return nil, err
	}
	return h.createLoginTwoFactorChallenge(ctx, userID)
}

func (h *Handler) loginTwoFactorRequired(ctx context.Context, userID int64) (bool, error) {
	var record store.UserTwoFactor
	if err := h.service.db.WithContext(ctx).
		Where("user_id = ? AND enabled = ?", userID, true).
		First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return strings.TrimSpace(record.Secret) != "", nil
}

func (h *Handler) createLoginTwoFactorChallenge(ctx context.Context, userID int64) (*loginTwoFactorChallenge, error) {
	if h.service.redis == nil {
		return nil, errors.New("two-factor challenge store unavailable")
	}
	challengeID, err := randomLoginTwoFactorChallengeID()
	if err != nil {
		return nil, err
	}
	payload, err := encodingjson.Marshal(loginTwoFactorChallengePayload{UserID: userID})
	if err != nil {
		return nil, err
	}
	if err := h.service.redis.Set(ctx, cache.LoginTwoFactorChallengeKey(challengeID), payload, loginTwoFactorChallengeTTL).Err(); err != nil {
		return nil, err
	}
	return &loginTwoFactorChallenge{
		ID:        challengeID,
		ExpiresIn: int(loginTwoFactorChallengeTTL.Seconds()),
	}, nil
}

func (h *Handler) loginTwoFactorVerify(c *gin.Context) {
	if h.session == nil {
		httpserver.Error(c, stdhttp.StatusServiceUnavailable, "session service unavailable")
		return
	}

	var request struct {
		ChallengeID  string `json:"challenge_id"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		httpserver.Error(c, stdhttp.StatusBadRequest, err.Error())
		return
	}

	challengeID := strings.TrimSpace(request.ChallengeID)
	if challengeID == "" {
		httpserver.Error(c, stdhttp.StatusBadRequest, "challenge_id is required")
		return
	}
	lockToken, locked, err := h.acquireLoginTwoFactorChallengeLock(c.Request.Context(), challengeID)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	if !locked {
		httpserver.Error(c, stdhttp.StatusConflict, errLoginTwoFactorChallengeBusy.Error())
		return
	}
	defer h.releaseLoginTwoFactorChallengeLock(c.Request.Context(), challengeID, lockToken)

	challenge, err := h.loadLoginTwoFactorChallenge(c.Request.Context(), challengeID)
	if err != nil {
		status := stdhttp.StatusInternalServerError
		if errors.Is(err, errLoginTwoFactorChallengeInvalid) {
			status = stdhttp.StatusBadRequest
		}
		httpserver.Error(c, status, err.Error())
		return
	}

	user, record, err := h.loadLoginTwoFactorUser(c.Request.Context(), challenge.UserID)
	if err != nil {
		_ = h.deleteLoginTwoFactorChallenge(c.Request.Context(), challengeID)
		status := stdhttp.StatusInternalServerError
		if errors.Is(err, errLoginTwoFactorChallengeInvalid) || errors.Is(err, ErrUserDisabled) {
			status = stdhttp.StatusBadRequest
		}
		httpserver.Error(c, status, err.Error())
		return
	}

	verified, err := h.verifyLoginTwoFactorCredential(c.Request.Context(), record, request.Code, request.RecoveryCode)
	if err != nil {
		status := stdhttp.StatusInternalServerError
		if errors.Is(err, errLoginTwoFactorCodeRequired) || errors.Is(err, errLoginTwoFactorCodeMalformed) {
			status = stdhttp.StatusBadRequest
		}
		httpserver.Error(c, status, err.Error())
		return
	}
	if !verified {
		_ = h.recordFailedLoginTwoFactorChallenge(c.Request.Context(), challengeID, challenge)
		httpserver.Error(c, stdhttp.StatusUnauthorized, errLoginTwoFactorCodeInvalid.Error())
		return
	}

	if err := h.deleteLoginTwoFactorChallenge(c.Request.Context(), challengeID); err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	pair, cookieValue, err := h.issueLoginTokens(c.Request.Context(), user)
	if err != nil {
		httpserver.Error(c, stdhttp.StatusInternalServerError, err.Error())
		return
	}
	h.session.SetOIDCAuthorizeCookie(c, cookieValue, int(h.session.OIDCAuthorizeCookieTTL().Seconds()))
	httpserver.Success(c, stdhttp.StatusOK, pair)
}

func (h *Handler) acquireLoginTwoFactorChallengeLock(ctx context.Context, challengeID string) (string, bool, error) {
	if h.service.redis == nil {
		return "", false, errors.New("two-factor challenge store unavailable")
	}
	token, err := randomLoginTwoFactorChallengeID()
	if err != nil {
		return "", false, err
	}
	locked, err := h.service.redis.SetNX(ctx, cache.LoginTwoFactorChallengeLockKey(challengeID), token, loginTwoFactorChallengeLockTTL).Result()
	if err != nil {
		return "", false, err
	}
	return token, locked, nil
}

func (h *Handler) releaseLoginTwoFactorChallengeLock(ctx context.Context, challengeID, token string) {
	if h.service.redis == nil || token == "" {
		return
	}
	key := cache.LoginTwoFactorChallengeLockKey(challengeID)
	_ = h.service.redis.Watch(ctx, func(tx *redis.Tx) error {
		current, err := tx.Get(ctx, key).Result()
		if errors.Is(err, redis.Nil) || current != token {
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, key)
			return nil
		})
		return err
	}, key)
}

func (h *Handler) loadLoginTwoFactorChallenge(ctx context.Context, challengeID string) (*loginTwoFactorChallengePayload, error) {
	if h.service.redis == nil {
		return nil, errors.New("two-factor challenge store unavailable")
	}
	raw, err := h.service.redis.Get(ctx, cache.LoginTwoFactorChallengeKey(challengeID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errLoginTwoFactorChallengeInvalid
		}
		return nil, err
	}
	var payload loginTwoFactorChallengePayload
	if err := encodingjson.Unmarshal(raw, &payload); err != nil || payload.UserID <= 0 {
		return nil, errLoginTwoFactorChallengeInvalid
	}
	return &payload, nil
}

func (h *Handler) recordFailedLoginTwoFactorChallenge(ctx context.Context, challengeID string, payload *loginTwoFactorChallengePayload) error {
	payload.Attempts++
	key := cache.LoginTwoFactorChallengeKey(challengeID)
	if payload.Attempts >= loginTwoFactorMaxFailedAttempts {
		return h.service.redis.Del(ctx, key).Err()
	}
	raw, err := encodingjson.Marshal(payload)
	if err != nil {
		return err
	}
	ttl := h.service.redis.TTL(ctx, key).Val()
	if ttl <= 0 {
		ttl = loginTwoFactorChallengeTTL
	}
	return h.service.redis.Set(ctx, key, raw, ttl).Err()
}

func (h *Handler) deleteLoginTwoFactorChallenge(ctx context.Context, challengeID string) error {
	if h.service.redis == nil {
		return nil
	}
	return h.service.redis.Del(ctx, cache.LoginTwoFactorChallengeKey(challengeID), cache.LoginTwoFactorChallengeLockKey(challengeID)).Err()
}

func (h *Handler) loadLoginTwoFactorUser(ctx context.Context, userID int64) (*store.User, *store.UserTwoFactor, error) {
	var user store.User
	if err := h.service.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, errLoginTwoFactorChallengeInvalid
		}
		return nil, nil, err
	}
	if user.Status == store.UserStatusDisabled {
		return nil, nil, ErrUserDisabled
	}

	var record store.UserTwoFactor
	if err := h.service.db.WithContext(ctx).
		Where("user_id = ? AND enabled = ?", userID, true).
		First(&record).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, errLoginTwoFactorChallengeInvalid
		}
		return nil, nil, err
	}
	if strings.TrimSpace(record.Secret) == "" {
		return nil, nil, errLoginTwoFactorChallengeInvalid
	}
	return &user, &record, nil
}

func (h *Handler) verifyLoginTwoFactorCredential(ctx context.Context, record *store.UserTwoFactor, rawCode, rawRecoveryCode string) (bool, error) {
	if code := strings.TrimSpace(rawCode); code != "" {
		normalized, ok := normalizeLoginTOTPCode(code)
		if !ok {
			return false, errLoginTwoFactorCodeMalformed
		}
		if !verifyLoginTOTPCode(record.Secret, normalized, time.Now().UTC()) {
			return false, nil
		}
		return true, h.touchLoginTwoFactorVerified(ctx, record.UserID)
	}
	if recoveryCode := strings.TrimSpace(rawRecoveryCode); recoveryCode != "" {
		return h.consumeLoginRecoveryCode(ctx, record.UserID, recoveryCode)
	}
	return false, errLoginTwoFactorCodeRequired
}

func (h *Handler) touchLoginTwoFactorVerified(ctx context.Context, userID int64) error {
	now := time.Now().UTC()
	return h.service.db.WithContext(ctx).Model(&store.UserTwoFactor{}).
		Where("user_id = ? AND enabled = ?", userID, true).
		Updates(map[string]any{
			"last_verified_at": now,
			"updated_at":       now,
		}).Error
}

func (h *Handler) consumeLoginRecoveryCode(ctx context.Context, userID int64, rawCode string) (bool, error) {
	var record store.UserTwoFactor
	if err := h.service.db.WithContext(ctx).
		Where("user_id = ? AND enabled = ?", userID, true).
		First(&record).Error; err != nil {
		return false, err
	}
	previousHashes := datatypes.JSON(append([]byte(nil), record.RecoveryCodeHashes...))
	hashes := parseLoginRecoveryCodeHashes(record.RecoveryCodeHashes)
	if len(hashes) == 0 {
		return false, nil
	}
	target := hashLoginRecoveryCode(rawCode)
	index := -1
	for i, hash := range hashes {
		if hmac.Equal([]byte(hash), []byte(target)) {
			index = i
			break
		}
	}
	if index == -1 {
		return false, nil
	}
	remaining := append(hashes[:index:index], hashes[index+1:]...)
	payload, err := encodingjson.Marshal(remaining)
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	result := h.service.db.WithContext(ctx).Model(&store.UserTwoFactor{}).
		Where("user_id = ? AND enabled = ? AND recovery_code_hashes = ?", userID, true, string(previousHashes)).
		Updates(map[string]any{
			"recovery_code_hashes": datatypes.JSON(payload),
			"last_verified_at":     now,
			"updated_at":           now,
		})
	if result.Error != nil {
		return false, result.Error
	}
	if result.RowsAffected == 0 {
		return false, nil
	}
	return true, nil
}

func normalizeLoginTOTPCode(raw string) (string, bool) {
	var builder strings.Builder
	for _, r := range raw {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < '0' || r > '9' {
			return "", false
		}
		builder.WriteRune(r)
	}
	code := builder.String()
	return code, len(code) == loginTwoFactorTOTPDigits
}

func verifyLoginTOTPCode(secret, code string, at time.Time) bool {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	counter := at.Unix() / loginTwoFactorTOTPPeriodSeconds
	for offset := int64(-1); offset <= 1; offset++ {
		if counter+offset < 0 {
			continue
		}
		expected := loginTOTPCodeAt(key, uint64(counter+offset))
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

func loginTOTPCodeAt(key []byte, counter uint64) string {
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", binaryCode%1000000)
}

func parseLoginRecoveryCodeHashes(raw datatypes.JSON) []string {
	if len(raw) == 0 {
		raw = datatypes.JSON([]byte(loginTwoFactorRecoveryCodeJSONNull))
	}
	var hashes []string
	if err := encodingjson.Unmarshal(raw, &hashes); err != nil {
		return nil
	}
	return hashes
}

func hashLoginRecoveryCode(code string) string {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

func randomLoginTwoFactorChallengeID() (string, error) {
	raw := make([]byte, 16)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
