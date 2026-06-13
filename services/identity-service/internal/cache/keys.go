// Package cache defines Redis key conventions for the identity service.
// All keys are namespaced under "auth:" to avoid collisions in shared Redis instances.
package cache

import "fmt"

// EmailCodeKey returns the Redis key for an email verification code.
//
// Call chain: email-code handler → EmailCodeKey → Redis GET/SET
func EmailCodeKey(purpose, email string) string {
	return fmt.Sprintf("auth:email_code:%s:%s", purpose, email)
}

// PermissionCacheKey returns the Redis key for a cached permission set.
//
// Call chain: authorization middleware → PermissionCacheKey → Redis GET/SET
func PermissionCacheKey(tenantID, userID int64) string {
	return fmt.Sprintf("auth:permissions:%d:%d", tenantID, userID)
}

// ExternalLoginExchangeKey returns the Redis key for an external-login exchange code.
//
// Call chain: external-login handler → ExternalLoginExchangeKey → Redis GET/SET
func ExternalLoginExchangeKey(code string) string {
	return fmt.Sprintf("auth:external_login_exchange:%s", code)
}

// ExternalOAuthStateKey returns the Redis key for an OAuth state parameter.
//
// Call chain: OAuth redirect handler → ExternalOAuthStateKey → Redis GET/SET
func ExternalOAuthStateKey(state string) string {
	return fmt.Sprintf("auth:external_oauth_state:%s", state)
}

// LoginTwoFactorChallengeKey returns the Redis key for a 2FA challenge.
//
// Call chain: 2FA handler → LoginTwoFactorChallengeKey → Redis GET/SET
func LoginTwoFactorChallengeKey(challengeID string) string {
	return fmt.Sprintf("auth:login_2fa_challenge:%s", challengeID)
}

// LoginTwoFactorChallengeLockKey returns the Redis key for a 2FA challenge lock.
//
// Call chain: 2FA handler → LoginTwoFactorChallengeLockKey → Redis SETNX
func LoginTwoFactorChallengeLockKey(challengeID string) string {
	return fmt.Sprintf("auth:login_2fa_challenge_lock:%s", challengeID)
}

// RateLimitKey returns the Redis key for a rate-limit counter.
//
// Call chain: rate-limit middleware → RateLimitKey → Redis INCR
func RateLimitKey(scope, key string) string {
	return fmt.Sprintf("auth:rate:%s:%s", scope, key)
}

// LockoutFailuresKey returns the Redis key for the lockout failure counter.
//
// Call chain: lockout.Manager → LockoutFailuresKey → Redis INCR/DEL
func LockoutFailuresKey(userID int64) string {
	return fmt.Sprintf("auth:lockout:failures:%d", userID)
}

// LockoutLockedKey returns the Redis key for the lockout flag.
//
// Call chain: lockout.Manager → LockoutLockedKey → Redis TTL/SETNX/DEL
func LockoutLockedKey(userID int64) string {
	return fmt.Sprintf("auth:lockout:locked:%d", userID)
}
