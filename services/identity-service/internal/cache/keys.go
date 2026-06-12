// Package cache defines Redis key conventions for the identity service.
// All keys are namespaced under "auth:" to avoid collisions in shared Redis instances.
package cache

import "fmt"

func EmailCodeKey(purpose, email string) string {
	return fmt.Sprintf("auth:email_code:%s:%s", purpose, email)
}

func PermissionCacheKey(tenantID, userID int64) string {
	return fmt.Sprintf("auth:permissions:%d:%d", tenantID, userID)
}

func ExternalLoginExchangeKey(code string) string {
	return fmt.Sprintf("auth:external_login_exchange:%s", code)
}

func ExternalOAuthStateKey(state string) string {
	return fmt.Sprintf("auth:external_oauth_state:%s", state)
}

func LoginTwoFactorChallengeKey(challengeID string) string {
	return fmt.Sprintf("auth:login_2fa_challenge:%s", challengeID)
}

func LoginTwoFactorChallengeLockKey(challengeID string) string {
	return fmt.Sprintf("auth:login_2fa_challenge_lock:%s", challengeID)
}

func RateLimitKey(scope, key string) string {
	return fmt.Sprintf("auth:rate:%s:%s", scope, key)
}

func LockoutFailuresKey(userID int64) string {
	return fmt.Sprintf("auth:lockout:failures:%d", userID)
}

func LockoutLockedKey(userID int64) string {
	return fmt.Sprintf("auth:lockout:locked:%d", userID)
}
