// Package cache defines Redis key conventions for the identity service.
// All keys are namespaced under "auth:" to avoid collisions in shared Redis instances.
package cache

import "fmt"

func EmailCodeKey(purpose, email string) string {
	return fmt.Sprintf("auth:email_code:%s:%s", purpose, email)
}

func UserCacheKey(userID int64) string {
	return fmt.Sprintf("auth:user:%d", userID)
}

func SessionKey(sessionID string) string {
	return fmt.Sprintf("auth:session:%s", sessionID)
}

func PermissionCacheKey(tenantID, userID int64) string {
	return fmt.Sprintf("auth:permissions:%d:%d", tenantID, userID)
}

func JtiDenylistKey(jti string) string {
	return fmt.Sprintf("auth:jti_denylist:%s", jti)
}

func OIDCStateKey(state string) string {
	return fmt.Sprintf("auth:oidc_state:%s", state)
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
