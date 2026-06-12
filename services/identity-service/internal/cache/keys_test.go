package cache

import "testing"

func TestTypedKeyHelpers(t *testing.T) {
	if got := EmailCodeKey("register", "user@example.com"); got != "auth:email_code:register:user@example.com" {
		t.Fatalf("EmailCodeKey() = %q", got)
	}
	if got := PermissionCacheKey(8, 12); got != "auth:permissions:8:12" {
		t.Fatalf("PermissionCacheKey() = %q", got)
	}

	if got := RateLimitKey("auth_login", "127.0.0.1|user@example.com"); got != "auth:rate:auth_login:127.0.0.1|user@example.com" {
		t.Fatalf("RateLimitKey() = %q", got)
	}
}
