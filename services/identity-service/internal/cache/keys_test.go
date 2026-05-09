package cache

import "testing"

func TestTypedKeyHelpers(t *testing.T) {
	if got := EmailCodeKey("register", "user@example.com"); got != "auth:email_code:register:user@example.com" {
		t.Fatalf("EmailCodeKey() = %q", got)
	}
	if got := UserCacheKey(11); got != "auth:user:11" {
		t.Fatalf("UserCacheKey() = %q", got)
	}
	if got := SessionKey("session-1"); got != "auth:session:session-1" {
		t.Fatalf("SessionKey() = %q", got)
	}
	if got := PermissionCacheKey(8, 12); got != "auth:permissions:8:12" {
		t.Fatalf("PermissionCacheKey() = %q", got)
	}
	if got := JtiDenylistKey("jti-1"); got != "auth:jti_denylist:jti-1" {
		t.Fatalf("JtiDenylistKey() = %q", got)
	}
	if got := OIDCStateKey("state-1"); got != "auth:oidc_state:state-1" {
		t.Fatalf("OIDCStateKey() = %q", got)
	}
	if got := RateLimitKey("auth_login", "127.0.0.1|user@example.com"); got != "auth:rate:auth_login:127.0.0.1|user@example.com" {
		t.Fatalf("RateLimitKey() = %q", got)
	}
}
