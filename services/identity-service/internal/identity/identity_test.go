package identity

import (
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"alice@example.com", "alice@example.com"},
		{"ALICE@EXAMPLE.COM", "alice@example.com"},
		{"  Alice@Example.Com  ", "alice@example.com"},
		{"", ""},
		{"  ", ""},
		{"no-at-sign", "no-at-sign"},
	}
	for _, tc := range tests {
		got := NormalizeEmail(tc.input)
		if got != tc.expected {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestNormalizeUsername(t *testing.T) {
	tests := []struct {
		input    string
		want    string
		wantErr bool
	}{
		{"kamuii", "kamuii", false},
		{"  Kamuii  ", "kamuii", false},
		{"kam_uii", "kam_uii", false},
		{"kam-uii", "kam-uii", false},
		{"ab", "", true},             // too short
		{"a-b", "a-b", false},        // 3 chars ok
		{"a_b", "a_b", false},
		{"a", "", true},              // 1 char
		{"user name", "", true},      // space
		{"kam@uii", "", true},        // @
		{"kamuii!", "", true},        // special char
		{"KAMUII_123", "kamuii_123", false},
		{"-kamuii", "kamuii", false}, // leading dash stripped
		{"kamuii-", "kamuii", false}, // trailing dash stripped
		{"_test_", "test", false},
		{"kamuii.kamuii", "", true},  // dot not allowed by public validation
	}
	for _, tc := range tests {
		got, err := NormalizeUsername(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("NormalizeUsername(%q) = (%q, nil), want error", tc.input, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeUsername(%q) error = %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("NormalizeUsername(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestNormalizeNickname(t *testing.T) {
	tests := []struct {
		nickname string
		fallback string
		want     string
	}{
		{"张三", "kamuii", "张三"},
		{"  Alice  ", "alice", "Alice"},
		{"", "fallback-user", "fallback-user"},
		{"  ", "fallback-user", "fallback-user"},
		{"卡密", "kamuii", "卡密"},
		{"", "", ""},
	}
	for _, tc := range tests {
		got := NormalizeNickname(tc.nickname, tc.fallback)
		if got != tc.want {
			t.Errorf("NormalizeNickname(%q, %q) = %q, want %q", tc.nickname, tc.fallback, got, tc.want)
		}
	}
}

func TestUsernameFromEmail(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{"alice@example.com", "alice"},
		{"BOB@example.com", "bob"},
		{"kam.uii@example.com", "kam-uii"},
		{"kam+tag@example.com", "kam-tag"},
		{"_test_@example.com", "test"},
		{".hidden@example.com", "hidden"},
		{"ab@example.com", ""},           // < 3 chars
		{"a@b.com", ""},
		{"@example.com", ""},
		{"noat", ""},
		{"", ""},
		{"+onlyplus@example.com", "onlyplus"},
	}
	for _, tc := range tests {
		got := UsernameFromEmail(tc.email)
		if got != tc.want {
			t.Errorf("UsernameFromEmail(%q) = %q, want %q", tc.email, got, tc.want)
		}
	}
}

func TestIsUsernameLikeIdentifier(t *testing.T) {
	tests := []struct {
		identifier string
		want       bool
	}{
		{"kamuii", true},
		{"kam_uii", true},
		{"kamuii123", true},
		{"kamuii@example.com", false},
		{"alice@test.org", false},
		{"", false},
	}
	for _, tc := range tests {
		got := IsUsernameLikeIdentifier(tc.identifier)
		if got != tc.want {
			t.Errorf("IsUsernameLikeIdentifier(%q) = %v, want %v", tc.identifier, got, tc.want)
		}
	}
}
