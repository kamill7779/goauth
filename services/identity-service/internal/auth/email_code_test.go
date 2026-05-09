package auth

import "testing"

func TestNormalizeEmailCodePurpose(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "blank defaults to register", input: "", want: EmailCodePurposeRegister},
		{name: "register", input: "register", want: EmailCodePurposeRegister},
		{name: "password reset", input: "password_reset", want: EmailCodePurposePasswordReset},
		{name: "case and whitespace", input: " Password_Reset ", want: EmailCodePurposePasswordReset},
		{name: "unsupported", input: "invite", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeEmailCodePurpose(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeEmailCodePurpose() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeEmailCodePurpose() = %q, want %q", got, tt.want)
			}
		})
	}
}
