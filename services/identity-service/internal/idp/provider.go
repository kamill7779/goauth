package idp

import "context"

type AuthCodeOptions struct {
	RedirectURI string
}

type TokenSet struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

type ExternalProfile struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Username       string
	DisplayName    string
	AvatarURL      string
}

type Provider interface {
	Slug() string
	DisplayName() string
	AuthCodeURL(state string, opts AuthCodeOptions) (string, error)
	ExchangeCode(ctx context.Context, code string, redirectURI string, state string) (*TokenSet, error)
	FetchProfile(ctx context.Context, token *TokenSet) (*ExternalProfile, error)
}
