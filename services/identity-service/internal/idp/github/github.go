package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"goauth/services/identity-service/internal/idp"
)

const (
	defaultAuthorizeURL = "https://github.com/login/oauth/authorize"
	defaultTokenURL     = "https://github.com/login/oauth/access_token"
	defaultAPIBaseURL   = "https://api.github.com"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
	AuthorizeURL string
	TokenURL     string
	APIBaseURL   string
	HTTPClient   *http.Client
}

type Provider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	authorizeURL string
	tokenURL     string
	apiBaseURL   string
	httpClient   *http.Client
}

func New(cfg Config) *Provider {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:user", "user:email"}
	}

	authorizeURL := cfg.AuthorizeURL
	if authorizeURL == "" {
		authorizeURL = defaultAuthorizeURL
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = defaultTokenURL
	}
	apiBaseURL := strings.TrimRight(cfg.APIBaseURL, "/")
	if apiBaseURL == "" {
		apiBaseURL = defaultAPIBaseURL
	}

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	return &Provider{
		clientID:     strings.TrimSpace(cfg.ClientID),
		clientSecret: strings.TrimSpace(cfg.ClientSecret),
		redirectURI:  strings.TrimSpace(cfg.RedirectURI),
		scopes:       scopes,
		authorizeURL: authorizeURL,
		tokenURL:     tokenURL,
		apiBaseURL:   apiBaseURL,
		httpClient:   client,
	}
}

func (p *Provider) Slug() string {
	return "github"
}

func (p *Provider) DisplayName() string {
	return "GitHub"
}

func (p *Provider) AuthCodeURL(state string, opts idp.AuthCodeOptions) (string, error) {
	authURL, err := url.Parse(p.authorizeURL)
	if err != nil {
		return "", fmt.Errorf("parse authorize URL: %w", err)
	}

	redirectURI := strings.TrimSpace(opts.RedirectURI)
	if redirectURI == "" {
		redirectURI = p.redirectURI
	}

	query := authURL.Query()
	query.Set("client_id", p.clientID)
	query.Set("scope", strings.Join(p.scopes, " "))
	query.Set("state", state)
	if redirectURI != "" {
		query.Set("redirect_uri", redirectURI)
	}
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

func (p *Provider) ExchangeCode(ctx context.Context, code string, redirectURI string) (*idp.TokenSet, error) {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		redirectURI = p.redirectURI
	}

	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret)
	form.Set("code", strings.TrimSpace(code))
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf("token endpoint status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var token idp.TokenSet
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("missing access token")
	}
	return &token, nil
}

func (p *Provider) FetchProfile(ctx context.Context, token *idp.TokenSet) (*idp.ExternalProfile, error) {
	if token == nil || strings.TrimSpace(token.AccessToken) == "" {
		return nil, errors.New("missing access token")
	}

	var user struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
		Email     string `json:"email"`
	}
	if err := p.getJSON(ctx, token.AccessToken, "/user", &user); err != nil {
		return nil, err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := p.getJSON(ctx, token.AccessToken, "/user/emails", &emails); err != nil {
		return nil, err
	}

	email, verified := resolveEmail(user.Email, emails)
	displayName := strings.TrimSpace(user.Name)
	if displayName == "" {
		displayName = strings.TrimSpace(user.Login)
	}

	return &idp.ExternalProfile{
		Provider:       p.Slug(),
		ProviderUserID: strconv.FormatInt(user.ID, 10),
		Email:          email,
		EmailVerified:  verified,
		Username:       strings.TrimSpace(user.Login),
		DisplayName:    displayName,
		AvatarURL:      strings.TrimSpace(user.AvatarURL),
	}, nil
}

func (p *Provider) getJSON(ctx context.Context, accessToken, path string, target any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiBaseURL+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(accessToken))

	response, err := p.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("github api status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	return json.NewDecoder(response.Body).Decode(target)
}

func resolveEmail(visibleEmail string, emails []struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}) (string, bool) {
	visibleEmail = strings.TrimSpace(visibleEmail)
	if visibleEmail != "" {
		for _, email := range emails {
			if strings.EqualFold(strings.TrimSpace(email.Email), visibleEmail) {
				return strings.TrimSpace(email.Email), email.Verified
			}
		}
		return visibleEmail, false
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return strings.TrimSpace(email.Email), true
		}
	}
	for _, email := range emails {
		if email.Verified {
			return strings.TrimSpace(email.Email), true
		}
	}
	for _, email := range emails {
		if email.Primary {
			return strings.TrimSpace(email.Email), false
		}
	}
	if len(emails) > 0 {
		return strings.TrimSpace(emails[0].Email), emails[0].Verified
	}
	return "", false
}
