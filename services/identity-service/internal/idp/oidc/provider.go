// Package oidc provides a generic OpenID Connect external identity provider
// adapter that implements the idp.Provider interface.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/golang-jwt/jwt/v5"
	idppkg "goauth/services/identity-service/internal/idp"
)

// Config holds the configuration for a generic OIDC provider.
type Config struct {
	Slug         string
	DisplayName  string
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// discoveryDoc is the OpenID Connect discovery document.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// tokenResponse is the OAuth2 token endpoint response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Provider implements idp.Provider for any OIDC-compliant identity provider.
type Provider struct {
	cfg       Config
	discovery discoveryDoc
	jwks      *jose.JSONWebKeySet
	client    *http.Client
	pkceMu    sync.Mutex
	pkce      map[string]pkceVerifier
}

type pkceVerifier struct {
	value     string
	expiresAt time.Time
}

const pkceVerifierTTL = 10 * time.Minute

// New creates a Provider by fetching and caching the discovery document and JWKS.
func New(cfg Config) (*Provider, error) {
	if cfg.DiscoveryURL == "" {
		return nil, fmt.Errorf("oidc provider %q: discovery_url is required", cfg.Slug)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}

	p := &Provider{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		pkce:   make(map[string]pkceVerifier),
	}

	if err := p.fetchDiscovery(); err != nil {
		return nil, fmt.Errorf("oidc provider %q: fetch discovery: %w", cfg.Slug, err)
	}
	if err := p.fetchJWKS(); err != nil {
		return nil, fmt.Errorf("oidc provider %q: fetch jwks: %w", cfg.Slug, err)
	}
	return p, nil
}

func (p *Provider) fetchDiscovery() error {
	resp, err := p.client.Get(p.cfg.DiscoveryURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, &p.discovery)
}

func (p *Provider) fetchJWKS() error {
	if p.discovery.JwksURI == "" {
		return nil
	}
	resp, err := p.client.Get(p.discovery.JwksURI)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var ks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &ks); err != nil {
		return err
	}
	p.jwks = &ks
	return nil
}

// Slug returns the provider's unique identifier.
func (p *Provider) Slug() string { return p.cfg.Slug }

// DisplayName returns the human-readable provider name.
func (p *Provider) DisplayName() string { return p.cfg.DisplayName }

// AuthCodeURL generates the authorization URL with state and PKCE.
func (p *Provider) AuthCodeURL(state string, opts idppkg.AuthCodeOptions) (string, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return "", fmt.Errorf("state is required")
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", fmt.Errorf("generate pkce: %w", err)
	}
	p.storePKCEVerifier(state, verifier)

	redirectURI := opts.RedirectURI
	if redirectURI == "" {
		redirectURI = p.cfg.RedirectURI
	}

	params := url.Values{}
	params.Set("client_id", p.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", strings.Join(p.cfg.Scopes, " "))
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	return p.discovery.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *Provider) ExchangeCode(ctx context.Context, code string, redirectURI string, state string) (*idppkg.TokenSet, error) {
	if redirectURI == "" {
		redirectURI = p.cfg.RedirectURI
	}

	verifier, err := p.loadPKCEVerifier(state)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("client_secret", p.cfg.ClientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}

	// Validate ID token signature if JWKS is available.
	if tr.IDToken != "" && p.jwks != nil {
		if err := p.validateIDToken(tr.IDToken); err != nil {
			return nil, fmt.Errorf("id_token validation: %w", err)
		}
	}

	p.deletePKCEVerifier(state)

	return &idppkg.TokenSet{
		AccessToken: tr.AccessToken,
		TokenType:   tr.TokenType,
		// Store ID token in Scope field for FetchProfile to use.
		Scope: tr.IDToken,
	}, nil
}

// FetchProfile extracts user profile from the ID token or userinfo endpoint.
func (p *Provider) FetchProfile(ctx context.Context, token *idppkg.TokenSet) (*idppkg.ExternalProfile, error) {
	// Try userinfo endpoint first.
	if p.discovery.UserinfoEndpoint != "" && token.AccessToken != "" {
		profile, err := p.fetchUserinfo(ctx, token.AccessToken)
		if err == nil {
			return profile, nil
		}
	}

	// Fall back to parsing ID token claims (stored in Scope field).
	if token.Scope != "" {
		return p.parseIDTokenClaims(token.Scope)
	}

	return nil, fmt.Errorf("no profile source available")
}

func (p *Provider) fetchUserinfo(ctx context.Context, accessToken string) (*idppkg.ExternalProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.discovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	return claimsToProfile(p.cfg.Slug, claims), nil
}

func (p *Provider) parseIDTokenClaims(idToken string) (*idppkg.ExternalProfile, error) {
	// Parse without verification (already verified in ExchangeCode).
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse id_token: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid id_token claims")
	}
	return claimsToProfile(p.cfg.Slug, map[string]any(claims)), nil
}

func (p *Provider) validateIDToken(idToken string) error {
	if p.jwks == nil {
		return nil
	}
	tok, err := josejwt.ParseSigned(idToken, []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
	})
	if err != nil {
		return fmt.Errorf("parse signed token: %w", err)
	}
	var claims map[string]any
	for _, key := range p.jwks.Keys {
		if err := tok.Claims(key, &claims); err == nil {
			return nil
		}
	}
	return fmt.Errorf("id_token signature verification failed")
}

func claimsToProfile(slug string, claims map[string]any) *idppkg.ExternalProfile {
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)
	preferredUsername, _ := claims["preferred_username"].(string)

	if preferredUsername == "" {
		preferredUsername = name
	}

	return &idppkg.ExternalProfile{
		Provider:       slug,
		ProviderUserID: sub,
		Email:          email,
		EmailVerified:  emailVerified,
		Username:       preferredUsername,
		DisplayName:    name,
		AvatarURL:      picture,
	}
}

func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil
}

func (p *Provider) storePKCEVerifier(state, verifier string) {
	now := time.Now()

	p.pkceMu.Lock()
	defer p.pkceMu.Unlock()

	for key, entry := range p.pkce {
		if !entry.expiresAt.After(now) {
			delete(p.pkce, key)
		}
	}
	p.pkce[state] = pkceVerifier{
		value:     verifier,
		expiresAt: now.Add(pkceVerifierTTL),
	}
}

func (p *Provider) loadPKCEVerifier(state string) (string, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return "", fmt.Errorf("state is required")
	}

	now := time.Now()

	p.pkceMu.Lock()
	defer p.pkceMu.Unlock()

	entry, ok := p.pkce[state]
	if !ok {
		return "", fmt.Errorf("pkce verifier not found for state")
	}
	if !entry.expiresAt.After(now) {
		delete(p.pkce, state)
		return "", fmt.Errorf("pkce verifier expired for state")
	}
	return entry.value, nil
}

func (p *Provider) deletePKCEVerifier(state string) {
	state = strings.TrimSpace(state)
	if state == "" {
		return
	}

	p.pkceMu.Lock()
	defer p.pkceMu.Unlock()
	delete(p.pkce, state)
}
