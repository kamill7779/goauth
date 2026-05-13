// Package logout implements OIDC Back-Channel Logout 1.0. When a user session
// ends, the Coordinator sends signed logout_token JWTs to all relying parties
// that registered a backchannel_logout_uri.
package logout

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"goauth/services/identity-service/internal/audit"
	"goauth/services/identity-service/internal/store"
	"gorm.io/gorm"
)

// Coordinator sends back-channel logout notifications to registered OAuth clients.
// Notifications are best-effort: failures are logged but do not block user logout.
type Coordinator struct {
	db         *gorm.DB
	privateKey *rsa.PrivateKey
	issuer     string
	keyID      string
	audit      audit.Recorder
	httpClient *http.Client
}

// NewCoordinator creates a Coordinator with a 5-second HTTP timeout.
func NewCoordinator(db *gorm.DB, key *rsa.PrivateKey, issuer, keyID string) *Coordinator {
	return &Coordinator{
		db:         db,
		privateKey: key,
		issuer:     issuer,
		keyID:      keyID,
		audit:      audit.NoopRecorder{},
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

func (c *Coordinator) SetAuditRecorder(r audit.Recorder) {
	if r == nil {
		c.audit = audit.NoopRecorder{}
		return
	}
	c.audit = r
}

// NotifyClients sends back-channel logout tokens to all OAuth clients that:
//   - have a backchannel_logout_uri configured, and
//   - have an active session for the user.
//
// Best-effort: failures are logged and do not block.
func (c *Coordinator) NotifyClients(ctx context.Context, userID int64, sessionID string) error {
	if c == nil || c.db == nil || c.privateKey == nil {
		return nil
	}

	// Find clients with active sessions for this user that have a logout URI.
	var clients []store.OAuthClient
	subQuery := c.db.WithContext(ctx).
		Model(&store.RefreshToken{}).
		Select("DISTINCT client_id").
		Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, time.Now())

	if err := c.db.WithContext(ctx).
		Where("backchannel_logout_uri != '' AND client_id IN (?)", subQuery).
		Find(&clients).Error; err != nil {
		return fmt.Errorf("find clients: %w", err)
	}

	for _, client := range clients {
		if err := c.notifyClient(ctx, client, userID, sessionID); err != nil {
			slog.Warn("back-channel logout failed",
				"client_id", client.ClientID,
				"error", err,
			)
		}
	}
	return nil
}

func (c *Coordinator) notifyClient(ctx context.Context, client store.OAuthClient, userID int64, sessionID string) error {
	logoutToken, err := c.buildLogoutToken(client, userID, sessionID)
	if err != nil {
		return fmt.Errorf("build logout token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx,
		http.MethodPost,
		client.BackchannelLogoutURI,
		strings.NewReader("logout_token="+logoutToken),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("logout URI returned %d", resp.StatusCode)
	}

	_ = c.audit.Record(ctx, audit.Entry{
		ActorUserID: userID,
		Action:      "backchannel_logout_sent",
		TargetType:  "oauth_client",
		TargetID:    client.ClientID,
		Metadata: map[string]any{
			"session_id": sessionID,
		},
	})
	return nil
}

// logoutTokenClaims are the JWT claims for a back-channel logout token.
type logoutTokenClaims struct {
	jwt.RegisteredClaims
	SessionID string         `json:"sid,omitempty"`
	Events    map[string]any `json:"events"`
}

func (c *Coordinator) buildLogoutToken(client store.OAuthClient, userID int64, sessionID string) (string, error) {
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}

	claims := logoutTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    c.issuer,
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  jwt.ClaimStrings{client.ClientID},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
		Events: map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}

	if client.BackchannelLogoutSessionRequired && sessionID != "" {
		claims.SessionID = sessionID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if c.keyID != "" {
		token.Header["kid"] = c.keyID
	}
	return token.SignedString(c.privateKey)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
