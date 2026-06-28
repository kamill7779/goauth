package humancheck

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestService(t *testing.T) (*Service, *miniredis.Miniredis) {
	t.Helper()
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	service := NewService(client, Config{
		Provider:     ProviderSlider,
		Actions:      []string{ActionRegister},
		ChallengeTTL: 2 * time.Minute,
		TokenTTL:     3 * time.Minute,
		TolerancePX:  4,
	})
	return service, mini
}

func TestServiceCreatesChallengeAndIssuesOneTimeToken(t *testing.T) {
	service, _ := newTestService(t)
	ctx := context.Background()

	challenge, err := service.CreateSliderChallenge(ctx)
	if err != nil {
		t.Fatalf("CreateSliderChallenge() error = %v", err)
	}
	if challenge.ID == "" || challenge.Nonce == "" {
		t.Fatalf("challenge identifiers must be set: %+v", challenge)
	}
	if challenge.TargetX < 40 || challenge.TargetX > 260 {
		t.Fatalf("target x = %d, want generated safe range", challenge.TargetX)
	}
	if challenge.Image == "" || challenge.Thumb == "" {
		t.Fatalf("challenge should include renderable image placeholders: %+v", challenge)
	}
	if got, want := challenge.Image[:len("data:image/png;base64,")], "data:image/png;base64,"; got != want {
		t.Fatalf("challenge image prefix = %q, want %q", got, want)
	}
	if got, want := challenge.Thumb[:len("data:image/png;base64,")], "data:image/png;base64,"; got != want {
		t.Fatalf("challenge thumb prefix = %q, want %q", got, want)
	}

	if _, err := service.VerifySlider(ctx, VerifyInput{ChallengeID: challenge.ID, Nonce: challenge.Nonce, X: challenge.TargetX + 12, ElapsedMS: 1200, Track: []TrackPoint{{X: 0, Y: 0, T: 0}, {X: challenge.TargetX + 12, Y: 1, T: 1200}}}); err == nil {
		t.Fatal("VerifySlider() error = nil, want error for wrong x")
	}

	token, err := service.VerifySlider(ctx, VerifyInput{ChallengeID: challenge.ID, Nonce: challenge.Nonce, X: challenge.TargetX + 2, ElapsedMS: 1300, Track: []TrackPoint{{X: 0, Y: 0, T: 0}, {X: 23, Y: 1, T: 350}, {X: challenge.TargetX + 2, Y: 0, T: 1300}}})
	if err != nil {
		t.Fatalf("VerifySlider(valid) error = %v", err)
	}
	if token.Token == "" {
		t.Fatal("VerifySlider(valid) returned empty token")
	}

	if err := service.ConsumeToken(ctx, token.Token, "register"); err != nil {
		t.Fatalf("ConsumeToken() error = %v", err)
	}
	if err := service.ConsumeToken(ctx, token.Token, "register"); err == nil {
		t.Fatal("ConsumeToken() second use error = nil, want one-time token rejection")
	}
}

func TestServiceRejectsFastOrTooShortTracks(t *testing.T) {
	service, _ := newTestService(t)
	ctx := context.Background()
	challenge, err := service.CreateSliderChallenge(ctx)
	if err != nil {
		t.Fatalf("CreateSliderChallenge() error = %v", err)
	}

	_, err = service.VerifySlider(ctx, VerifyInput{ChallengeID: challenge.ID, Nonce: challenge.Nonce, X: challenge.TargetX, ElapsedMS: 120, Track: []TrackPoint{{X: challenge.TargetX, T: 120}}})
	if err == nil {
		t.Fatal("VerifySlider() error = nil, want fast/short track rejection")
	}
}
