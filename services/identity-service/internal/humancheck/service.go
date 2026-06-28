package humancheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	ProviderSlider = "slider"
	ActionRegister = "register"
)

var (
	ErrDisabled         = errors.New("human check disabled")
	ErrMissingToken     = errors.New("human check token required")
	ErrInvalidToken     = errors.New("human check token invalid")
	ErrInvalidChallenge = errors.New("human check challenge invalid")
)

type Config struct {
	Provider     string
	Actions      []string
	ChallengeTTL time.Duration
	TokenTTL     time.Duration
	TolerancePX  int
}

type Service struct {
	redis        *redis.Client
	provider     string
	actions      map[string]struct{}
	challengeTTL time.Duration
	tokenTTL     time.Duration
	tolerancePX  int
	now          func() time.Time
}

type Challenge struct {
	ID          string `json:"id"`
	Nonce       string `json:"nonce"`
	TargetX     int    `json:"target_x,omitempty"`
	ThumbX      int    `json:"thumb_x"`
	ThumbY      int    `json:"thumb_y"`
	ThumbWidth  int    `json:"thumb_width"`
	ThumbHeight int    `json:"thumb_height"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Image       string `json:"image"`
	Thumb       string `json:"thumb"`
}

type TrackPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
	T int `json:"t"`
}

type VerifyInput struct {
	ChallengeID string       `json:"challenge_id"`
	Nonce       string       `json:"nonce"`
	X           int          `json:"x"`
	Y           int          `json:"y"`
	ElapsedMS   int          `json:"elapsed_ms"`
	Track       []TrackPoint `json:"track"`
}

type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type storedChallenge struct {
	Nonce     string    `json:"nonce"`
	TargetX   int       `json:"target_x"`
	TargetY   int       `json:"target_y"`
	CreatedAt time.Time `json:"created_at"`
}

func NewService(redisClient *redis.Client, cfg Config) *Service {
	challengeTTL := cfg.ChallengeTTL
	if challengeTTL <= 0 {
		challengeTTL = 2 * time.Minute
	}
	tokenTTL := cfg.TokenTTL
	if tokenTTL <= 0 {
		tokenTTL = 3 * time.Minute
	}
	tolerance := cfg.TolerancePX
	if tolerance <= 0 {
		tolerance = 4
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	actions := actionSet(cfg.Actions)
	return &Service{
		redis:        redisClient,
		provider:     provider,
		actions:      actions,
		challengeTTL: challengeTTL,
		tokenTTL:     tokenTTL,
		tolerancePX:  tolerance,
		now:          time.Now,
	}
}

func (s *Service) EnabledFor(action string) bool {
	if s == nil || s.redis == nil || s.provider == "" {
		return false
	}
	_, ok := s.actions[strings.ToLower(strings.TrimSpace(action))]
	return ok
}

func (s *Service) CreateSliderChallenge(ctx context.Context) (Challenge, error) {
	if s == nil || s.redis == nil {
		return Challenge{}, ErrDisabled
	}
	id, err := randomToken(18)
	if err != nil {
		return Challenge{}, err
	}
	nonce, err := randomToken(18)
	if err != nil {
		return Challenge{}, err
	}
	targetX, err := randomInt(40, 260)
	if err != nil {
		return Challenge{}, err
	}
	targetY, err := randomInt(28, 104)
	if err != nil {
		return Challenge{}, err
	}
	stored := storedChallenge{Nonce: nonce, TargetX: targetX, TargetY: targetY, CreatedAt: s.now().UTC()}
	payload, err := json.Marshal(stored)
	if err != nil {
		return Challenge{}, err
	}
	if err := s.redis.Set(ctx, challengeKey(id), payload, s.challengeTTL).Err(); err != nil {
		return Challenge{}, err
	}
	return Challenge{
		ID:          id,
		Nonce:       nonce,
		TargetX:     targetX,
		ThumbX:      0,
		ThumbY:      targetY,
		ThumbWidth:  42,
		ThumbHeight: 42,
		Width:       320,
		Height:      160,
		Image:       sliderImageDataURI(targetX, targetY),
		Thumb:       sliderThumbDataURI(),
	}, nil
}

func (s *Service) VerifySlider(ctx context.Context, input VerifyInput) (Token, error) {
	if s == nil || s.redis == nil {
		return Token{}, ErrDisabled
	}
	id := strings.TrimSpace(input.ChallengeID)
	nonce := strings.TrimSpace(input.Nonce)
	if id == "" || nonce == "" {
		return Token{}, ErrInvalidChallenge
	}
	payload, err := s.redis.Get(ctx, challengeKey(id)).Bytes()
	if err == redis.Nil {
		return Token{}, ErrInvalidChallenge
	}
	if err != nil {
		return Token{}, err
	}
	var stored storedChallenge
	if err := json.Unmarshal(payload, &stored); err != nil {
		return Token{}, err
	}
	if subtleCompare(stored.Nonce, nonce) == false {
		return Token{}, ErrInvalidChallenge
	}
	if abs(input.X-stored.TargetX) > s.tolerancePX || input.ElapsedMS < 700 || len(input.Track) < 2 {
		return Token{}, ErrInvalidChallenge
	}
	if err := s.redis.Del(ctx, challengeKey(id)).Err(); err != nil {
		return Token{}, err
	}
	token, err := randomToken(32)
	if err != nil {
		return Token{}, err
	}
	expiresAt := s.now().Add(s.tokenTTL).UTC()
	storedToken := map[string]any{"action": ActionRegister, "expires_at": expiresAt.Format(time.RFC3339Nano)}
	tokenPayload, err := json.Marshal(storedToken)
	if err != nil {
		return Token{}, err
	}
	if err := s.redis.Set(ctx, tokenKey(token), tokenPayload, s.tokenTTL).Err(); err != nil {
		return Token{}, err
	}
	return Token{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Service) ConsumeToken(ctx context.Context, token, action string) error {
	if s == nil || s.redis == nil || !s.EnabledFor(action) {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrMissingToken
	}
	payload, err := s.redis.GetDel(ctx, tokenKey(token)).Bytes()
	if err == redis.Nil {
		return ErrInvalidToken
	}
	if err != nil {
		return err
	}
	var stored struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(payload, &stored); err != nil {
		return err
	}
	if strings.ToLower(strings.TrimSpace(stored.Action)) != strings.ToLower(strings.TrimSpace(action)) {
		return ErrInvalidToken
	}
	return nil
}

func challengeKey(id string) string { return "auth:human:slider:" + id }
func tokenKey(token string) string  { return "auth:human:token:" + hashToken(token) }

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func actionSet(actions []string) map[string]struct{} {
	out := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		action = strings.ToLower(strings.TrimSpace(action))
		if action != "" {
			out[action] = struct{}{}
		}
	}
	return out
}

func randomToken(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func randomInt(min, max int) (int, error) {
	if max < min {
		return 0, fmt.Errorf("invalid range")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return 0, err
	}
	return min + int(n.Int64()), nil
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func sliderImageDataURI(targetX, targetY int) string {
	img := image.NewRGBA(image.Rect(0, 0, 320, 160))
	for y := 0; y < 160; y++ {
		for x := 0; x < 320; x++ {
			r := uint8(236 + (x * 10 / 320))
			g := uint8(228 + (y * 14 / 160))
			b := uint8(210 + ((x + y) * 12 / 480))
			img.SetRGBA(x, y, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}
	drawSoftCircle(img, 70, 44, 20, color.RGBA{255, 255, 255, 80})
	drawSoftCircle(img, 246, 114, 28, color.RGBA{255, 255, 255, 70})
	drawSoftCircle(img, 164, 82, 18, color.RGBA{42, 75, 64, 34})
	drawPuzzleCutout(img, targetX, targetY, 42)
	return pngDataURI(img)
}

func sliderThumbDataURI() string {
	img := image.NewRGBA(image.Rect(0, 0, 42, 42))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{255, 255, 255, 0}), image.Point{}, draw.Src)
	for y := 0; y < 42; y++ {
		for x := 0; x < 42; x++ {
			if puzzleMask(x, y, 42) {
				img.SetRGBA(x, y, color.RGBA{255, 255, 255, 226})
				if x < 3 || y < 3 || x > 38 || y > 38 {
					img.SetRGBA(x, y, color.RGBA{32, 42, 36, 130})
				}
			}
		}
	}
	for x := 14; x < 28; x++ {
		img.SetRGBA(x, 20, color.RGBA{31, 42, 36, 220})
		img.SetRGBA(x, 21, color.RGBA{31, 42, 36, 220})
	}
	for i := 0; i < 5; i++ {
		img.SetRGBA(24+i, 16+i, color.RGBA{31, 42, 36, 220})
		img.SetRGBA(24+i, 25-i, color.RGBA{31, 42, 36, 220})
	}
	return pngDataURI(img)
}

func drawPuzzleCutout(img *image.RGBA, x0, y0, size int) {
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if !puzzleMask(x, y, size) {
				continue
			}
			px, py := x0+x, y0+y
			if !image.Pt(px, py).In(img.Bounds()) {
				continue
			}
			current := img.RGBAAt(px, py)
			img.SetRGBA(px, py, color.RGBA{
				R: uint8(int(current.R) * 58 / 100),
				G: uint8(int(current.G) * 58 / 100),
				B: uint8(int(current.B) * 58 / 100),
				A: 255,
			})
		}
	}
}

func drawSoftCircle(img *image.RGBA, cx, cy, radius int, c color.RGBA) {
	r2 := radius * radius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if !image.Pt(x, y).In(img.Bounds()) {
				continue
			}
			dx, dy := x-cx, y-cy
			if dx*dx+dy*dy > r2 {
				continue
			}
			base := img.RGBAAt(x, y)
			alpha := int(c.A)
			img.SetRGBA(x, y, color.RGBA{
				R: uint8((int(c.R)*alpha + int(base.R)*(255-alpha)) / 255),
				G: uint8((int(c.G)*alpha + int(base.G)*(255-alpha)) / 255),
				B: uint8((int(c.B)*alpha + int(base.B)*(255-alpha)) / 255),
				A: 255,
			})
		}
	}
}

func puzzleMask(x, y, size int) bool {
	if x < 3 || y < 3 || x >= size-3 || y >= size-3 {
		return false
	}
	cx, cy := size/2, size/2
	dx, dy := x-cx, y-cy
	if dx*dx+dy*dy <= 9*9 {
		return true
	}
	return x >= 6 && x < size-6 && y >= 6 && y < size-6
}

func pngDataURI(img image.Image) string {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}
