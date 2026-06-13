// Package mailer defines the email sending interface and provides SMTP and
// no-op implementations. The no-op sender is used in development/testing.
package mailer

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

type Message struct {
	To      string
	Subject string
	Body    string
}

type Sender interface {
	Send(ctx context.Context, message Message) error
}

type NoopSender struct{}

func (NoopSender) Send(context.Context, Message) error {
	return nil
}

type ConsoleSender struct {
	logger *slog.Logger
	dir    string
}

// NewConsoleSender returns a ConsoleSender that writes mail to temp files.
//
// Call chain: wire → NewConsoleSender
func NewConsoleSender(logger *slog.Logger) ConsoleSender {
	if logger == nil {
		logger = slog.Default()
	}
	return ConsoleSender{
		logger: logger,
		dir:    filepath.Join(os.TempDir(), "goauth-mailbox"),
	}
}

// Send writes the message to a temp file under goauth-mailbox and logs it.
//
// Call chain: email dispatch → Send → os.CreateTemp + logger.InfoContext
func (s ConsoleSender) Send(ctx context.Context, message Message) error {
	logger := s.logger
	if logger == nil {
		logger = slog.Default()
	}
	dir := s.dir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "goauth-mailbox")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create console mail dir: %w", err)
	}
	file, err := os.CreateTemp(dir, "mail-*.txt")
	if err != nil {
		return fmt.Errorf("create console mail file: %w", err)
	}
	defer file.Close()
	if _, err := fmt.Fprintf(file, "To: %s\nSubject: %s\n\n%s", message.To, message.Subject, message.Body); err != nil {
		return fmt.Errorf("write console mail file: %w", err)
	}
	logger.InfoContext(ctx, "mail message",
		"to", message.To,
		"subject", message.Subject,
		"path", file.Name(),
		"body_bytes", len(message.Body),
	)
	return nil
}
