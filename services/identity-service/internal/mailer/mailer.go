// Package mailer defines the email sending interface and provides SMTP and
// no-op implementations. The no-op sender is used in development/testing.
package mailer

import "context"

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
