package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

const defaultSMTPTimeout = 10 * time.Second

type SMTPConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	From      string
	SSL       bool
	AuthLogin bool
	Timeout   time.Duration
}

// SMTPSender delivers emails via SMTP with support for STARTTLS, implicit TLS,
// PLAIN auth, and the non-standard LOGIN auth mechanism (required by some
// providers like Outlook/Exchange).
type SMTPSender struct {
	cfg SMTPConfig
}

// NewSMTPSender creates an SMTPSender with defaults for Port (587) and Timeout.
//
// Call chain: wire → NewSMTPSender
func NewSMTPSender(cfg SMTPConfig) *SMTPSender {
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSMTPTimeout
	}
	return &SMTPSender{cfg: cfg}
}

// Send delivers a single email via SMTP using the configured auth mechanism.
//
// Call chain: email dispatch → Send → validate → client (dial) → SMTP MAIL/RCPT/DATA → buildRFC822Message
func (s *SMTPSender) Send(ctx context.Context, message Message) error {
	if s == nil {
		return errors.New("smtp sender is nil")
	}
	if err := s.validate(message); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	client, err := s.client(ctx)
	if err != nil {
		return err
	}
	defer client.Close()

	if strings.TrimSpace(s.cfg.Username) != "" {
		auth := smtp.Auth(smtp.PlainAuth("", strings.TrimSpace(s.cfg.Username), s.cfg.Password, strings.TrimSpace(s.cfg.Host)))
		if s.cfg.AuthLogin {
			auth = loginAuth{
				username: strings.TrimSpace(s.cfg.Username),
				password: s.cfg.Password,
			}
		}
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	fromAddress, err := envelopeAddress(s.cfg.From)
	if err != nil {
		return fmt.Errorf("smtp from address: %w", err)
	}
	if err := client.Mail(fromAddress); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	toAddress, err := envelopeAddress(message.To)
	if err != nil {
		return fmt.Errorf("smtp recipient address: %w", err)
	}
	if err := client.Rcpt(toAddress); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := io.WriteString(writer, buildRFC822Message(s.cfg.From, message)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write smtp data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close smtp data: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}
	return nil
}

// validate checks that host, from, and recipient are set.
//
// Call chain: Send → validate
func (s *SMTPSender) validate(message Message) error {
	if strings.TrimSpace(s.cfg.Host) == "" {
		return errors.New("smtp host is required")
	}
	if strings.TrimSpace(s.cfg.From) == "" {
		return errors.New("smtp from is required")
	}
	if strings.TrimSpace(message.To) == "" {
		return errors.New("message recipient is required")
	}
	return nil
}

// client establishes an SMTP connection, using implicit TLS when SSL is configured.
//
// Call chain: Send → client → net.Dialer / tls.Dialer → smtp.NewClient
func (s *SMTPSender) client(ctx context.Context) (*smtp.Client, error) {
	address := net.JoinHostPort(strings.TrimSpace(s.cfg.Host), fmt.Sprintf("%d", s.cfg.Port))
	var conn net.Conn
	var err error
	if s.cfg.SSL {
		conn, err = (&tls.Dialer{
			NetDialer: &net.Dialer{Timeout: s.cfg.Timeout},
			Config: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: strings.TrimSpace(s.cfg.Host),
			},
		}).DialContext(ctx, "tcp", address)
	} else {
		conn, err = (&net.Dialer{Timeout: s.cfg.Timeout}).DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil, fmt.Errorf("dial smtp: %w", err)
	}

	client, err := smtp.NewClient(conn, strings.TrimSpace(s.cfg.Host))
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create smtp client: %w", err)
	}
	return client, nil
}

// envelopeAddress parses an RFC 5322 address and returns the bare addr-spec.
//
// Call chain: Send → envelopeAddress → mail.ParseAddress
func envelopeAddress(value string) (string, error) {
	address, err := mail.ParseAddress(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	return address.Address, nil
}

// buildRFC822Message constructs a plain-text MIME message with standard headers.
//
// Call chain: Send → buildRFC822Message → (pure string builder)
func buildRFC822Message(from string, message Message) string {
	headers := []string{
		"From: " + strings.TrimSpace(from),
		"To: " + strings.TrimSpace(message.To),
		"Subject: " + strings.TrimSpace(message.Subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + strings.TrimRight(message.Body, "\r\n") + "\r\n"
}

type loginAuth struct {
	username string
	password string
}

// Start begins the LOGIN auth exchange by sending the username.
func (a loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte(a.username), nil
}

// Next responds to server challenges during the LOGIN auth exchange.
//
// Call chain: smtp.Client.Auth → loginAuth.Start → loginAuth.Next
func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	challenge := strings.ToLower(string(fromServer))
	if strings.Contains(challenge, "password") {
		return []byte(a.password), nil
	}
	return []byte(a.username), nil
}
