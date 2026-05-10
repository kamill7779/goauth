package mailer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMTPSenderSendsVerificationMessage(t *testing.T) {
	server := newFakeSMTPServer(t)
	defer server.Close()

	host, portString, ok := strings.Cut(server.Addr(), ":")
	if !ok {
		t.Fatalf("fake SMTP addr = %q", server.Addr())
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("parse fake SMTP port: %v", err)
	}

	sender := NewSMTPSender(SMTPConfig{
		Host:     host,
		Port:     port,
		Username: "user@example.com",
		Password: "secret",
		From:     "GoAuth <no-reply@example.com>",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sender.Send(ctx, Message{
		To:      "alice@example.com",
		Subject: "GoAuth verification code",
		Body:    "123456",
	}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if got, want := server.mailFrom(), "no-reply@example.com"; got != want {
		t.Fatalf("MAIL FROM = %q, want %q", got, want)
	}
	if got, want := server.rcptTo(), "alice@example.com"; got != want {
		t.Fatalf("RCPT TO = %q, want %q", got, want)
	}
	body := server.message()
	for _, want := range []string{
		"From: GoAuth <no-reply@example.com>",
		"To: alice@example.com",
		"Subject: GoAuth verification code",
		"123456",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("message does not contain %q:\n%s", want, body)
		}
	}
}

type fakeSMTPServer struct {
	listener net.Listener
	done     chan struct{}
	state    chan fakeSMTPState
}

type fakeSMTPState struct {
	auth     string
	mailFrom string
	rcptTo   string
	message  string
}

func newFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake SMTP: %v", err)
	}
	server := &fakeSMTPServer{
		listener: listener,
		done:     make(chan struct{}),
		state:    make(chan fakeSMTPState, 1),
	}
	go server.serve()
	return server
}

func (s *fakeSMTPServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *fakeSMTPServer) Close() {
	_ = s.listener.Close()
	<-s.done
}

func (s *fakeSMTPServer) mailFrom() string {
	return s.readState().mailFrom
}

func (s *fakeSMTPServer) rcptTo() string {
	return s.readState().rcptTo
}

func (s *fakeSMTPServer) message() string {
	return s.readState().message
}

func (s *fakeSMTPServer) readState() fakeSMTPState {
	state := <-s.state
	s.state <- state
	return state
}

func (s *fakeSMTPServer) serve() {
	defer close(s.done)

	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writeLine := func(line string) {
		_, _ = fmt.Fprintf(conn, "%s\r\n", line)
	}
	writeLine("220 fake smtp")

	var state fakeSMTPState
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO "):
			writeLine("250-fake smtp")
			writeLine("250 AUTH PLAIN")
		case strings.HasPrefix(upper, "AUTH PLAIN "):
			state.auth = strings.TrimPrefix(line, "AUTH PLAIN ")
			writeLine("235 authenticated")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			state.mailFrom = strings.Trim(line[len("MAIL FROM:"):], "<>")
			writeLine("250 ok")
		case strings.HasPrefix(upper, "RCPT TO:"):
			state.rcptTo = strings.Trim(line[len("RCPT TO:"):], "<>")
			writeLine("250 ok")
		case upper == "DATA":
			writeLine("354 end with dot")
			var builder strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if dataLine == ".\r\n" {
					break
				}
				builder.WriteString(dataLine)
			}
			state.message = builder.String()
			writeLine("250 queued")
		case upper == "QUIT":
			s.state <- state
			writeLine("221 bye")
			return
		default:
			writeLine("250 ok")
		}
	}
}
