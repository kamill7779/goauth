package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestConsoleSenderWritesMessage(t *testing.T) {
	var buf bytes.Buffer
	sender := NewConsoleSender(slog.New(slog.NewJSONHandler(&buf, nil)))
	sender.dir = t.TempDir()

	err := sender.Send(context.Background(), Message{
		To:      "member@example.com",
		Subject: "GoAuth verification code",
		Body:    "123456",
	})
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(buf.String(), "123456") {
		t.Fatalf("console mail log leaked message body: %q", buf.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &payload); err != nil {
		t.Fatalf("json.Unmarshal() error = %v body=%s", err, buf.String())
	}
	if payload["to"] != "member@example.com" {
		t.Fatalf("to = %#v", payload["to"])
	}
	path, _ := payload["path"].(string)
	if path == "" {
		t.Fatalf("path = %#v", payload["path"])
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", path, err)
	}
	if !strings.Contains(string(content), "123456") {
		t.Fatalf("console mail file = %q", string(content))
	}
}
