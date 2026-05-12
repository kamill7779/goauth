package mailer

import (
	"strings"
	"testing"
	"testing/fstest"
	"text/template"
)

func TestLoadAllFromFS_ReturnsErrorWhenTemplatesMissing(t *testing.T) {
	engine := &TemplateEngine{
		defaultLocale: "en",
		templates:     make(map[string]*template.Template),
	}

	err := engine.loadAllFromFS(fstest.MapFS{})
	if err == nil {
		t.Fatal("expected missing templates error")
	}
}

func TestLoadAllFromFS_ReturnsParseError(t *testing.T) {
	engine := &TemplateEngine{
		defaultLocale: "en",
		templates:     make(map[string]*template.Template),
	}

	err := engine.loadAllFromFS(fstest.MapFS{
		"templates/en/bad.txt": &fstest.MapFile{Data: []byte("Subject\n\n{{")},
	})
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "parse template") {
		t.Fatalf("expected parse template error, got %v", err)
	}
}
