package mailer

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"strings"
	"text/template"
)

//go:embed templates
var templateFS embed.FS

// TemplateData holds the variables available in all email templates.
type TemplateData struct {
	AppName   string
	UserName  string
	Code      string
	Link      string
	ExpiryMin int
}

// TemplateEngine renders email bodies from embedded locale-specific templates.
type TemplateEngine struct {
	defaultLocale string
	templates     map[string]*template.Template // key: "{locale}/{type}"
}

// NewTemplateEngine creates a TemplateEngine and pre-parses all embedded templates.
// Panics if the embedded template filesystem cannot be loaded.
//
// Call chain: wire → NewTemplateEngine → loadAllFromFS → embed.FS + text/template
func NewTemplateEngine(defaultLocale string) *TemplateEngine {
	if defaultLocale == "" {
		defaultLocale = "en"
	}
	e := &TemplateEngine{
		defaultLocale: defaultLocale,
		templates:     make(map[string]*template.Template),
	}
	if err := e.loadAllFromFS(templateFS); err != nil {
		panic(fmt.Errorf("load embedded email templates: %w", err))
	}
	return e
}

// loadAllFromFS walks templates/<locale>/*.txt and compiles each into a cached template.
//
// Call chain: NewTemplateEngine → loadAllFromFS → fs.ReadDir / fs.ReadFile / template.Parse
func (e *TemplateEngine) loadAllFromFS(fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, "templates")
	if err != nil {
		return err
	}
	for _, localeEntry := range entries {
		if !localeEntry.IsDir() {
			continue
		}
		locale := localeEntry.Name()
		subEntries, err := fs.ReadDir(fsys, "templates/"+locale)
		if err != nil {
			return fmt.Errorf("read locale directory %s: %w", locale, err)
		}
		for _, fileEntry := range subEntries {
			if fileEntry.IsDir() {
				continue
			}
			name := fileEntry.Name()
			if !strings.HasSuffix(name, ".txt") {
				continue
			}
			tmplType := strings.TrimSuffix(name, ".txt")
			path := fmt.Sprintf("templates/%s/%s", locale, name)
			content, err := fs.ReadFile(fsys, path)
			if err != nil {
				return fmt.Errorf("read template %s: %w", path, err)
			}
			tmpl, err := template.New(path).Parse(string(content))
			if err != nil {
				return fmt.Errorf("parse template %s: %w", path, err)
			}
			e.templates[locale+"/"+tmplType] = tmpl
		}
	}
	if len(e.templates) == 0 {
		return fmt.Errorf("no templates loaded")
	}
	return nil
}

// Render returns (subject, body, error) for the given template type and locale.
// Falls back to defaultLocale if the requested locale is not found.
// The first line of the rendered output is the subject; the rest after a blank line is the body.
//
// Call chain: email dispatch → Render → template.Execute
func (e *TemplateEngine) Render(templateType, locale string, data TemplateData) (subject, body string, err error) {
	if locale == "" {
		locale = e.defaultLocale
	}

	tmpl := e.templates[locale+"/"+templateType]
	if tmpl == nil && locale != e.defaultLocale {
		// Fallback to default locale.
		tmpl = e.templates[e.defaultLocale+"/"+templateType]
	}
	if tmpl == nil {
		return "", "", fmt.Errorf("template not found: %s/%s", locale, templateType)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("render template %s/%s: %w", locale, templateType, err)
	}

	rendered := buf.String()
	// First line is the subject; rest (after first blank line) is the body.
	// Normalize line endings first.
	rendered = strings.ReplaceAll(rendered, "\r\n", "\n")
	idx := strings.Index(rendered, "\n\n")
	if idx < 0 {
		return strings.TrimSpace(rendered), "", nil
	}
	subject = strings.TrimSpace(rendered[:idx])
	body = strings.TrimSpace(rendered[idx+2:])
	return subject, body, nil
}
