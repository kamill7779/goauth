package mailer

import (
	"bytes"
	"embed"
	"fmt"
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
func NewTemplateEngine(defaultLocale string) *TemplateEngine {
	if defaultLocale == "" {
		defaultLocale = "en"
	}
	e := &TemplateEngine{
		defaultLocale: defaultLocale,
		templates:     make(map[string]*template.Template),
	}
	e.loadAll()
	return e
}

func (e *TemplateEngine) loadAll() {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return
	}
	for _, localeEntry := range entries {
		if !localeEntry.IsDir() {
			continue
		}
		locale := localeEntry.Name()
		subEntries, err := templateFS.ReadDir("templates/" + locale)
		if err != nil {
			continue
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
			content, err := templateFS.ReadFile(path)
			if err != nil {
				continue
			}
			tmpl, err := template.New(path).Parse(string(content))
			if err != nil {
				continue
			}
			e.templates[locale+"/"+tmplType] = tmpl
		}
	}
}

// Render returns (subject, body, error) for the given template type and locale.
// Falls back to defaultLocale if the requested locale is not found.
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
