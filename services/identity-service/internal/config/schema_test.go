package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestEnvDefinitionsCoverEnvExample(t *testing.T) {
	definitions := EnvDefinitions()
	byName := map[string]EnvDefinition{}
	for _, definition := range definitions {
		if strings.TrimSpace(definition.Name) == "" {
			t.Fatalf("env definition has empty name: %+v", definition)
		}
		if _, exists := byName[definition.Name]; exists {
			t.Fatalf("duplicate env definition for %s", definition.Name)
		}
		byName[definition.Name] = definition
	}

	envExampleKeys := readEnvExampleKeys(t)
	for _, key := range envExampleKeys {
		if _, ok := byName[key]; !ok {
			t.Fatalf("%s is present in .env.example but missing from EnvDefinitions()", key)
		}
	}
}

func TestEnvDefinitionsAreDocumented(t *testing.T) {
	keys := mapEnvDefinitionsByName()
	documented := readBacktickKeys(t, filepath.Join("..", "..", "..", "..", "docs", "configuration.md"))

	for key := range keys {
		if !documented[key] {
			t.Fatalf("%s is present in EnvDefinitions() but missing from docs/configuration.md", key)
		}
	}
}

func TestDockerComposePassesAllRuntimeEnvDefinitions(t *testing.T) {
	keys := mapEnvDefinitionsByName()
	composeKeys := readComposeEnvKeys(t)

	for key := range keys {
		if !composeKeys[key] {
			t.Fatalf("%s is present in EnvDefinitions() but missing from docker-compose.yml", key)
		}
	}
}

func TestEnvDefinitionsClassifySecretsAndPublicConfig(t *testing.T) {
	byName := mapEnvDefinitionsByName()

	for _, key := range []string{
		"MYSQL_DSN",
		"REDIS_URL",
		"JWT_PRIVATE_KEY_PATH",
		"SMTP_PASSWORD",
		"GITHUB_CLIENT_SECRET",
		"BOOTSTRAP_ADMIN_PASSWORD",
		"CAPTCHA_SECRET_KEY",
	} {
		definition, ok := byName[key]
		if !ok {
			t.Fatalf("missing env definition for %s", key)
		}
		if !definition.Secret {
			t.Fatalf("%s Secret = false, want true", key)
		}
		if definition.PublicConfig {
			t.Fatalf("%s PublicConfig = true, secrets must never be public", key)
		}
	}

	for _, key := range []string{
		"PUBLIC_ISSUER_URL",
		"REGISTRATION_MODE",
		"LOCAL_PASSWORD_LOGIN_ENABLED",
		"MAILER_PROVIDER",
		"BRAND_NAME",
		"BRAND_TAGLINE",
		"BRAND_ICON_TEXT",
		"BRAND_ICON_URL",
		"GITHUB_OAUTH_ENABLED",
		"CAPTCHA_PROVIDER",
		"CAPTCHA_SITE_KEY",
		"CAPTCHA_ACTIONS",
		"PASSWORD_MIN_LENGTH",
		"PASSWORD_REQUIRE_DIGIT",
	} {
		definition, ok := byName[key]
		if !ok {
			t.Fatalf("missing env definition for %s", key)
		}
		if definition.Secret {
			t.Fatalf("%s Secret = true, want false", key)
		}
		if !definition.PublicConfig {
			t.Fatalf("%s PublicConfig = false, want true", key)
		}
	}
}

func TestEnvDefinitionsRequireProductionStorageAndSigningKeys(t *testing.T) {
	byName := mapEnvDefinitionsByName()

	for _, key := range []string{
		"PUBLIC_ISSUER_URL",
		"MYSQL_DSN",
		"REDIS_URL",
		"JWT_PRIVATE_KEY_PATH",
		"JWT_KEY_ID",
	} {
		definition, ok := byName[key]
		if !ok {
			t.Fatalf("missing env definition for %s", key)
		}
		if !definition.RequiredInProduction {
			t.Fatalf("%s RequiredInProduction = false, want true", key)
		}
	}
}

func mapEnvDefinitionsByName() map[string]EnvDefinition {
	byName := map[string]EnvDefinition{}
	for _, definition := range EnvDefinitions() {
		byName[definition.Name] = definition
	}
	return byName
}

func readEnvExampleKeys(t *testing.T) []string {
	t.Helper()

	path := filepath.Join("..", "..", ".env.example")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	keys := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		keys = append(keys, strings.TrimSpace(key))
	}
	sort.Strings(keys)
	return keys
}

func readBacktickKeys(t *testing.T, path string) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	result := map[string]bool{}
	for _, definition := range EnvDefinitions() {
		if strings.Contains(string(raw), "`"+definition.Name+"`") {
			result[definition.Name] = true
		}
	}
	return result
}

func readComposeEnvKeys(t *testing.T) map[string]bool {
	t.Helper()

	path := filepath.Join("..", "..", "docker-compose.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	keys := map[string]bool{}
	definitions := mapEnvDefinitionsByName()
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		key, _, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, exists := definitions[key]; exists {
			keys[key] = true
		}
	}
	return keys
}
