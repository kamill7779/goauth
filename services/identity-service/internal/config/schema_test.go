package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestEnvDefinitionsHaveStableKeys(t *testing.T) {
	byName := map[string]EnvDefinition{}
	for _, definition := range EnvDefinitions() {
		if strings.TrimSpace(definition.Name) == "" {
			t.Fatalf("env definition has empty name: %+v", definition)
		}
		if _, exists := byName[definition.Name]; exists {
			t.Fatalf("duplicate env definition for %s", definition.Name)
		}
		byName[definition.Name] = definition
	}
}

func TestEnvExampleMatchesEnvDefinitions(t *testing.T) {
	assertSameEnvKeys(t, "services/identity-service/.env.example", readEnvExampleKeys(t), envDefinitionKeys())
}

func TestConfigurationMatrixMatchesEnvDefinitions(t *testing.T) {
	assertSameEnvKeys(t, "docs/deployment/configuration.md", readConfigurationMatrixKeys(t), envDefinitionKeys())
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
		"JWT_KEYSET_DIR",
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

func readConfigurationMatrixKeys(t *testing.T) []string {
	t.Helper()

	path := filepath.Join("..", "..", "..", "..", "docs", "deployment", "configuration.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	keys := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 2 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(cells[1]), "`")
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
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

func envDefinitionKeys() []string {
	definitions := EnvDefinitions()
	keys := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		keys = append(keys, definition.Name)
	}
	sort.Strings(keys)
	return keys
}

func assertSameEnvKeys(t *testing.T, source string, got, want []string) {
	t.Helper()

	gotSet := sliceSet(got)
	wantSet := sliceSet(want)
	for _, key := range want {
		if !gotSet[key] {
			t.Fatalf("%s missing %s from EnvDefinitions()", source, key)
		}
	}
	for _, key := range got {
		if !wantSet[key] {
			t.Fatalf("%s contains %s but EnvDefinitions() does not", source, key)
		}
	}
}

func sliceSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
