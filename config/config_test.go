package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfig_DumpModes(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yml")
	os.WriteFile(configFile, []byte("notifyfrom: \"a@b.co\"\n"), 0644)

	t.Run("configdump sets ConfigDump flag", func(t *testing.T) {
		cfg, err := New([]string{"-config", configFile, "-configdump"})
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		SetGlobal(cfg)
		if !ConfigDump() {
			t.Error("expected ConfigDump() == true")
		}
	})

	t.Run("configtest sets ConfigTest flag", func(t *testing.T) {
		cfg, err := New([]string{"-config", configFile, "-configtest"})
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		SetGlobal(cfg)
		if !ConfigTest() {
			t.Error("expected ConfigTest() == true")
		}
	})
}

func TestConfig_New(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yml")

	// Готовим тестовый конфиг.
	// YAML теперь парсится через UnmarshalYAML в наш тип Direction.
	yamlContent := `
authservid: "test.domain.name"
notifyfrom: "postmaster@test.domain.name"
host: "127.0.0.1:11333"
actions:
  reject:
    description: "Spam rejected"
    direction: "in"
    notifyto: ["admin@domain.name"]
`
	if err := os.WriteFile(configFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("Full initialization", func(t *testing.T) {
		args := []string{"-config", configFile, "-debug"}
		cfg, err := New(args)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if cfg.Timeout != 15*time.Second {
			t.Errorf("Expected default timeout 15s, got %v", cfg.Timeout)
		}
		if cfg.AuthservId != "test.domain.name" {
			t.Errorf("AuthservId mismatch: %s", cfg.AuthservId)
		}
		if !cfg.debug {
			t.Error("Debug flag was not set")
		}

		expectedHost := "http://127.0.0.1:11333/checkv2"
		if cfg.Host != expectedHost {
			t.Errorf("Host transformation failed. Got %s, want %s", cfg.Host, expectedHost)
		}
	})

	t.Run("Direction enum parsing", func(t *testing.T) {
		args := []string{"-config", configFile}
		cfg, _ := New(args)

		op, ok := cfg.Actions["reject"]
		// Проверяем соответствие константе DirIn (1)
		if !ok || op.Direction != DirIn {
			t.Errorf("Action 'reject' should have direction DirIn (1), got %v", op.Direction)
		}
		// Проверка строкового представления
		if op.Direction.String() != "in" {
			t.Errorf("String representation failed. Got %s, want 'in'", op.Direction.String())
		}
	})

	t.Run("Invalid direction in YAML", func(t *testing.T) {
		badHdr := "notifyfrom: \"a@b.c\"\nactions:\n  bad:\n    direction: \"upwards\""
		badFile := filepath.Join(tmpDir, "bad_config.yml")
		os.WriteFile(badFile, []byte(badHdr), 0644)

		_, err := New([]string{"-config", badFile})
		if err == nil {
			t.Error("Expected error for invalid direction 'upwards', but got nil")
		} else if !strings.Contains(err.Error(), "invalid direction") {
			t.Errorf("Unexpected error message: %v", err)
		}
	})
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "Valid config",
			cfg: &Config{
				NotifyFrom: "scanner@domain.name",
				Actions: map[string]*Operation{
					"quarantine": {Direction: DirBoth},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid email",
			cfg: &Config{
				NotifyFrom: "not-an-email",
			},
			wantErr: true,
		},
		{
			name: "Invalid direction enum",
			cfg: &Config{
				NotifyFrom: "ok@domain.name",
				Actions: map[string]*Operation{
					"test": {Direction: Direction(99)}, // Несуществующее значение
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVersionOutput(t *testing.T) {
	Version = "1.0.0"
	Commit = "abcde"

	out := GetVersion()
	if !contains(out, "1.0.0") || !contains(out, "abcde") {
		t.Errorf("Version output mismatch: %s", out)
	}
}

func TestConfig_AuthservIdFallback(t *testing.T) {
	tmpDir := t.TempDir()
	settingsDir := filepath.Join(tmpDir, "Settings")
	os.MkdirAll(settingsDir, 0755)

	mainSettingsContent := []byte(`DomainName = "domain.name";`)
	os.WriteFile(filepath.Join(settingsDir, "Main.settings"), mainSettingsContent, 0644)

	configFile := filepath.Join(tmpDir, "config.yml")
	yamlContent := []byte("notifyfrom: \"postmaster@domain.name\"\nhost: \"localhost:11333\"")
	os.WriteFile(configFile, yamlContent, 0644)

	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	t.Run("Detect AuthservId from Main.settings", func(t *testing.T) {
		args := []string{"-config", configFile}
		cfg, err := New(args)
		if err != nil {
			t.Fatalf("New() failed to detect domain: %v", err)
		}

		if cfg.AuthservId != "domain.name" {
			t.Errorf("Expected AuthservId 'domain.name', got %q", cfg.AuthservId)
		}
	})
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
