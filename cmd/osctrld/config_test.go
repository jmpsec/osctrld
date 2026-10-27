package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestLoadConfigurationInvalid(t *testing.T) {
	_, err := loadConfiguration("nonexistent-file.yaml", false)
	assert.Error(t, err)
}

func TestLoadConfigurationJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld-test.json")
	configData := []byte(`{
  "osctrld": {
    "osctrlSecret": "test-secret",
    "osquerySecretFile": "/tmp/osquery.secret",
    "osqueryFlagFile": "/tmp/osquery.flags",
    "osqueryCertFile": "/tmp/osctrl.crt",
    "environment": "dev",
    "baseurl": "https://localhost:9000",
    "insecure": true,
    "verbose": true,
    "force": true
  }
}`)
	err := os.WriteFile(configPath, configData, 0644)
	assert.NoError(t, err)

	cfg, err := loadConfiguration(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "test-secret", cfg.OsctrlSecret)
	assert.Equal(t, "/tmp/osquery.secret", cfg.OsquerySecretFile)
	assert.Equal(t, "/tmp/osquery.flags", cfg.OsqueryFlagFile)
	assert.Equal(t, "/tmp/osctrl.crt", cfg.OsqueryCertFile)
	assert.Equal(t, "dev", cfg.Environment)
	assert.Equal(t, "https://localhost:9000", cfg.BaseURL)
	assert.True(t, cfg.Insecure)
	assert.True(t, cfg.Verbose)
	assert.True(t, cfg.Force)
}

func TestLoadConfigurationYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld-test.yaml")
	configData := []byte(`osctrld:
  osctrlSecret: "test-secret"
  osquerySecretFile: "/tmp/osquery.secret"
  osqueryFlagFile: "/tmp/osquery.flags"
  osqueryCertFile: "/tmp/osctrl.crt"
  environment: "dev"
  baseurl: "https://localhost:9000"
  insecure: true
  verbose: true
  force: true
  logFormat: "json"
  interval: 30
  extensionsDir: "/tmp/extensions/"
`)
	err := os.WriteFile(configPath, configData, 0644)
	assert.NoError(t, err)

	cfg, err := loadConfiguration(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "test-secret", cfg.OsctrlSecret)
	assert.Equal(t, "/tmp/osquery.secret", cfg.OsquerySecretFile)
	assert.Equal(t, "/tmp/osquery.flags", cfg.OsqueryFlagFile)
	assert.Equal(t, "/tmp/osctrl.crt", cfg.OsqueryCertFile)
	assert.Equal(t, "dev", cfg.Environment)
	assert.Equal(t, "https://localhost:9000", cfg.BaseURL)
	assert.True(t, cfg.Insecure)
	assert.True(t, cfg.Verbose)
	assert.True(t, cfg.Force)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.Equal(t, 30, cfg.Interval)
	assert.Equal(t, "/tmp/extensions/", cfg.ExtensionsDir)
}

func TestLoadConfigurationLegacySecretFields(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld-legacy.yaml")
	configData := []byte(`osctrld:
  secret: "legacy-secret"
  secretFile: "/tmp/legacy.secret"
  flags: "/tmp/legacy.flags"
  cert: "/tmp/legacy.crt"
`)
	err := os.WriteFile(configPath, configData, 0644)
	assert.NoError(t, err)

	cfg, err := loadConfiguration(configPath, false)
	assert.NoError(t, err)
	assert.Equal(t, "legacy-secret", cfg.OsctrlSecret)
	assert.Equal(t, "/tmp/legacy.secret", cfg.OsquerySecretFile)
	assert.Equal(t, "/tmp/legacy.flags", cfg.OsqueryFlagFile)
	assert.Equal(t, "/tmp/legacy.crt", cfg.OsqueryCertFile)
}

func TestBuildConfigFlagsIncludesConfigurationDefaults(t *testing.T) {
	appConfig = Configuration{}
	configFile = defEmptyValue

	configFlags := buildConfigFlags()

	assert.Len(t, configFlags, 16)
	assert.Equal(t, "configuration", configFlags[0].Names()[0])
	assert.Equal(t, "secret", configFlags[1].Names()[0])
	logFormatFlag, ok := configFlags[11].(*cli.StringFlag)
	assert.True(t, ok)
	assert.Equal(t, defLogFormat, logFormatFlag.Value)
	intervalFlag, ok := configFlags[12].(*cli.IntFlag)
	assert.True(t, ok)
	assert.Equal(t, defInterval, intervalFlag.Value)
}

func TestValidateConfigurationAcceptsValidConfig(t *testing.T) {
	cfg := Configuration{
		OsctrlSecret: "test-secret",
		Environment:  "11111111-1111-4111-8111-111111111111",
		BaseURL:      "https://localhost:9000",
		LogFormat:    "json",
		Interval:     30,
	}
	applyConfigurationDefaults(&cfg)

	assert.NoError(t, validateConfiguration(cfg))
	assert.NotEmpty(t, cfg.OsquerySecretFile)
	assert.NotEmpty(t, cfg.OsqueryFlagFile)
	assert.NotEmpty(t, cfg.OsqueryCertFile)
}

func TestValidateConfigurationRejectsMissingRequiredFields(t *testing.T) {
	cfg := Configuration{
		LogFormat: defLogFormat,
		Interval:  defInterval,
	}

	err := validateConfiguration(cfg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "osctrlSecret is required")
	assert.Contains(t, err.Error(), "environment is required")
	assert.Contains(t, err.Error(), "baseurl is required")
}

func TestValidateConfigurationRejectsInvalidValues(t *testing.T) {
	cfg := Configuration{
		OsctrlSecret: "test-secret",
		Environment:  "11111111-1111-4111-8111-111111111111",
		BaseURL:      "ftp://localhost",
		LogFormat:    "xml",
		Interval:     0,
	}

	err := validateConfiguration(cfg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "baseurl must use http or https")
	assert.Contains(t, err.Error(), "logFormat must be text or json")
	assert.Contains(t, err.Error(), "interval must be greater than 0")
}

func TestBuildConfigFlagsIncludesInstallFlags(t *testing.T) {
	configFlags := buildConfigFlags()

	names := map[string]bool{}
	for _, f := range configFlags {
		names[f.Names()[0]] = true
	}
	assert.True(t, names["osquery-sha256"], "osquery-sha256 flag missing")
	assert.True(t, names["allow-unverified"], "allow-unverified flag missing")
	assert.True(t, names["osquery-package"], "osquery-package flag missing")
}

func TestCheckConfigCommandValidatesConfigurationFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld.yaml")
	configData := []byte(`osctrld:
  osctrlSecret: "test-secret"
  environment: "11111111-1111-4111-8111-111111111111"
  baseurl: "https://localhost:9000"
  logFormat: "text"
  interval: 60
`)
	assert.NoError(t, os.WriteFile(configPath, configData, 0644))

	appConfig = Configuration{}
	configFile = defEmptyValue
	app := buildApp()
	var output strings.Builder
	app.Writer = &output

	err := app.Run(context.Background(), []string{"osctrld", "--configuration", configPath, "check-config"})

	assert.NoError(t, err)
	assert.Contains(t, output.String(), "configuration is valid")
}

// osctrl's osctrld endpoints look the environment up by UUID and answer a bare
// HTTP 400 to anything else, so a name must be caught here with a clear message.
func TestValidateConfigurationRequiresEnvironmentUUID(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		valid bool
	}{
		{"canonical uuid", "11111111-1111-4111-8111-111111111111", true},
		{"uppercase uuid", "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D", true},
		{"environment name", "dev", false},
		{"uuid without dashes", "11111111111141118111111111111111", false},
		{"uuid with trailing text", "11111111-1111-4111-8111-111111111111x", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Configuration{OsctrlSecret: "s", Environment: tt.env, BaseURL: "https://osctrl.example", LogFormat: defLogFormat, Interval: defInterval}
			err := validateConfiguration(cfg)
			if tt.valid {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "environment must be the osctrl environment UUID")
		})
	}
}

func TestWarnCleartextURLs(t *testing.T) {
	tests := []struct {
		name, baseURL, pkg string
		want               []string
	}{
		{"https everywhere", "https://osctrl.example.com", "https://mirror.example.com/osquery.pkg", nil},
		{"no package override", "https://osctrl.example.com", "", nil},
		{"http baseurl", "http://osctrl.example.com", "", []string{"baseurl"}},
		{"http package", "https://osctrl.example.com", "http://mirror.example.com/osquery.pkg", []string{"osqueryPackage"}},
		{"both http", "HTTP://osctrl.example.com", "http://mirror.example.com/osquery.pkg", []string{"baseurl", "osqueryPackage"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			old := log.Logger
			log.Logger = zerolog.New(&logs)
			t.Cleanup(func() { log.Logger = old })
			warnCleartextURLs(Configuration{BaseURL: tt.baseURL, OsqueryPackage: tt.pkg})
			out := logs.String()
			if tt.want == nil {
				assert.Empty(t, out)
				return
			}
			assert.Equal(t, len(tt.want), strings.Count(out, `"level":"warn"`))
			for _, opt := range tt.want {
				assert.Contains(t, out, `"option":"`+opt+`"`)
			}
		})
	}
}
