package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
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

	assert.Len(t, configFlags, 13)
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
		Environment:  "dev",
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
		Environment:  "dev",
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

func TestCheckConfigCommandValidatesConfigurationFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "osctrld.yaml")
	configData := []byte(`osctrld:
  osctrlSecret: "test-secret"
  environment: "dev"
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

	err := app.Run([]string{"osctrld", "--configuration", configPath, "check-config"})

	assert.NoError(t, err)
	assert.Contains(t, output.String(), "configuration is valid")
}
