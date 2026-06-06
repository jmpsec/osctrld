package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
