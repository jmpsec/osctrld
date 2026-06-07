package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestForceFlagDoesNotAffectVerbose(t *testing.T) {
	appConfig = Configuration{}
	app := buildApp()
	err := app.Run([]string{"osctrld", "--force", "--secret", "test-secret", "--environment", "dev", "--osctrl-url", "http://localhost", "flags"})
	_ = err
	assert.True(t, appConfig.Force, "Force should be true when --force flag is set")
	assert.False(t, appConfig.Verbose, "Verbose should be false when only --force flag is set")
}

func TestVerboseFlagDoesNotAffectForce(t *testing.T) {
	appConfig = Configuration{}
	app := buildApp()
	err := app.Run([]string{"osctrld", "--verbose", "--secret", "test-secret", "--environment", "dev", "--osctrl-url", "http://localhost", "flags"})
	_ = err
	assert.True(t, appConfig.Verbose, "Verbose should be true when --verbose flag is set")
	assert.False(t, appConfig.Force, "Force should be false when only --verbose flag is set")
}

func TestDefaultConfigCommandWritesLoadableYAML(t *testing.T) {
	appConfig = Configuration{}
	configFile = defEmptyValue
	app := buildApp()

	var stdout bytes.Buffer
	app.Writer = &stdout

	err := app.Run([]string{"osctrld", "default-config"})
	require.NoError(t, err)

	output := stdout.String()
	var expected bytes.Buffer
	encoder := yaml.NewEncoder(&expected)
	encoder.SetIndent(2)
	err = encoder.Encode(ConfigurationFile{Osctrld: defaultConfiguration()})
	require.NoError(t, err)
	require.NoError(t, encoder.Close())
	assert.Equal(t, expected.String(), output)

	configPath := filepath.Join(t.TempDir(), "osctrld.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(output), 0644))

	cfg, err := loadConfiguration(configPath, false)
	require.NoError(t, err)
	assert.Equal(t, "replace-with-osctrl-enrollment-secret", cfg.OsctrlSecret)
	assert.Equal(t, "/path/to/osquery.secret", cfg.OsquerySecretFile)
	assert.Equal(t, "/path/to/osquery.flags", cfg.OsqueryFlagFile)
	assert.Equal(t, "/path/to/osctrl.crt", cfg.OsqueryCertFile)
	assert.Equal(t, "/path/to/osquery/", cfg.OsqueryPath)
	assert.Equal(t, "/path/to/osctrld-enroll.sh", cfg.EnrollScript)
	assert.Equal(t, "/path/to/osctrld-remove.sh", cfg.RemoveScript)
	assert.False(t, cfg.Insecure)
	assert.False(t, cfg.Force)
	assert.Equal(t, 60, cfg.Interval)
}
