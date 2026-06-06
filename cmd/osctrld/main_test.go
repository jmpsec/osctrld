package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForceFlagDoesNotAffectVerbose(t *testing.T) {
	appConfig = Configuration{}
	app := buildApp()
	err := app.Run([]string{"osctrld", "--force", "--environment", "dev", "--osctrl-url", "http://localhost", "flags"})
	_ = err
	assert.True(t, appConfig.Force, "Force should be true when --force flag is set")
	assert.False(t, appConfig.Verbose, "Verbose should be false when only --force flag is set")
}

func TestVerboseFlagDoesNotAffectForce(t *testing.T) {
	appConfig = Configuration{}
	app := buildApp()
	err := app.Run([]string{"osctrld", "--verbose", "--environment", "dev", "--osctrl-url", "http://localhost", "flags"})
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
	assert.True(t, strings.HasPrefix(output, "osctrld:\n"))
	assert.Contains(t, output, `secret: "replace-with-osctrl-enrollment-secret"`)
	assert.Contains(t, output, `secretFile: "/path/to/osquery.secret"`)
	assert.Contains(t, output, `flags: "/path/to/osquery.flags"`)
	assert.Contains(t, output, `cert: "/path/to/osctrl.crt"`)
	assert.Contains(t, output, `enrollScript: "/path/to/osctrld-enroll.sh"`)
	assert.Contains(t, output, `removeScript: "/path/to/osctrld-remove.sh"`)
	assert.Contains(t, output, `osquery: "/path/to/osquery/"`)
	assert.Contains(t, output, `environment: "environment_name_or_UUID"`)
	assert.Contains(t, output, `baseurl: "https://osctrl.url"`)
	assert.Contains(t, output, "insecure: false")
	assert.Contains(t, output, "verbose: false")
	assert.Contains(t, output, "force: false")
	assert.Contains(t, output, `logFormat: "text"`)
	assert.Contains(t, output, "interval: 60")
	assert.Contains(t, output, `extensionsDir: "/path/to/extensions/"`)

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
