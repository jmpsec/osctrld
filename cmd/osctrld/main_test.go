package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestForceFlagDoesNotAffectVerbose(t *testing.T) {
	appConfig = Configuration{}
	app := buildApp()
	err := app.Run(context.Background(), []string{"osctrld", "--force", "--secret", "test-secret", "--environment", "11111111-1111-4111-8111-111111111111", "--osctrl-url", "http://localhost", "flags"})
	_ = err
	assert.True(t, appConfig.Force, "Force should be true when --force flag is set")
	assert.False(t, appConfig.Verbose, "Verbose should be false when only --force flag is set")
}

func TestVerboseFlagDoesNotAffectForce(t *testing.T) {
	appConfig = Configuration{}
	app := buildApp()
	err := app.Run(context.Background(), []string{"osctrld", "--verbose", "--secret", "test-secret", "--environment", "11111111-1111-4111-8111-111111111111", "--osctrl-url", "http://localhost", "flags"})
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

	err := app.Run(context.Background(), []string{"osctrld", "default-config"})
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

	cfg, _, err := loadConfiguration(configPath, false)
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

// captureStderr returns what fn wrote to os.Stderr, where cliWrapper logs
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	prev := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	defer func() { os.Stderr = prev }()
	fn()
	require.NoError(t, w.Close())
	return string(<-done)
}

// runWithFreshFlags runs the app with new flag instances: urfave/cli keeps a
// flag's "set" state across runs, and the shared ones are used by other tests
func runWithFreshFlags(t *testing.T, args ...string) (string, error) {
	t.Helper()
	prevFlags, prevConfig, prevFile, prevLogger := flags, appConfig, configFile, log.Logger
	t.Cleanup(func() { flags, appConfig, configFile, log.Logger = prevFlags, prevConfig, prevFile, prevLogger })
	flags = buildConfigFlags()
	appConfig, configFile = Configuration{}, defEmptyValue
	app := buildApp()
	app.Writer = io.Discard
	var err error
	out := captureStderr(t, func() { err = app.Run(context.Background(), append([]string{"osctrld"}, args...)) })
	return out, err
}

// A config file replaces every flag and environment variable: that stays, but
// is now warned about, naming what was ignored and never its value
func TestConfigFileOverridesFlagsWithWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "osctrld.yaml")
	require.NoError(t, os.WriteFile(path, []byte("osctrld:\n  osctrlSecret: file-secret\n  environment: 11111111-1111-4111-8111-111111111111\n  baseurl: https://osctrl.example\n  interval: 30\n"), 0600))
	t.Setenv("OSCTRL_SECRET", "env-secret-value")
	t.Setenv("OSCTRL_CONFIG", "")

	out, err := runWithFreshFlags(t, "--insecure", "--interval", "5", "--osctrl-url", "https://flag-host.example", "-c", path, "check-config")
	require.NoError(t, err)

	assert.False(t, appConfig.Insecure, "the file wins over --insecure")
	assert.Equal(t, 30, appConfig.Interval, "the file wins over --interval")
	assert.Equal(t, "file-secret", appConfig.OsctrlSecret, "the file wins over OSCTRL_SECRET")
	assert.Equal(t, 1, strings.Count(out, "takes precedence"), out)
	for _, name := range []string{"--insecure", "--interval", "--osctrl-url", "OSCTRL_SECRET"} {
		assert.Contains(t, out, name)
	}
	for _, value := range []string{"env-secret-value", "flag-host", "file-secret"} {
		assert.NotContains(t, out, value)
	}
	assert.NotContains(t, out, "--configuration", "the config file itself is not ignored")
}

func TestNoPrecedenceWarningWithoutConfigFile(t *testing.T) {
	t.Setenv("OSCTRL_CONFIG", "")
	out, err := runWithFreshFlags(t, "--insecure", "--secret", "s", "--environment", "11111111-1111-4111-8111-111111111111", "--osctrl-url", "https://osctrl.example", "check-config")
	require.NoError(t, err)
	assert.True(t, appConfig.Insecure)
	assert.NotContains(t, out, "takes precedence")
}

func TestNoPrecedenceWarningWithOnlyConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "osctrld.yaml")
	require.NoError(t, os.WriteFile(path, []byte("osctrld:\n  osctrlSecret: s\n  environment: 11111111-1111-4111-8111-111111111111\n  baseurl: https://osctrl.example\n"), 0600))
	t.Setenv("OSCTRL_CONFIG", path)
	out, err := runWithFreshFlags(t, "check-config")
	require.NoError(t, err)
	assert.NotContains(t, out, "takes precedence")
	assert.NotContains(t, out, "WRN", "no warning at all")
}

// Relative paths resolve against the working directory ('/' under systemd and
// launchd): warned about, not refused, so existing configs keep working
func TestRelativePathOptionsWarned(t *testing.T) {
	t.Setenv("OSCTRL_CONFIG", "")
	base := []string{"--secret", "s", "--environment", "11111111-1111-4111-8111-111111111111", "--osctrl-url", "https://osctrl.example"}
	abs := filepath.Join(t.TempDir(), "osquery")

	out, err := runWithFreshFlags(t, append(base, "--osquery-path", "rel/osquery", "--flagfile", abs+"/osquery.flags", "check-config")...)
	require.NoError(t, err, "a relative path is a warning, not an error")
	assert.Equal(t, 1, strings.Count(out, "relative paths"), out)
	// Paths derived from a relative osquery path are relative too
	for _, opt := range []string{`"osquery"`, `"osquerySecretFile"`, `"osqueryCertFile"`, `"extensionsDir"`} {
		assert.Contains(t, out, opt)
	}
	assert.NotContains(t, out, `"osqueryFlagFile"`)

	out, err = runWithFreshFlags(t, append(base, "--osquery-path", abs, "check-config")...)
	require.NoError(t, err)
	assert.NotContains(t, out, "relative paths")
}

// Accepted but unusual values are warned about once, never printing credentials
func TestUnusualValuesWarned(t *testing.T) {
	t.Setenv("OSCTRL_CONFIG", "")
	base := []string{"--secret", "s", "--environment", "11111111-1111-4111-8111-111111111111"}

	out, err := runWithFreshFlags(t, append(base, "--verbose", "--osctrl-url", "https://alice:hunter2@osctrl.example/", "--interval", "10081", "check-config")...)
	require.NoError(t, err, "userinfo and a long interval are accepted")
	assert.Equal(t, 1, strings.Count(out, "credentials in baseurl"), out)
	assert.Equal(t, 1, strings.Count(out, "unusually long"), out)
	assert.NotContains(t, out, "hunter2")
	assert.NotContains(t, out, "alice")

	out, err = runWithFreshFlags(t, append(base, "--osctrl-url", "https://osctrl.example", "--interval", "10080", "check-config")...)
	require.NoError(t, err)
	assert.NotContains(t, out, "credentials in baseurl")
	assert.NotContains(t, out, "unusually long")
}
