//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsqueryInstallDecision(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		required  string
		expected  bool
	}{
		{"not installed", "", "5.12.1", true},
		{"older must install", "5.11.0", "5.12.1", true},
		{"much older must install", "4.9.0", "5.0.0", true},
		{"equal is skipped", "5.12.1", "5.12.1", false},
		{"newer is left alone", "5.13.0", "5.12.1", false},
		{"newer major is left alone", "6.0.0", "5.12.1", false},
		{"unparseable installed is reinstalled", "5.12.x", "5.12.1", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, osqueryInstallDecision(tt.installed, tt.required))
		})
	}
}

func TestInstallNodeRequiresPrivileges(t *testing.T) {
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int { return 501 }

	err := installNode(context.Background(), newTestCLICommand())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestEnsureOsquerySkipsWhenCurrent(t *testing.T) {
	recorded := fakeExec(t)

	prevVersion := osqueryVersionReader
	t.Cleanup(func() { osqueryVersionReader = prevVersion })
	osqueryVersionReader = func() string { return "5.12.1" }

	require.NoError(t, ensureOsquery(VerifyResponse{OsqueryVersion: "5.12.1"}))
	assert.Empty(t, *recorded, "nothing should be installed when the version already matches")
}

func TestRemoveIfExists(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(present, []byte("s3cr3t"), 0600))

	require.NoError(t, removeIfExists(present, "secret"))
	assert.NoFileExists(t, present)

	// An absent file is reported, not an error: uninstall must be idempotent
	require.NoError(t, removeIfExists(filepath.Join(dir, "never-existed"), "secret"))
}

func TestUninstallNodeRequiresPrivileges(t *testing.T) {
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int { return 501 }

	err := uninstallNode(context.Background(), newTestCLICommand())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestUninstallNodeRemovesTheThreeFiles(t *testing.T) {
	prevUID := geteuid
	t.Cleanup(func() { geteuid = prevUID })
	geteuid = func() int { return 0 }
	fakeExec(t)
	fakeLookPath(t, "systemctl")

	dir := t.TempDir()
	prevConfig := appConfig
	t.Cleanup(func() { appConfig = prevConfig })
	appConfig = Configuration{
		OsquerySecretFile: filepath.Join(dir, "osquery.secret"),
		OsqueryFlagFile:   filepath.Join(dir, "osquery.flags"),
		OsqueryCertFile:   filepath.Join(dir, "osctrl.crt"),
	}
	for _, p := range []string{appConfig.OsquerySecretFile, appConfig.OsqueryFlagFile, appConfig.OsqueryCertFile} {
		require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	}

	require.NoError(t, uninstallNode(context.Background(), newTestCLICommand()))

	assert.NoFileExists(t, appConfig.OsquerySecretFile)
	assert.NoFileExists(t, appConfig.OsqueryFlagFile)
	assert.NoFileExists(t, appConfig.OsqueryCertFile)
}
