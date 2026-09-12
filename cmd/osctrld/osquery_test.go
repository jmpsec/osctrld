package main

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsqueryRestartCommand(t *testing.T) {
	cmd, args := osqueryRestartCommand()
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, "systemctl", cmd)
		assert.Equal(t, []string{"restart", "osqueryd"}, args)
	case "darwin":
		assert.Equal(t, "launchctl", cmd)
		assert.Equal(t, []string{"kickstart", "-k", "system/io.osquery.agent"}, args)
	default:
		assert.Empty(t, cmd, "unsupported OS should return empty command")
		assert.Nil(t, args)
	}
}

// fakeExec records every command instead of running it. The returned commands
// succeed; use fakeExecFailing for the error path.
func fakeExec(t *testing.T) *[][]string {
	t.Helper()
	recorded := &[][]string{}
	prev := execCommand
	execCommand = func(name string, args ...string) *exec.Cmd {
		*recorded = append(*recorded, append([]string{name}, args...))
		return exec.Command("true")
	}
	t.Cleanup(func() { execCommand = prev })
	return recorded
}

func fakeLookPath(t *testing.T, available ...string) {
	t.Helper()
	set := map[string]bool{}
	for _, a := range available {
		set[a] = true
	}
	prev := lookPath
	lookPath = func(file string) (string, error) {
		if set[file] {
			return "/usr/bin/" + file, nil
		}
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { lookPath = prev })
}

func TestRunCommandRecords(t *testing.T) {
	recorded := fakeExec(t)
	require.NoError(t, runCommand("systemctl", "stop", "osqueryd"))
	assert.Equal(t, [][]string{{"systemctl", "stop", "osqueryd"}}, *recorded)
}

func TestRunCommandReportsFailure(t *testing.T) {
	prev := execCommand
	t.Cleanup(func() { execCommand = prev })
	execCommand = func(name string, args ...string) *exec.Cmd { return exec.Command("false") }

	err := runCommand("systemctl", "stop", "osqueryd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "systemctl")
}

func TestRunFirstAvailableSkipsMissingBinaries(t *testing.T) {
	recorded := fakeExec(t)
	fakeLookPath(t, "service")

	err := runFirstAvailable([][]string{
		{"systemctl", "stop", "osqueryd"},
		{"service", "osqueryd", "stop"},
	})
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"service", "osqueryd", "stop"}}, *recorded,
		"systemctl is absent, so the service fallback must be used")
}

func TestRunFirstAvailableNoneFound(t *testing.T) {
	fakeExec(t)
	fakeLookPath(t)

	err := runFirstAvailable([][]string{{"systemctl", "stop", "osqueryd"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no service manager")
}

func TestStopOsqueryLinux(t *testing.T) {
	if runtime.GOOS != LinuxOS {
		t.Skip("linux-only dispatch")
	}
	recorded := fakeExec(t)
	fakeLookPath(t, "systemctl")

	require.NoError(t, stopOsquery())
	assert.Equal(t, [][]string{{"systemctl", "stop", "osqueryd"}}, *recorded)
}

func TestStopOsqueryDarwin(t *testing.T) {
	if runtime.GOOS != DarwinOS {
		t.Skip("darwin-only dispatch")
	}
	recorded := fakeExec(t)

	require.NoError(t, stopOsquery())
	assert.Equal(t, [][]string{{"launchctl", "unload", darwinLaunchDaemon}}, *recorded)
}

// TestStopOsqueryDarwinToleratesFailedUnload locks in that a failed launchctl
// unload (e.g. osquery was never loaded) is still reported as success: a
// first-time install depends on this.
func TestStopOsqueryDarwinToleratesFailedUnload(t *testing.T) {
	if runtime.GOOS != DarwinOS {
		t.Skip("darwin-only dispatch")
	}
	prev := execCommand
	t.Cleanup(func() { execCommand = prev })
	execCommand = func(name string, args ...string) *exec.Cmd { return exec.Command("false") }

	require.NoError(t, stopOsquery())
}

func TestEnableOsqueryLinuxFallsBackToUpdateRcD(t *testing.T) {
	if runtime.GOOS != LinuxOS {
		t.Skip("linux-only dispatch")
	}
	recorded := fakeExec(t)
	fakeLookPath(t, "update-rc.d")

	require.NoError(t, enableOsquery())
	assert.Equal(t, [][]string{{"update-rc.d", "osqueryd", "defaults"}}, *recorded)
}

func TestStartOsqueryLinux(t *testing.T) {
	if runtime.GOOS != LinuxOS {
		t.Skip("linux-only dispatch")
	}
	recorded := fakeExec(t)
	fakeLookPath(t, "systemctl")

	require.NoError(t, startOsquery())
	assert.Equal(t, [][]string{{"systemctl", "start", "osqueryd"}}, *recorded)
}

func TestStartOsqueryDarwin(t *testing.T) {
	if runtime.GOOS != DarwinOS {
		t.Skip("darwin-only dispatch")
	}
	recorded := fakeExec(t)

	require.NoError(t, startOsquery())
	assert.Equal(t, [][]string{
		{"cp", darwinSourcePlist, darwinLaunchDaemon},
		{"launchctl", "load", darwinLaunchDaemon},
	}, *recorded)
}
