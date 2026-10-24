package main

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsqueryRestartCandidates(t *testing.T) {
	// Linux restarts through the same systemctl -> service -> init.d chain as
	// install's stop and start, so hosts without systemd can apply new flags
	assert.Equal(t, [][]string{
		{"systemctl", "restart", "osqueryd"},
		{"service", "osqueryd", "restart"},
		{"/etc/init.d/osqueryd", "restart"},
	}, osqueryRestartCandidates(LinuxOS))
	assert.Equal(t, [][]string{{"launchctl", "kickstart", "-k", "system/io.osquery.agent"}}, osqueryRestartCandidates(DarwinOS))
	// Windows restarts through the service manager, not a command
	assert.Nil(t, osqueryRestartCandidates(WindowsOS))
	assert.Nil(t, osqueryRestartCandidates("plan9"))
}

func TestRestartOsqueryFallsBackWithoutSystemd(t *testing.T) {
	if runtime.GOOS != LinuxOS {
		t.Skip("linux-only dispatch")
	}
	recorded := fakeExec(t)
	fakeLookPath(t, "service")

	require.NoError(t, restartOsquery())
	assert.Equal(t, [][]string{{"service", "osqueryd", "restart"}}, *recorded)
}

func TestRestartOsqueryDarwin(t *testing.T) {
	if runtime.GOOS != DarwinOS {
		t.Skip("darwin-only dispatch")
	}
	recorded := fakeExec(t)
	fakeLookPath(t, "launchctl")

	require.NoError(t, restartOsquery())
	assert.Equal(t, [][]string{{"launchctl", "kickstart", "-k", "system/io.osquery.agent"}}, *recorded)
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

func TestServiceCommandLine(t *testing.T) {
	const ff = `C:\Program Files\osquery\osquery.flags`
	const exe = `"C:\Program Files\osquery\osqueryd\osqueryd.exe"`
	for _, tc := range []struct {
		name, existing, want string
		changed              bool
	}{
		{"quoted value kept", exe + ` --flagfile="` + ff + `"`, exe + ` --flagfile="` + ff + `"`, false},
		{"case and quotes tolerated", exe + ` "--flagfile=c:\program files\osquery\OSQUERY.FLAGS"`, exe + ` "--flagfile=c:\program files\osquery\OSQUERY.FLAGS"`, false},
		{"missing added", exe, exe + ` --flagfile="` + ff + `"`, true},
		{"other args kept", exe + ` --windows_service`, exe + ` --windows_service --flagfile="` + ff + `"`, true},
		{"wrong replaced", exe + ` --flagfile=C:\other.flags --verbose`, exe + ` --verbose --flagfile="` + ff + `"`, true},
		{"space form replaced", exe + ` --flagfile "C:\other.flags"`, exe + ` --flagfile="` + ff + `"`, true},
		{"duplicate collapsed", exe + ` --flagfile="` + ff + `" --flagfile=C:\x`, exe + ` --flagfile="` + ff + `"`, true},
		{"single dash", exe + ` -flagfile=C:\x`, exe + ` --flagfile="` + ff + `"`, true},
		{"unquoted exe", `C:\osquery\osqueryd.exe`, `C:\osquery\osqueryd.exe --flagfile="` + ff + `"`, true},
		{"empty left alone", ``, ``, false},
		{"flag name is case-sensitive", exe + ` --FLAGFILE="` + ff + `"`, exe + ` --FLAGFILE="` + ff + `" --flagfile="` + ff + `"`, true},
		{"path is not", exe + ` --flagfile="` + strings.ToUpper(ff) + `"`, exe + ` --flagfile="` + strings.ToUpper(ff) + `"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed, err := serviceCommandLine(tc.existing, ff)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.changed, changed)
		})
	}
	for _, bad := range []string{`C:\osquery"x".flags`, `C:\osquery\`} {
		t.Run("refuses "+bad, func(t *testing.T) {
			got, changed, err := serviceCommandLine(exe, bad)
			require.Error(t, err)
			assert.Equal(t, exe, got, "left unchanged")
			assert.False(t, changed)
		})
	}
}

// TestFixServiceConfig covers the decision ensureServiceSettings applies; the
// svc/mgr wiring around it is Windows-only and compile-checked only
func TestFixServiceConfig(t *testing.T) {
	const ff = `C:\osquery\osquery.flags`
	const exe = `"C:\Program Files\osquery\osqueryd\osqueryd.exe"`
	good := exe + ` --flagfile="` + ff + `"`
	for _, tc := range []struct {
		name      string
		automatic bool
		bin       string
		changed   bool
	}{
		{"flagfile missing", true, exe, true},
		{"manual start", false, good, true},
		{"both reset", false, exe, true},
		{"already correct", true, good, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, changed, err := fixServiceConfig(tc.automatic, tc.bin, ff)
			require.NoError(t, err)
			assert.Equal(t, tc.changed, changed)
			assert.Equal(t, good, bin, "the update always carries the flagfile")
		})
	}
	t.Run("refused path still fixes the start type", func(t *testing.T) {
		bin, changed, err := fixServiceConfig(false, exe, `C:\bad\`)
		require.Error(t, err)
		assert.True(t, changed)
		assert.Equal(t, exe, bin)
	})
}
