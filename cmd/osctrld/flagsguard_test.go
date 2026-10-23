package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testEnvFlags      = "--tls_hostname=osctrl.example.com"
	testOverrideFlags = "--tls_hostname=osctrl.example.com\n--bad_flag=1"
)

// flagsServer serves override when the request carries a uuid and env otherwise,
// recording every request it receives
type flagsServer struct {
	mu       sync.Mutex
	override string
	env      string
	requests []FlagsRequest
}

func (s *flagsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req FlagsRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, req)
	if req.UUID != "" {
		_, _ = w.Write([]byte(s.override))
		return
	}
	_, _ = w.Write([]byte(s.env))
}

func (s *flagsServer) recorded() []FlagsRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]FlagsRequest(nil), s.requests...)
}

// setupGuard wires a fake osctrl, host uuid, process check and service manager
func setupGuard(t *testing.T, override string, running func() (bool, error)) (*flagsServer, *[][]string) {
	t.Helper()
	fs := &flagsServer{override: override, env: testEnvFlags}
	server := httptest.NewServer(fs)
	t.Cleanup(server.Close)

	prevConfig, prevURLs := appConfig, osctrlURLs
	prevUUID, prevRunning, prevVersion := hostUUIDReader, osquerydRunning, osqueryVersionReader
	prevTimeout, prevInterval := restartCheckTimeout, restartCheckInterval
	t.Cleanup(func() {
		appConfig, osctrlURLs = prevConfig, prevURLs
		hostUUIDReader, osquerydRunning, osqueryVersionReader = prevUUID, prevRunning, prevVersion
		restartCheckTimeout, restartCheckInterval = prevTimeout, prevInterval
	})

	dir := t.TempDir()
	appConfig = Configuration{
		OsctrlSecret:      "test-secret",
		OsquerySecretFile: filepath.Join(dir, "osquery.secret"),
		OsqueryFlagFile:   filepath.Join(dir, "osquery.flags"),
		OsqueryCertFile:   filepath.Join(dir, "osctrl.crt"),
		Force:             true,
	}
	osctrlURLs = genURLs(server.URL, "env", false)
	osctrlURLs.Flags = server.URL + "/flags"
	// An osctrl without the upgrade route: syncs stay quiet about upgrades
	noUpgrades := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(noUpgrades.Close)
	osctrlURLs.Osquery = noUpgrades.URL
	osqueryVersionReader = func() string { return "5.12.1" }
	hostUUIDReader = func() (string, error) { return testHostUUID, nil }
	if running == nil {
		running = func() (bool, error) { return true, nil }
	}
	osquerydRunning = running
	restartCheckTimeout = 50 * time.Millisecond
	restartCheckInterval = 5 * time.Millisecond

	recorded := fakeExec(t)
	fakeLookPath(t, "launchctl", "systemctl")
	return fs, recorded
}

func readFlagFile(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(appConfig.OsqueryFlagFile)
	require.NoError(t, err)
	return string(b)
}

func neverRunning() (bool, error) { return false, nil }

func TestSyncFlagsSendsUUIDAndLastStatus(t *testing.T) {
	fs, _ := setupGuard(t, testOverrideFlags, nil)
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{
		Last: &ApplyStatus{Result: "ok", SHA256: sha256Hex(testEnvFlags), At: at},
	}))

	changed, attempted, uuid, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, testOverrideFlags, attempted)
	assert.Equal(t, testHostUUID, uuid)

	reqs := fs.recorded()
	require.Len(t, reqs, 1)
	assert.Equal(t, testHostUUID, reqs[0].UUID)
	require.NotNil(t, reqs[0].Apply)
	assert.Equal(t, "ok", reqs[0].Apply.Result)
	assert.Equal(t, sha256Hex(testEnvFlags), reqs[0].Apply.SHA256)
	assert.Equal(t, testOverrideFlags, readFlagFile(t))
}

func TestSyncFlagsWithoutUUIDWhenLookupFails(t *testing.T) {
	fs, _ := setupGuard(t, testOverrideFlags, nil)
	hostUUIDReader = func() (string, error) { return "", errors.New("osqueryd missing") }

	changed, _, uuid, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Empty(t, uuid)

	reqs := fs.recorded()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].UUID)
	assert.Nil(t, reqs[0].Apply, "no state file yet, so no status to report")
	assert.Equal(t, testEnvFlags, readFlagFile(t))
}

func TestSyncFlagsUnchanged(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags+"\n"), 0700))

	changed, _, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestVerifyAfterRestartOK(t *testing.T) {
	fs, recorded := setupGuard(t, testOverrideFlags, nil)
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))

	st := loadFlagsState(flagsStatePath())
	require.NotNil(t, st.Last)
	assert.Equal(t, "ok", st.Last.Result)
	assert.Equal(t, sha256Hex(testOverrideFlags), st.Last.SHA256)
	assert.Empty(t, st.Last.Error)
	assert.Empty(t, st.RejectedSHA256)
	assert.Empty(t, fs.recorded(), "no rollback request")
	assert.Empty(t, *recorded, "no rollback restart")
	assert.Equal(t, testOverrideFlags, readFlagFile(t))
}

func TestVerifyAfterRestartKeepsRejectedHashOnOK(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{RejectedSHA256: "old"}))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testEnvFlags, testHostUUID))
	assert.Equal(t, "old", loadFlagsState(flagsStatePath()).RejectedSHA256)
}

func TestVerifyAfterRestartRollsBack(t *testing.T) {
	fs, recorded := setupGuard(t, testOverrideFlags, neverRunning)
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))

	assert.Equal(t, testEnvFlags, readFlagFile(t), "environment flags written back")
	assert.Len(t, *recorded, 1, "one rollback restart")
	reqs := fs.recorded()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].UUID, "rollback asks for the environment flags")
	assert.Nil(t, reqs[0].Apply)

	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)
	assert.Equal(t, sha256Hex(testOverrideFlags), st.Last.SHA256)
	assert.Equal(t, rejectedErrorFor(restartCheckTimeout), st.Last.Error)
}

// A service manager respawning a crashing osqueryd makes it visible briefly;
// that must not count as a successful apply
func TestVerifyAfterRestartFlappingIsRejected(t *testing.T) {
	var mu sync.Mutex
	n := 0
	setupGuard(t, testOverrideFlags, func() (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		n++
		return n%2 == 0, nil
	})

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))
	st := loadFlagsState(flagsStatePath())
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)
}

func TestVerifyAfterRestartRejectsWhenRollbackFetchFails(t *testing.T) {
	setupGuard(t, testOverrideFlags, neverRunning)
	osctrlURLs.Flags = "http://127.0.0.1:1/flags"

	err := verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID)
	assert.Error(t, err)
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256,
		"rejection is remembered so the next sync writes the environment flags")
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)
}

func TestVerifyAfterRestartStopsOnCancel(t *testing.T) {
	setupGuard(t, testOverrideFlags, neverRunning)
	restartCheckTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := verifyFlagsAfterRestart(ctx, testOverrideFlags, testHostUUID)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, loadFlagsState(flagsStatePath()).Last)
}

func TestSyncFlagsSkipsRejectedContent(t *testing.T) {
	fs, _ := setupGuard(t, testOverrideFlags, nil)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{RejectedSHA256: sha256Hex(testOverrideFlags)}))

	changed, attempted, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, testEnvFlags, attempted)
	assert.Equal(t, testEnvFlags, readFlagFile(t))

	reqs := fs.recorded()
	require.Len(t, reqs, 2)
	assert.Equal(t, testHostUUID, reqs[0].UUID)
	assert.Empty(t, reqs[1].UUID)

	// Already holding the environment flags: nothing to do
	changed, _, _, err = syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, testEnvFlags, readFlagFile(t))
}

func TestSyncFlagsRetriesWhenContentChanges(t *testing.T) {
	newOverride := "--tls_hostname=osctrl.example.com\n--host_identifier=uuid"
	fs, _ := setupGuard(t, newOverride, nil)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{RejectedSHA256: sha256Hex(testOverrideFlags)}))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testEnvFlags), 0700))

	changed, attempted, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, newOverride, attempted)
	assert.Equal(t, newOverride, readFlagFile(t))
	assert.Len(t, fs.recorded(), 1)
}

func TestVerifyAfterRestartEnvFlagsFailToo(t *testing.T) {
	_, recorded := setupGuard(t, testEnvFlags, neverRunning)
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testEnvFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testEnvFlags, testHostUUID))

	assert.Empty(t, *recorded, "nothing to roll back to, no restart")
	st := loadFlagsState(flagsStatePath())
	assert.Empty(t, st.RejectedSHA256)
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)
	assert.Equal(t, sha256Hex(testEnvFlags), st.Last.SHA256)
	assert.Equal(t, rejectedErrorFor(restartCheckTimeout), st.Last.Error)
}

func TestLoadFlagsStateCorrupt(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{not json"), 0600))

	for name, path := range map[string]string{
		"corrupt":   corrupt,
		"missing":   filepath.Join(dir, "missing.json"),
		"directory": dir,
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, flagsState{}, loadFlagsState(path))
		})
	}
}

func TestSaveFlagsStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	want := flagsState{
		Last:           &ApplyStatus{Result: "rejected", SHA256: "ab", Error: "e", At: at},
		RejectedSHA256: "ab",
	}
	require.NoError(t, saveFlagsState(path, want))
	got := loadFlagsState(path)
	assert.Equal(t, want.RejectedSHA256, got.RejectedSHA256)
	require.NotNil(t, got.Last)
	assert.True(t, at.Equal(got.Last.At))
	assert.Equal(t, "rejected", got.Last.Result)
}

func TestSaveFlagsStateMode(t *testing.T) {
	if runtime.GOOS == WindowsOS {
		t.Skip("no unix modes on windows")
	}
	path := filepath.Join(t.TempDir(), "state.json")
	// A pre-existing, too-open file is tightened too
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0644))
	require.NoError(t, saveFlagsState(path, flagsState{RejectedSHA256: "ab"}))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestFlagsStatePath(t *testing.T) {
	prev := appConfig
	t.Cleanup(func() { appConfig = prev })
	appConfig.OsqueryFlagFile = "/etc/osquery/osquery.flags"
	assert.Equal(t, "/etc/osquery/osquery.flags.osctrld-state.json", flagsStatePath())
}

func TestIsOsquerydRunningMatchesName(t *testing.T) {
	prev := processNames
	t.Cleanup(func() { processNames = prev })

	tests := []struct {
		name string
		want bool
	}{
		{"osqueryd", true},
		{"osqueryd.exe", true},
		{"OSQUERYD.EXE", true},
		{"osqueryi", false},
		{"not-osqueryd-helper", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processNames = func() ([]string, error) { return []string{"launchd", tt.name}, nil }
			got, err := isOsquerydRunning()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	processNames = func() ([]string, error) { return nil, errors.New("boom") }
	_, err := isOsquerydRunning()
	assert.Error(t, err)
}

// syncOnceGuard points cert and extensions at a server that 404s, so only flags change
func syncOnceGuard(t *testing.T, running func() (bool, error)) *[][]string {
	t.Helper()
	_, recorded := setupGuard(t, testOverrideFlags, running)
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	osctrlURLs.Cert = notFound.URL
	osctrlURLs.Extensions = notFound.URL
	return recorded
}

func TestSyncOnceVerifiesChangedFlags(t *testing.T) {
	recorded := syncOnceGuard(t, neverRunning)

	syncOnce(context.Background(), newTestCLICommand())

	assert.Len(t, *recorded, 2, "restart for the new flags, then the rollback restart")
	assert.Equal(t, testEnvFlags, readFlagFile(t))
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)

	// The next cycle keeps the environment flags: no restart, no new check
	*recorded = nil
	syncOnce(context.Background(), newTestCLICommand())
	assert.Empty(t, *recorded)
	assert.Equal(t, testEnvFlags, readFlagFile(t))
}

func TestSyncOnceSkipsVerifyWhenFlagsUnchanged(t *testing.T) {
	checks := 0
	recorded := syncOnceGuard(t, func() (bool, error) { checks++; return false, nil })
	resetHealth(t) // unknown at start: no upgrade check polls
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	syncOnce(context.Background(), newTestCLICommand())

	assert.Empty(t, *recorded)
	assert.Equal(t, 1, checks, "only the end-of-sync status poll")
	assert.Equal(t, testOverrideFlags, readFlagFile(t))
}

func TestSyncFlagsSetsPending(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)

	changed, _, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, sha256Hex(testOverrideFlags), loadFlagsState(flagsStatePath()).Pending)

	// Unchanged content leaves Pending to the verification, it never sets a new one
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{}))
	changed, _, _, err = syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Empty(t, loadFlagsState(flagsStatePath()).Pending)
}

func TestVerifyAfterRestartClearsPending(t *testing.T) {
	for name, running := range map[string]func() (bool, error){
		"ok":       nil,
		"rejected": neverRunning,
	} {
		t.Run(name, func(t *testing.T) {
			setupGuard(t, testOverrideFlags, running)
			require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{Pending: sha256Hex(testOverrideFlags)}))
			require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))
			st := loadFlagsState(flagsStatePath())
			assert.Empty(t, st.Pending)
			require.NotNil(t, st.Last)
			assert.Equal(t, name, st.Last.Result)
		})
	}
}

func TestSyncOnceRestartErrorStillVerifies(t *testing.T) {
	syncOnceGuard(t, neverRunning)
	restarts := 0
	execCommand = func(name string, args ...string) *exec.Cmd {
		restarts++
		return exec.Command("false")
	}

	syncOnce(context.Background(), newTestCLICommand())

	assert.Equal(t, 2, restarts, "failed restart, then the rollback restart")
	assert.Equal(t, testEnvFlags, readFlagFile(t))
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)
	assert.Empty(t, st.Pending)
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)
}

func TestSyncOnceResumesInterruptedCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// osctrld is stopped while waiting for osqueryd
	recorded := syncOnceGuard(t, func() (bool, error) { cancel(); return false, nil })

	syncOnce(ctx, newTestCLICommand())
	assert.Len(t, *recorded, 1, "restart for the new flags")
	assert.Equal(t, testOverrideFlags, readFlagFile(t))
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, sha256Hex(testOverrideFlags), st.Pending, "unverified flags stay pending")
	assert.Nil(t, st.Last)

	// Next start: flags are unchanged on disk, the check resumes without a
	// restart and rolls back
	*recorded = nil
	osquerydRunning = neverRunning
	syncOnce(context.Background(), newTestCLICommand())
	assert.Len(t, *recorded, 1, "only the rollback restart")
	assert.Equal(t, testEnvFlags, readFlagFile(t))
	st = loadFlagsState(flagsStatePath())
	assert.Empty(t, st.Pending)
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)

	// After the rollback nothing re-verifies the environment flags: the
	// rejection stays reported
	*recorded = nil
	osquerydRunning = func() (bool, error) { return true, nil }
	syncOnce(context.Background(), newTestCLICommand())
	assert.Empty(t, *recorded)
	st = loadFlagsState(flagsStatePath())
	assert.Empty(t, st.Pending)
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)
}

func TestSyncOnceResumedCheckOK(t *testing.T) {
	recorded := syncOnceGuard(t, nil)
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{Pending: sha256Hex(testOverrideFlags)}))

	syncOnce(context.Background(), newTestCLICommand())

	assert.Empty(t, *recorded, "a resumed check does not restart")
	st := loadFlagsState(flagsStatePath())
	assert.Empty(t, st.Pending)
	require.NotNil(t, st.Last)
	assert.Equal(t, "ok", st.Last.Result)
}

func TestSyncOnceClearsStalePending(t *testing.T) {
	checks := 0
	recorded := syncOnceGuard(t, func() (bool, error) { checks++; return false, nil })
	resetHealth(t) // unknown at start, as other tests leave it: no upgrade-gate check
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{Pending: sha256Hex("edited since")}))

	syncOnce(context.Background(), newTestCLICommand())

	assert.Equal(t, 1, checks, "only the end-of-sync status poll")
	assert.Empty(t, *recorded)
	st := loadFlagsState(flagsStatePath())
	assert.Empty(t, st.Pending)
	assert.Nil(t, st.Last)
}

func TestSyncFlagsUsesCachedUUID(t *testing.T) {
	fs, _ := setupGuard(t, testOverrideFlags, nil)
	cached := "11111111-2222-3333-4444-555555555555"
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{HostUUID: cached}))
	hostUUIDReader = func() (string, error) { return "", errors.New("osqueryd busy") }

	_, attempted, uuid, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.Equal(t, cached, uuid)
	assert.Equal(t, testOverrideFlags, attempted, "no flap back to environment flags")
	reqs := fs.recorded()
	require.Len(t, reqs, 1)
	assert.Equal(t, cached, reqs[0].UUID)
	assert.Equal(t, cached, loadFlagsState(flagsStatePath()).HostUUID)
}

func TestSyncFlagsCachesUUID(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{HostUUID: "11111111-2222-3333-4444-555555555555"}))
	// Unchanged flags still refresh the cache
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	changed, _, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, testHostUUID, loadFlagsState(flagsStatePath()).HostUUID)
}

// The reported text names the configured timeout, and keeps its wording for the default.
func TestRejectedErrorNamesTimeout(t *testing.T) {
	prev := restartCheckTimeout
	t.Cleanup(func() { restartCheckTimeout = prev })

	restartCheckTimeout = 60 * time.Second
	assert.Equal(t, "osqueryd was not running 60s after restart", rejectedError())
	restartCheckTimeout = 90 * time.Second
	assert.Equal(t, "osqueryd was not running 90s after restart", rejectedError())
}

func rejectedErrorFor(d time.Duration) string {
	return fmt.Sprintf("osqueryd was not running %gs after restart", d.Seconds())
}

const testLastGoodFlags = "--tls_hostname=osctrl.example.com\n--verbose=false"

var eventIDRe = regexp.MustCompile(`^[0-9]+:[0-9a-f]{64}$`)

// runningWith reports osqueryd running only while the flagfile holds content
func runningWith(content string) func() (bool, error) {
	return func() (bool, error) {
		b, _ := os.ReadFile(appConfig.OsqueryFlagFile)
		return string(b) == content, nil
	}
}

// withLastGood stores content as the last known good flags and returns the state pointing at it
func withLastGood(t *testing.T, content string) flagsState {
	t.Helper()
	require.NoError(t, saveLastGood(content))
	return flagsState{LastGoodSHA256: sha256Hex(content)}
}

func TestVerifyFlagsRollsBackToEnvironmentThenLastGood(t *testing.T) {
	_, recorded := setupGuard(t, testOverrideFlags, runningWith(testLastGoodFlags))
	require.NoError(t, saveFlagsState(flagsStatePath(), withLastGood(t, testLastGoodFlags)))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))

	assert.Equal(t, testLastGoodFlags, readFlagFile(t))
	assert.Len(t, *recorded, 2, "restart to environment flags, then to last good")
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageLastKnownGood, st.Stage)
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)
	assert.Equal(t, sha256Hex(testEnvFlags), st.RejectedEnvSHA256)
	assert.Regexp(t, eventIDRe, st.EventID)
	assert.Contains(t, st.EventID, ":"+sha256Hex(testOverrideFlags))
	assert.Empty(t, st.Pending)
	require.NotNil(t, st.Last)
	assert.Equal(t, applyRejected, st.Last.Result)
	assert.Equal(t, sha256Hex(testOverrideFlags), st.Last.SHA256)
}

func TestVerifyFlagsExhaustedStopsWithoutLoop(t *testing.T) {
	_, recorded := setupGuard(t, testOverrideFlags, neverRunning)
	require.NoError(t, saveFlagsState(flagsStatePath(), withLastGood(t, testLastGoodFlags)))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))
	assert.Len(t, *recorded, 2, "one restart per candidate")
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageExhausted, st.Stage)
	assert.Regexp(t, eventIDRe, st.EventID)
	assert.Empty(t, st.Pending)

	*recorded = nil
	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))
	assert.Empty(t, *recorded, "every candidate already failed")
	assert.Equal(t, stageExhausted, loadFlagsState(flagsStatePath()).Stage)

	// Nothing changed for osctrld, so nothing is written and nothing restarts
	changed, _, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestVerifyFlagsEnvironmentFlagsFallBackToLastGood(t *testing.T) {
	_, recorded := setupGuard(t, testEnvFlags, runningWith(testLastGoodFlags))
	require.NoError(t, saveFlagsState(flagsStatePath(), withLastGood(t, testLastGoodFlags)))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testEnvFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testEnvFlags, testHostUUID))

	assert.Equal(t, testLastGoodFlags, readFlagFile(t))
	assert.Len(t, *recorded, 1)
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageLastKnownGood, st.Stage)
	assert.Equal(t, sha256Hex(testEnvFlags), st.RejectedEnvSHA256)
	assert.Empty(t, st.RejectedSHA256)
	assert.Regexp(t, eventIDRe, st.EventID)
}

func TestVerifyFlagsNoLastGoodStopsAtEnvironment(t *testing.T) {
	_, recorded := setupGuard(t, testOverrideFlags, neverRunning)
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))

	assert.Len(t, *recorded, 1)
	assert.Equal(t, testEnvFlags, readFlagFile(t))
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageExhausted, st.Stage)
	assert.Equal(t, sha256Hex(testEnvFlags), st.RejectedEnvSHA256)
	assert.Regexp(t, eventIDRe, st.EventID)
}

func TestVerifyFlagsEnvironmentRunsAndBecomesLastGood(t *testing.T) {
	_, recorded := setupGuard(t, testOverrideFlags, runningWith(testEnvFlags))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))

	assert.Len(t, *recorded, 1)
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageEnvironment, st.Stage)
	assert.Empty(t, st.RejectedEnvSHA256)
	got, ok := loadLastGood(st)
	assert.True(t, ok)
	assert.Equal(t, testEnvFlags, got)
}

func TestVerifyFlagsOKRecordsLastGood(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{Stage: stageExhausted, EventID: newEventID("x", time.Now())}))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))

	b, err := os.ReadFile(lastGoodPath())
	require.NoError(t, err)
	assert.Equal(t, testOverrideFlags, string(b))
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, sha256Hex(testOverrideFlags), st.LastGoodSHA256)
	assert.Equal(t, stageNone, st.Stage)
	assert.Empty(t, st.EventID)
	if runtime.GOOS != WindowsOS {
		info, err := os.Stat(lastGoodPath())
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestLastGoodWithWrongHashIsIgnored(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)
	_, ok := loadLastGood(flagsState{LastGoodSHA256: sha256Hex(testLastGoodFlags)})
	assert.False(t, ok, "missing file")

	st := withLastGood(t, testLastGoodFlags)
	got, ok := loadLastGood(st)
	assert.True(t, ok)
	assert.Equal(t, testLastGoodFlags, got)

	require.NoError(t, os.WriteFile(lastGoodPath(), []byte("--tampered=1"), 0600))
	_, ok = loadLastGood(st)
	assert.False(t, ok)
}

func TestSaveLastGoodFailedWriteKeepsPrevious(t *testing.T) {
	if runtime.GOOS == WindowsOS || os.Geteuid() == 0 {
		t.Skip("needs unix modes enforced for a non-root user")
	}
	setupGuard(t, testOverrideFlags, nil)
	require.NoError(t, saveLastGood(testLastGoodFlags))
	dir := filepath.Dir(lastGoodPath())
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	assert.Error(t, saveLastGood(testOverrideFlags))
	b, err := os.ReadFile(lastGoodPath())
	require.NoError(t, err)
	assert.Equal(t, testLastGoodFlags, string(b))
}

func TestSyncFlagsServesLastGoodWhileEnvironmentRejected(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)
	st := withLastGood(t, testLastGoodFlags)
	st.RejectedSHA256 = sha256Hex(testOverrideFlags)
	st.RejectedEnvSHA256 = sha256Hex(testEnvFlags)
	require.NoError(t, saveFlagsState(flagsStatePath(), st))

	changed, attempted, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, testLastGoodFlags, attempted)
	assert.Equal(t, testLastGoodFlags, readFlagFile(t))

	changed, _, _, err = syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestSyncFlagsAppliesFixedFlagsWhileExhausted(t *testing.T) {
	fixed := "--tls_hostname=osctrl.example.com\n--host_identifier=uuid"
	setupGuard(t, fixed, nil)
	st := withLastGood(t, testLastGoodFlags)
	st.RejectedSHA256 = sha256Hex(testOverrideFlags)
	st.RejectedEnvSHA256 = sha256Hex(testEnvFlags)
	st.Stage = stageExhausted
	st.EventID = newEventID(testOverrideFlags, time.Now())
	require.NoError(t, saveFlagsState(flagsStatePath(), st))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testLastGoodFlags), 0700))

	changed, attempted, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, fixed, attempted)
	assert.Equal(t, fixed, readFlagFile(t))
	assert.Equal(t, sha256Hex(fixed), loadFlagsState(flagsStatePath()).Pending)

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), attempted, testHostUUID))
	got := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageNone, got.Stage)
	require.NotNil(t, got.Last)
	assert.Equal(t, applyOK, got.Last.Result)
	assert.Equal(t, sha256Hex(fixed), got.LastGoodSHA256)
}

// interruptedChain is the state left when osctrld stopped while checking the
// environment flags a rollback of testOverrideFlags fell back to
func interruptedChain(t *testing.T) flagsState {
	t.Helper()
	st := withLastGood(t, testLastGoodFlags)
	st.RejectedSHA256 = sha256Hex(testOverrideFlags)
	st.Last = &ApplyStatus{Result: applyRejected, SHA256: sha256Hex(testOverrideFlags), At: time.Now().UTC()}
	st.EventID = newEventID(testOverrideFlags, time.Unix(1760000000, 0))
	st.Pending = sha256Hex(testEnvFlags)
	st.PendingStage = stageEnvironment
	require.NoError(t, saveFlagsState(flagsStatePath(), st))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testEnvFlags), 0700))
	return st
}

func TestResumeFlagsCheckContinuesChain(t *testing.T) {
	tests := []struct {
		name      string
		running   func() (bool, error)
		restarts  int
		stage     string
		flagfile  string
		rejectEnv bool
	}{
		{"fallback runs", runningWith(testEnvFlags), 0, stageEnvironment, testEnvFlags, false},
		{"fallback fails, last good runs", runningWith(testLastGoodFlags), 1, stageLastKnownGood, testLastGoodFlags, true},
		{"nothing runs", neverRunning, 1, stageExhausted, testLastGoodFlags, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, recorded := setupGuard(t, testOverrideFlags, tt.running)
			before := interruptedChain(t)

			require.NoError(t, resumeFlagsCheck(context.Background()))

			assert.Len(t, *recorded, tt.restarts)
			assert.Equal(t, tt.flagfile, readFlagFile(t))
			st := loadFlagsState(flagsStatePath())
			assert.Equal(t, tt.stage, st.Stage)
			assert.Equal(t, before.EventID, st.EventID, "one event per chain")
			assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)
			if tt.rejectEnv {
				assert.Equal(t, sha256Hex(testEnvFlags), st.RejectedEnvSHA256)
			} else {
				assert.Empty(t, st.RejectedEnvSHA256)
			}
			assert.Empty(t, st.Pending)
			assert.Empty(t, st.PendingStage)
			require.NotNil(t, st.Last)
			assert.Equal(t, applyRejected, st.Last.Result, "the override rejection stays reported")
			assert.Equal(t, sha256Hex(testOverrideFlags), st.Last.SHA256)
		})
	}
}

// A new override failing after an exhausted chain has nothing left to try:
// already failed content is never restarted, and its rejection stays reported
func TestVerifyFlagsNewOverrideAfterExhausted(t *testing.T) {
	fs, recorded := setupGuard(t, testOverrideFlags, neverRunning)
	require.NoError(t, saveFlagsState(flagsStatePath(), withLastGood(t, testLastGoodFlags)))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))
	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))
	require.Equal(t, stageExhausted, loadFlagsState(flagsStatePath()).Stage)

	o2 := "--tls_hostname=osctrl.example.com\n--bad_flag=2"
	fs.mu.Lock()
	fs.override = o2
	fs.mu.Unlock()
	changed, attempted, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, o2, attempted)
	assert.Empty(t, loadFlagsState(flagsStatePath()).PendingStage)

	*recorded = nil
	require.NoError(t, verifyFlagsAfterRestart(context.Background(), o2, testHostUUID))
	assert.Empty(t, *recorded, "every fallback already failed")
	assert.Equal(t, testLastGoodFlags, readFlagFile(t), "settled on what the next sync serves")
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageExhausted, st.Stage)
	assert.Equal(t, sha256Hex(o2), st.RejectedSHA256)
	assert.Contains(t, st.EventID, ":"+sha256Hex(o2))
	require.NotNil(t, st.Last)
	assert.Equal(t, sha256Hex(o2), st.Last.SHA256)

	changed, _, _, err = syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed, "no restart with content that already failed")
}

func TestNewEventID(t *testing.T) {
	at := time.Unix(1760000000, 0)
	assert.Equal(t, "1760000000000000000:"+sha256Hex("x"), newEventID("x", at))
}

func TestProtectedFilesIncludeLastGood(t *testing.T) {
	setupGuard(t, testOverrideFlags, nil)
	assert.Contains(t, protectedFiles(), lastGoodPath())
}

// An override that ran before (so it is the last known good) and now fails is
// never restarted again, neither as the override nor as the last known good
func TestVerifyFlagsFailedLastGoodOverrideIsNotRetried(t *testing.T) {
	_, recorded := setupGuard(t, testOverrideFlags, neverRunning)
	require.NoError(t, saveFlagsState(flagsStatePath(), withLastGood(t, testOverrideFlags)))
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags), 0700))

	require.NoError(t, verifyFlagsAfterRestart(context.Background(), testOverrideFlags, testHostUUID))
	assert.Len(t, *recorded, 1, "only the environment flags are tried")
	st := loadFlagsState(flagsStatePath())
	assert.Equal(t, stageExhausted, st.Stage)
	assert.Equal(t, sha256Hex(testOverrideFlags), st.RejectedSHA256)

	changed, attempted, _, err := syncFlags(context.Background())
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, testEnvFlags, attempted)
}
