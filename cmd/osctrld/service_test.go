package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntervalWithJitter(t *testing.T) {
	base := 60 * time.Minute
	min := 54 * time.Minute // base - 10%
	max := 66 * time.Minute // base + 10%

	for i := 0; i < 100; i++ {
		result := intervalWithJitter(base)
		assert.GreaterOrEqual(t, result, min, "jitter should not go below -10%%")
		assert.LessOrEqual(t, result, max, "jitter should not go above +10%%")
	}
}

func TestIntervalWithJitter_SmallInterval(t *testing.T) {
	base := 1 * time.Minute
	min := 54 * time.Second // 1min - 10%
	max := 66 * time.Second // 1min + 10%

	for i := 0; i < 100; i++ {
		result := intervalWithJitter(base)
		assert.GreaterOrEqual(t, result, min)
		assert.LessOrEqual(t, result, max)
	}
}

func TestServiceCommandRegistered(t *testing.T) {
	app := buildApp()
	found := false
	for _, cmd := range app.Commands {
		if cmd.Name == "service" {
			found = true
			assert.Equal(t, "Run as a daemon, periodically syncing flags and certificate", cmd.Usage)
			break
		}
	}
	assert.True(t, found, "service command should be registered")
}

// syncUpgradeEnv runs syncOnce against the upgrade harness: its osctrl answers
// the upgrade route with h.res() and has no flags, cert or extensions routes
func syncUpgradeEnv(t *testing.T) (*upgradeHarness, *statusSink) {
	t.Helper()
	h := setupUpgrade(t)
	h.resolve = func(upgradeRequest) upgradeResolution { return h.res() }
	prevUUID := hostUUIDReader
	hostUUIDReader = func() (string, error) { return testHostUUID, nil }
	t.Cleanup(func() { hostUUIDReader = prevUUID })
	fakeLookPath(t, "launchctl", "systemctl")
	sink := withStatusSink(t, http.StatusOK)
	// The watcher has seen osqueryd once: known running
	health.observe(true, time.Now())
	return h, sink
}

// withFlags serves flags as both the environment and the override flags
func withFlags(t *testing.T, flags string) *flagsServer {
	t.Helper()
	fs := &flagsServer{override: flags, env: flags}
	srv := httptest.NewServer(fs)
	t.Cleanup(srv.Close)
	osctrlURLs.Flags = srv.URL
	return fs
}

func (h *upgradeHarness) hits() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.routeHits
}

func (h *upgradeHarness) count(event string) int {
	n := 0
	for _, e := range h.recorded() {
		if e == event {
			n++
		}
	}
	return n
}

func onlyReport(t *testing.T, sink *statusSink) statusReport {
	t.Helper()
	reps := sink.recorded()
	require.Len(t, reps, 1)
	return reps[0]
}

func TestSyncUpgradesAtEndWhenHealthy(t *testing.T) {
	h, sink := syncUpgradeEnv(t)
	syncOnce(context.Background(), newTestCLICommand())

	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start"}, h.recorded())
	last := h.state().Last
	require.NotNil(t, last)
	assert.Equal(t, "ok", last.Result)
	rep := onlyReport(t, sink)
	assert.True(t, rep.OsqueryRunning)
	assert.Equal(t, &upgradeReport{Result: "ok", Version: upTarget, RequestID: upReq1}, rep.Upgrade, "reported in the same sync")
}

func TestSyncUpgradesWindowsWithTargetOnly(t *testing.T) {
	h, sink := syncUpgradeEnv(t)
	h.windows()
	var reqs []upgradeRequest
	h.resolve = func(r upgradeRequest) upgradeResolution { reqs = append(reqs, r); return h.winRes() }
	syncOnce(context.Background(), newTestCLICommand())

	require.NotEmpty(t, reqs)
	assert.Equal(t, upgradeRequest{Secret: "S", UUID: "U", Platform: "windows", Arch: "amd64", Format: "msi", InstalledVersion: upPrevious}, reqs[0])
	assert.Equal(t, 1, h.count("install:"+upTarget))
	require.NotNil(t, h.state().Last)
	assert.Equal(t, "ok", h.state().Last.Result)
	assert.Equal(t, &upgradeReport{Result: "ok", Version: upTarget, RequestID: upReq1}, onlyReport(t, sink).Upgrade)
}

func TestSyncSkipsUpgradeWhenOsquerydDownOrStateUnknown(t *testing.T) {
	t.Run("down", func(t *testing.T) {
		h, sink := syncUpgradeEnv(t)
		h.running = false
		now := time.Now()
		health = &healthWatcher{}
		health.observe(false, now)
		health.observe(false, now)
		syncOnce(context.Background(), newTestCLICommand())

		assert.Zero(t, h.hits())
		assert.Empty(t, h.recorded(), "osqueryd neither installed nor started")
		rep := onlyReport(t, sink)
		assert.False(t, rep.OsqueryRunning)
		assert.Equal(t, &upgradeReport{Result: "skipped", Reason: "osqueryd_not_running"}, rep.Upgrade)
	})
	t.Run("unknown", func(t *testing.T) {
		h, sink := syncUpgradeEnv(t)
		health = &healthWatcher{}
		osquerydRunning = func() (bool, error) { return false, errors.New("no process table") }
		syncOnce(context.Background(), newTestCLICommand())

		assert.Zero(t, h.hits())
		assert.Empty(t, h.recorded())
		assert.Equal(t, upgradeState{}, h.state(), "an unknown state decides nothing: the next sync does")
		assert.Empty(t, sink.recorded(), "an unknown state is not reported")
	})
}

func TestSyncUnknownHealthFirstSyncSendsNoDownReport(t *testing.T) {
	h, sink := syncUpgradeEnv(t)
	health = &healthWatcher{} // fresh start, no watcher tick yet
	h.running = false
	syncOnce(context.Background(), newTestCLICommand())

	assert.Zero(t, h.hits(), "no upgrade route call")
	for _, r := range sink.recorded() {
		assert.True(t, r.OsqueryRunning, "one miss at start is no down report")
	}
	assert.False(t, health.known, "still unknown after a single miss")
	assert.Equal(t, upgradeState{}, h.state())
}

func TestUpgradeStepDoesNotFeedHealth(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		setup func(h *upgradeHarness)
	}{
		{"unknown", func(*upgradeHarness) { health = &healthWatcher{} }},
		{"unknown one miss", func(*upgradeHarness) { health = &healthWatcher{}; health.observe(false, now) }},
		{"known down", func(*upgradeHarness) { health.settle(false, now) }},
		{"fresh check not running", func(h *upgradeHarness) { h.running = false }},
		{"fresh check fails", func(*upgradeHarness) {
			osquerydRunning = func() (bool, error) { return false, errors.New("no process table") }
		}},
		{"fresh check running", func(*upgradeHarness) {}},
		{"windows", func(h *upgradeHarness) {
			h.windows()
			h.resolve = func(upgradeRequest) upgradeResolution { return h.winRes() }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := syncUpgradeEnv(t)
			tc.setup(h)
			before := *health
			upgradeStep(context.Background(), false)
			assert.Equal(t, before, *health)
		})
	}
}

func TestUpgradeStepStaleRunningFreshNotRunningSkips(t *testing.T) {
	h, _ := syncUpgradeEnv(t)
	require.True(t, health.known && health.running)
	h.running = false // crashed since the watcher last looked
	upgradeStep(context.Background(), false)

	assert.Zero(t, h.hits(), "no route call")
	assert.Empty(t, h.recorded(), "no engine, no start or restart")
	last := h.state().Last
	require.NotNil(t, last)
	assert.Equal(t, upgradeResult{Result: "skipped", Reason: "osqueryd_not_running", At: last.At}, *last)

	osquerydRunning = func() (bool, error) { return false, errors.New("no process table") }
	require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{}))
	upgradeStep(context.Background(), false)
	assert.Zero(t, h.hits())
	assert.Equal(t, upgradeState{}, h.state(), "a failed check records nothing")
}

func TestUpgradeStepFreshRunningProceeds(t *testing.T) {
	h, _ := syncUpgradeEnv(t)
	upgradeStep(context.Background(), false)
	assert.Equal(t, 1, h.count("install:"+upTarget))
	require.NotNil(t, h.state().Last)
	assert.Equal(t, "ok", h.state().Last.Result)
}

func TestSyncCancelledDuringResumeSkipsFlags(t *testing.T) {
	h, sink := syncUpgradeEnv(t)
	pendingBeforeInstall(t, h)
	h.running = false // forgetting the upgrade starts osqueryd and waits for it
	h.runsAfter = func(string) bool { return false }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := upgradeStartOsquery
	upgradeStartOsquery = func() error { cancel(); return start() }
	fs := withFlags(t, testEnvFlags+"\n--fixed=1")

	syncOnce(ctx, newTestCLICommand())
	assert.Empty(t, fs.recorded(), "flags not synced after a cancelled resume")
	assert.Empty(t, sink.recorded())
	assert.NotNil(t, h.state().Pending, "the next start resumes it")
}

func TestUpgradeStepSkipMemoryRecordsWithoutRewrite(t *testing.T) {
	h, _ := syncUpgradeEnv(t)
	res := h.res()
	require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Skipped: &skippedUpgrade{
		Version: upTarget, SHA256: res.Target.SHA256, RequestID: upReq1, Reason: "target_unavailable", At: time.Now().Add(-time.Hour)}}))

	upgradeStep(context.Background(), false)
	last := h.state().Last
	require.NotNil(t, last, "the remembered skip is saved as Last")
	assert.Equal(t, upgradeResult{Result: "skipped", Version: upTarget, Reason: "target_unavailable", RequestID: upReq1, At: last.At}, *last)
	assert.Zero(t, h.pkgHits, "nothing downloaded again")

	before, err := os.ReadFile(upgradeStatePath())
	require.NoError(t, err)
	info, err := os.Stat(upgradeStatePath())
	require.NoError(t, err)
	upgradeStep(context.Background(), false)
	after, err := os.ReadFile(upgradeStatePath())
	require.NoError(t, err)
	info2, err := os.Stat(upgradeStatePath())
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after))
	assert.Equal(t, info.ModTime(), info2.ModTime(), "the state file is not rewritten")
	assert.Empty(t, h.recorded())
}

func TestUpgradeStepUnknownServerReasonLoggedOnce(t *testing.T) {
	h, _ := syncUpgradeEnv(t)
	h.resolve = func(upgradeRequest) upgradeResolution { return upgradeResolution{Reason: "something_new"} }
	logs := captureLogs(t)
	for i := 0; i < 3; i++ {
		upgradeStep(context.Background(), false)
	}
	out := logs.String()
	assert.Equal(t, 1, strings.Count(out, "something_new"), "logged once per process")
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "something_new") {
			assert.Contains(t, line, `"level":"debug"`)
		}
	}
	assert.Nil(t, h.state().Last)
}

func TestSyncSkipsUpgradeWhenFlagsCertOrExtensionsChanged(t *testing.T) {
	h, _ := syncUpgradeEnv(t)
	upgradeStep(context.Background(), true)
	assert.Zero(t, h.hits(), "no call to the upgrade route")
	assert.Equal(t, upgradeState{}, h.state())

	withFlags(t, testEnvFlags+"\n--new=1")
	syncOnce(context.Background(), newTestCLICommand())
	assert.Zero(t, h.hits())
	assert.Zero(t, h.count("install:"+upTarget))
	assert.Nil(t, h.state().Last)
}

func TestSyncAppliesFlagsFixThenUpgradeLater(t *testing.T) {
	const fixed = testEnvFlags + "\n--fixed=1"
	h, _ := syncUpgradeEnv(t)
	withFlags(t, fixed)

	syncOnce(context.Background(), newTestCLICommand())
	assert.Zero(t, h.count("install:"+upTarget), "the flags fix sync does not upgrade")
	assert.Equal(t, fixed, readFlagFile(t))

	syncOnce(context.Background(), newTestCLICommand())
	assert.Equal(t, 1, h.count("install:"+upTarget), "the next sync upgrades")
	require.NotNil(t, h.state().Last)
	assert.Equal(t, "ok", h.state().Last.Result)
	assert.Equal(t, fixed, readFlagFile(t), "the fixed flags survive the upgrade")
}

func TestSyncOneUpgradeAttemptPerSync(t *testing.T) {
	h, sink := syncUpgradeEnv(t)
	h.reported = func(string) string { return upPrevious }
	syncOnce(context.Background(), newTestCLICommand())

	assert.Equal(t, 1, h.count("install:"+upTarget))
	assert.Equal(t, 1, h.count("downgrade:"+upPrevious))
	st := h.state()
	require.NotNil(t, st.Last)
	assert.Equal(t, "rejected", st.Last.Result)
	rep := onlyReport(t, sink)
	require.NotNil(t, rep.Upgrade)
	assert.Equal(t, st.Last.EventID, rep.Upgrade.EventID, "the rollback is reported in the same sync")
	assert.Equal(t, st.Last.EventID, st.ReportedEventID)

	syncOnce(context.Background(), newTestCLICommand())
	assert.Equal(t, 1, h.count("install:"+upTarget), "a rejected target is not retried")
	assert.Equal(t, "rejected", h.state().Last.Result)
}

func TestSyncUpgradeIgnoresLowerOrEqualTarget(t *testing.T) {
	h, sink := syncUpgradeEnv(t)
	h.resolve = nil // ahead_of_target
	logs := captureLogs(t)
	syncOnce(context.Background(), newTestCLICommand())

	assert.Empty(t, h.recorded())
	assert.Equal(t, &upgradeReport{Result: "skipped", Reason: "ahead_of_target"}, onlyReport(t, sink).Upgrade)
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "ahead_of_target") || strings.Contains(line, "upgrade") {
			assert.NotContains(t, line, `"level":"warn"`, line)
			assert.NotContains(t, line, `"level":"error"`, line)
		}
	}
}

func TestSyncUpgradeOldOsctrlIsQuiet(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			h, _ := syncUpgradeEnv(t)
			old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
			t.Cleanup(old.Close)
			osctrlURLs.Osquery = old.URL
			logs := captureLogs(t)
			for i := 0; i < 3; i++ {
				syncOnce(context.Background(), newTestCLICommand())
			}
			out := logs.String()
			assert.Equal(t, 1, strings.Count(out, errUpgradeUnsupported.Error()), "logged once per process")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "upgrade") {
					assert.Contains(t, line, `"level":"debug"`, line)
				}
			}
			assert.Equal(t, upgradeState{}, h.state())
		})
	}
}

func TestSyncUpgradeInvalidResolutionNeverReported(t *testing.T) {
	h, sink := syncUpgradeEnv(t)
	h.resolve = func(upgradeRequest) upgradeResolution {
		res := h.res()
		res.Target.SHA256 = "not-a-digest"
		return res
	}
	syncOnce(context.Background(), newTestCLICommand())

	assert.Equal(t, 1, h.hits())
	assert.Empty(t, h.recorded())
	assert.Nil(t, h.state().Last)
	assert.Nil(t, onlyReport(t, sink).Upgrade)
}

func TestResumeUpgradeRunsBeforeFlagsSync(t *testing.T) {
	const fixed = testEnvFlags + "\n--fixed=1"
	h, _ := syncUpgradeEnv(t)
	pendingBeforeInstall(t, h) // its snapshot holds the old flagfile
	withFlags(t, fixed)

	syncOnce(context.Background(), newTestCLICommand())
	assert.Nil(t, h.state().Pending, "the pending upgrade was resumed")
	assert.Equal(t, fixed, readFlagFile(t), "the snapshot was restored before the flags sync, not over it")
	assert.Zero(t, h.count("install:"+upTarget))
}

func TestUpgradeSkipNeverReplacesUnreportedRejection(t *testing.T) {
	rejected := upgradeResult{Result: "rejected", Version: upTarget, Reason: "version_not_reported", RequestID: upReq1, EventID: testEventID, At: time.Now().UTC()}

	t.Run("osqueryd down", func(t *testing.T) {
		h, sink := syncUpgradeEnv(t)
		require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Last: &rejected}))
		h.running = false
		health.settle(false, time.Now())

		upgradeStep(context.Background(), false)
		assert.Equal(t, "rejected", h.state().Last.Result, "kept until reported")

		sink.mu.Lock()
		sink.code = http.StatusInternalServerError
		sink.mu.Unlock()
		reportStatus(time.Now())
		assert.Empty(t, h.state().ReportedEventID, "a failed report does not count")
		upgradeStep(context.Background(), false)
		assert.Equal(t, "rejected", h.state().Last.Result)

		sink.mu.Lock()
		sink.code = http.StatusOK
		sink.mu.Unlock()
		reportStatus(time.Now())
		assert.Equal(t, testEventID, h.state().ReportedEventID)
		reps := sink.recorded()
		require.Len(t, reps, 2)
		require.NotNil(t, reps[1].Upgrade)
		assert.Equal(t, testEventID, reps[1].Upgrade.EventID)

		upgradeStep(context.Background(), false)
		last := h.state().Last
		assert.Equal(t, "skipped", last.Result, "replaced once reported")
		assert.Equal(t, "osqueryd_not_running", last.Reason)
	})
	t.Run("engine skip", func(t *testing.T) {
		h, _ := syncUpgradeEnv(t)
		require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Last: &rejected,
			Rejected: &rejectedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq1}}))
		h.resolve = func(upgradeRequest) upgradeResolution {
			res := h.res()
			res.RequestID = upReq2
			return res
		}
		delete(h.pkgs, upTarget)

		upgradeStep(context.Background(), false)
		assert.Empty(t, h.recorded(), "target unavailable, nothing installed")
		assert.Equal(t, rejected.EventID, h.state().Last.EventID, "the unreported rollback is kept")
	})
}

func TestUpgradeRejectionComesBackAfterDownSync(t *testing.T) {
	rejected := upgradeResult{Result: "rejected", Version: upTarget, Reason: "version_not_reported", RequestID: upReq1, EventID: testEventID, At: time.Now().UTC()}
	downThenUp := func(t *testing.T, h *upgradeHarness) {
		t.Helper()
		h.running = false
		health.settle(false, time.Now())
		upgradeStep(context.Background(), false)
		last := h.state().Last
		require.NotNil(t, last)
		require.Equal(t, "osqueryd_not_running", last.Reason, "the reported rejection may be replaced while down")
		h.running = true
		health.settle(true, time.Now())
		upgradeStep(context.Background(), false)
	}
	t.Run("restored once osqueryd is back", func(t *testing.T) {
		h, sink := syncUpgradeEnv(t)
		r := rejected
		require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Last: &rejected, ReportedEventID: testEventID,
			Rejected: &rejectedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq1, Result: &r}}))
		downThenUp(t, h)
		st := h.state()
		require.NotNil(t, st.Last)
		assert.Equal(t, rejected.EventID, st.Last.EventID)
		assert.Equal(t, "rejected", st.Last.Result)
		assert.Equal(t, "version_not_reported", st.Last.Reason)
		assert.Empty(t, h.recorded(), "the rejected target is not retried")
		reportStatus(time.Now())
		reps := sink.recorded()
		require.Len(t, reps, 1)
		require.NotNil(t, reps[0].Upgrade)
		assert.Equal(t, testEventID, reps[0].Upgrade.EventID, "the report carries the rollback's event id")
		assert.Equal(t, testEventID, h.state().ReportedEventID)
	})
	t.Run("old state without the stored result behaves as before", func(t *testing.T) {
		h, _ := syncUpgradeEnv(t)
		old := `{"last":{"result":"rejected","version":"` + upTarget + `","reason":"version_not_reported","request_id":"` + upReq1 + `","event_id":"` + testEventID + `"},` +
			`"rejected":{"version":"` + upTarget + `","sha256":"` + h.res().Target.SHA256 + `","request_id":"` + upReq1 + `"},"reported_event_id":"` + testEventID + `"}`
		require.NoError(t, os.WriteFile(upgradeStatePath(), []byte(old), 0600))
		st := h.state()
		require.NotNil(t, st.Rejected)
		assert.Nil(t, st.Rejected.Result)
		downThenUp(t, h)
		assert.Equal(t, "osqueryd_not_running", h.state().Last.Reason)
		assert.Empty(t, h.recorded())
	})
}

func TestServiceStartSweepsStaleDownloads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows test runner's temp files are not owned by Administrators or SYSTEM, nothing is swept")
	}
	h := setupUpgrade(t)
	stale := plantStaleDownload(t, h.tmp)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, serviceNode(ctx, newTestCLICommand()))
	assert.NoFileExists(t, stale)
	assert.Empty(t, h.recorded())
}

func rolloutRes(reason string) func(upgradeRequest) upgradeResolution {
	return func(upgradeRequest) upgradeResolution {
		return upgradeResolution{Reason: reason, Source: "environment", RequestID: upReq1}
	}
}

func testUpgradeStepRecordsRollout(t *testing.T, reason string) {
	h, _ := syncUpgradeEnv(t)
	h.resolve = rolloutRes(reason)
	logs := captureLogs(t)
	upgradeStep(context.Background(), false)
	last := h.state().Last
	require.NotNil(t, last)
	assert.Equal(t, upgradeResult{Result: "skipped", Reason: reason, RequestID: upReq1, At: last.At}, *last)
	assert.Zero(t, h.count("install:"+upTarget), "no install")
	assert.Zero(t, h.pkgHits, "no package download")
	assert.NotContains(t, logs.String(), `"level":"warn"`)
	assert.NotContains(t, logs.String(), `"level":"error"`)

	info, err := os.Stat(upgradeStatePath())
	require.NoError(t, err)
	upgradeStep(context.Background(), false)
	info2, err := os.Stat(upgradeStatePath())
	require.NoError(t, err)
	assert.Equal(t, info.ModTime(), info2.ModTime(), "state file not rewritten on a repeat")
}

func TestUpgradeStepRecordsRolloutPending(t *testing.T) {
	testUpgradeStepRecordsRollout(t, "rollout_pending")
}

func TestUpgradeStepRecordsRolloutPaused(t *testing.T) {
	testUpgradeStepRecordsRollout(t, "rollout_paused")
}

func TestUpgradeStepRolloutReasonNeverReplacesUnreportedRejection(t *testing.T) {
	rejected := upgradeResult{Result: "rejected", Version: upTarget, Reason: "version_not_reported", RequestID: upReq1, EventID: testEventID, At: time.Now().UTC()}
	for _, reason := range []string{"rollout_pending", "rollout_paused"} {
		h, _ := syncUpgradeEnv(t)
		h.resolve = rolloutRes(reason)
		require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Last: &rejected}))
		upgradeStep(context.Background(), false)
		assert.Equal(t, "rejected", h.state().Last.Result, reason)
	}
}

func TestUpgradeStepUnknownReasonStillIgnored(t *testing.T) {
	h, _ := syncUpgradeEnv(t)
	h.resolve = rolloutRes("rollout_made_up")
	logs := captureLogs(t)
	for i := 0; i < 2; i++ {
		upgradeStep(context.Background(), false)
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "rollout_made_up"))
	assert.Nil(t, h.state().Last)
}

func TestUpgradeStepRolloutKeepsMatchingRollback(t *testing.T) {
	const otherReq = "fedcba9876543210fedcba9876543210"
	for _, reason := range []string{"rollout_pending", "rollout_paused"} {
		rolled := upgradeResult{Result: "rejected", Version: upTarget, Reason: "version_not_reported", RequestID: upReq1, EventID: testEventID, At: time.Now().UTC()}
		skip := upgradeResult{Result: "skipped", Reason: reason, RequestID: upReq1}
		seed := func(h *upgradeHarness) {
			require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Last: &skip,
				Rejected: &rejectedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq1, Result: &rolled}, ReportedEventID: testEventID}))
		}

		// Same request id: the rollback is restored over the skip, then left alone
		h, _ := syncUpgradeEnv(t)
		h.resolve = rolloutRes(reason)
		seed(h)
		upgradeStep(context.Background(), false)
		require.NotNil(t, h.state().Last)
		assert.Equal(t, rolled.EventID, h.state().Last.EventID, reason)
		assert.Equal(t, "rejected", h.state().Last.Result, reason)
		info, err := os.Stat(upgradeStatePath())
		require.NoError(t, err)
		upgradeStep(context.Background(), false)
		info2, err := os.Stat(upgradeStatePath())
		require.NoError(t, err)
		assert.Equal(t, info.ModTime(), info2.ModTime(), "no rewrite")
		assert.Equal(t, testEventID, h.state().ReportedEventID)

		// Different request id: the skip is recorded as before
		h, _ = syncUpgradeEnv(t)
		h.resolve = func(upgradeRequest) upgradeResolution {
			return upgradeResolution{Reason: reason, Source: "environment", RequestID: otherReq}
		}
		seed(h)
		require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Last: &rolled,
			Rejected: &rejectedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq1, Result: &rolled}, ReportedEventID: testEventID}))
		upgradeStep(context.Background(), false)
		assert.Equal(t, "skipped", h.state().Last.Result, reason)
		assert.Equal(t, otherReq, h.state().Last.RequestID)
	}
}
