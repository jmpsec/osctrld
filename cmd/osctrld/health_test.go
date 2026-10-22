package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusSink is a fake osctrld-status route answering with code
type statusSink struct {
	mu      sync.Mutex
	code    int
	reports []statusReport
}

func (s *statusSink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var rep statusReport
	_ = json.NewDecoder(r.Body).Decode(&rep)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports = append(s.reports, rep)
	w.WriteHeader(s.code)
}

func (s *statusSink) recorded() []statusReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]statusReport(nil), s.reports...)
}

// withStatusSink points the status URL at a sink and resets the service's health state
func withStatusSink(t *testing.T, code int) *statusSink {
	t.Helper()
	sink := &statusSink{code: code}
	srv := httptest.NewServer(sink)
	t.Cleanup(srv.Close)
	osctrlURLs.Status = srv.URL
	resetHealth(t)
	return sink
}

func resetHealth(t *testing.T) {
	t.Helper()
	prevWatch, prevBeat, prevStable, prevUnit := watchInterval, heartbeatDown, stableUp, syncIntervalUnit
	reset := func() {
		health = &healthWatcher{}
		statusUnsupported, unsupportedLogged, lastStatusWarn = false, false, time.Time{}
	}
	reset()
	t.Cleanup(func() {
		reset()
		watchInterval, heartbeatDown, stableUp, syncIntervalUnit = prevWatch, prevBeat, prevStable, prevUnit
	})
}

func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(buf)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	t.Cleanup(func() { log.Logger = old; zerolog.SetGlobalLevel(oldLevel) })
	return buf
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestHealthWatcherDownNeedsTwoMisses(t *testing.T) {
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	w := &healthWatcher{}
	assert.False(t, w.observe(true, now), "first observation is the truth, not a change")
	running, _ := w.state()
	assert.True(t, running)

	assert.False(t, w.observe(false, now.Add(time.Minute)), "one miss is not down")
	running, _ = w.state()
	assert.True(t, running)

	assert.True(t, w.observe(false, now.Add(2*time.Minute)), "second consecutive miss is down")
	running, since := w.state()
	assert.False(t, running)
	assert.Equal(t, now.Add(time.Minute), since, "down since the first miss")

	// A miss, a hit, a miss: never two consecutive misses
	w = &healthWatcher{}
	w.observe(true, now)
	for i := 1; i <= 6; i++ {
		assert.False(t, w.observe(i%2 == 0, now.Add(time.Duration(i)*time.Minute)))
	}
	running, _ = w.state()
	assert.True(t, running)
}

func TestHealthWatcherUpNeedsConsecutiveHits(t *testing.T) {
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	w := &healthWatcher{}
	assert.False(t, w.observe(false, now), "first observation is the truth, not a change")
	_, since := w.state()
	assert.Equal(t, now, since)

	// A service manager respawning a crashing osqueryd: seen, gone, seen, gone
	for i := 1; i <= 9; i++ {
		seen := i%3 != 0 // two hits, then a miss
		assert.False(t, w.observe(seen, now.Add(time.Duration(i)*time.Minute)), "flapping must not flip state")
	}
	running, since := w.state()
	assert.False(t, running)
	assert.Equal(t, now, since, "flapping keeps the original down time")

	at := now.Add(20 * time.Minute)
	for i := 1; i < runningChecks; i++ {
		assert.False(t, w.observe(true, at))
	}
	assert.True(t, w.observe(true, at), "up after runningChecks consecutive hits")
	running, since = w.state()
	assert.True(t, running)
	assert.True(t, since.IsZero())
}

func TestHeartbeatDueWhileDownAndDuringStableWindow(t *testing.T) {
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	w := &healthWatcher{}
	assert.False(t, w.heartbeatDue(now), "nothing known, nothing to beat")

	w.observe(true, now)
	assert.False(t, w.heartbeatDue(now), "up from the start: reports ride the sync")

	w.observe(false, now)
	w.observe(false, now)
	assert.True(t, w.heartbeatDue(now), "down and never reported")
	w.markReported(now)
	assert.False(t, w.heartbeatDue(now.Add(heartbeatDown/2)))
	assert.True(t, w.heartbeatDue(now.Add(heartbeatDown*12/10)), "due every heartbeatDown, jitter at most 10%")

	up := now.Add(time.Hour)
	for i := 0; i < runningChecks; i++ {
		w.observe(true, up)
	}
	w.markReported(up)
	assert.True(t, w.heartbeatDue(up.Add(heartbeatDown*12/10)), "still beating inside the stable window")
	assert.False(t, w.heartbeatDue(up.Add(stableUp)), "up for stableUp: back to the sync cadence")
}

func TestStateChangeReportsImmediately(t *testing.T) {
	statusEnv(t)
	sink := withStatusSink(t, http.StatusOK)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{HostUUID: testHostUUID}))
	prev := osquerydRunning
	t.Cleanup(func() { osquerydRunning = prev })
	running := true
	osquerydRunning = func() (bool, error) { return running, nil }

	now := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	watchTick(now)
	assert.Empty(t, sink.recorded(), "first observation is not a change")

	running = false
	watchTick(now.Add(time.Minute))
	assert.Empty(t, sink.recorded(), "one miss is not down")
	watchTick(now.Add(2 * time.Minute))
	reps := sink.recorded()
	require.Len(t, reps, 1, "down reported on the tick that decides it")
	assert.False(t, reps[0].OsqueryRunning)
	require.NotNil(t, reps[0].DownSince)

	running = true
	for i := 1; i <= runningChecks; i++ {
		watchTick(now.Add(time.Duration(2+i) * time.Second))
	}
	reps = sink.recorded()
	require.Len(t, reps, 2, "up reported on the tick that decides it")
	assert.True(t, reps[1].OsqueryRunning)
	assert.Nil(t, reps[1].DownSince)
}

func TestSyncOnceReportsAtEnd(t *testing.T) {
	syncOnceGuard(t, nil)
	sink := withStatusSink(t, http.StatusOK)

	syncOnce(context.Background(), newTestCLICommand())

	reps := sink.recorded()
	require.Len(t, reps, 1)
	assert.Equal(t, testHostUUID, reps[0].UUID)
	assert.True(t, reps[0].OsqueryRunning)
	assert.Equal(t, "none", reps[0].Flags.Stage)
}

// runService runs serviceNode with short intervals until stop is called
func runService(t *testing.T) (stop func()) {
	t.Helper()
	watchInterval = 2 * time.Millisecond
	heartbeatDown = 10 * time.Millisecond
	syncIntervalUnit = 30 * time.Millisecond
	appConfig.Interval = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serviceNode(ctx, newTestCLICommand()) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("service loop did not stop")
		}
	}
	t.Cleanup(stop)
	return stop
}

func TestServiceLoopReportsWhileOsquerydDown(t *testing.T) {
	fs, recorded := setupGuard(t, testOverrideFlags, neverRunning)
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	osctrlURLs.Cert = notFound.URL
	osctrlURLs.Extensions = notFound.URL
	sink := withStatusSink(t, http.StatusOK)

	stop := runService(t)
	require.Eventually(t, func() bool { return len(sink.recorded()) >= 5 }, 5*time.Second, time.Millisecond,
		"heartbeats while osqueryd stays down")
	syncs := len(fs.recorded())
	require.Eventually(t, func() bool { return len(fs.recorded()) > syncs }, 5*time.Second, time.Millisecond,
		"syncs keep running while osqueryd is down")
	stop()

	for _, r := range sink.recorded() {
		assert.Equal(t, testHostUUID, r.UUID)
		assert.False(t, r.OsqueryRunning)
		assert.NotNil(t, r.DownSince)
	}
	// Only the first sync's restart and its rollback restart: never one because osqueryd is down
	assert.Len(t, *recorded, 2)
}

func TestLoopSurvivesUnreachableOsctrl(t *testing.T) {
	fs, _ := setupGuard(t, testEnvFlags, neverRunning)
	sink := withStatusSink(t, http.StatusInternalServerError)
	logs := captureLogs(t)

	stop := runService(t)
	require.Eventually(t, func() bool { return len(sink.recorded()) >= 5 }, 5*time.Second, time.Millisecond)
	syncs := len(fs.recorded())
	require.Eventually(t, func() bool { return len(fs.recorded()) > syncs }, 5*time.Second, time.Millisecond,
		"syncs keep running after report failures")
	stop()

	warns := 0
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "failed to send status report") {
			assert.Contains(t, line, `"level":"warn"`)
			warns++
		}
	}
	assert.Positive(t, warns)
	assert.Less(t, warns, len(sink.recorded()), "warn at most once per interval")
}

func TestUnsupportedStatusNotLoggedAsErrorEachInterval(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			syncOnceGuard(t, neverRunning)
			sink := withStatusSink(t, code)
			logs := captureLogs(t)

			syncOnce(context.Background(), newTestCLICommand())
			require.Len(t, sink.recorded(), 1)

			now := time.Now()
			for i := 0; i < 10; i++ {
				watchTick(now.Add(time.Duration(i) * time.Hour))
			}
			assert.Len(t, sink.recorded(), 1, "no heartbeat while unsupported")

			syncOnce(context.Background(), newTestCLICommand())
			assert.Len(t, sink.recorded(), 2, "the next sync tests support again")

			out := logs.String()
			assert.NotContains(t, out, "failed to send status report")
			assert.Equal(t, 1, strings.Count(out, errStatusUnsupported.Error()), "logged once per process")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, errStatusUnsupported.Error()) {
					assert.Contains(t, line, `"level":"debug"`)
				}
			}
		})
	}
}

func TestSyncAppliesFixWhileDown(t *testing.T) {
	const fixed = "--tls_hostname=osctrl.example.com\n--fixed=1"
	restarted := false
	fs, recorded := setupGuard(t, testEnvFlags, nil)
	osquerydRunning = func() (bool, error) { return restarted, nil }
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	osctrlURLs.Cert = notFound.URL
	osctrlURLs.Extensions = notFound.URL
	sink := withStatusSink(t, http.StatusOK)

	now := time.Now()
	watchTick(now)
	watchTick(now)
	running, _ := health.state()
	require.False(t, running)

	fs.mu.Lock()
	fs.override = fixed
	fs.mu.Unlock()
	osquerydRunning = func() (bool, error) { restarted = len(*recorded) > 0; return restarted, nil }
	syncOnce(context.Background(), newTestCLICommand())

	assert.Equal(t, fixed, readFlagFile(t), "fix applied while osqueryd was down")
	assert.Len(t, *recorded, 1, "one restart for the new flags")
	assert.Equal(t, applyOK, loadFlagsState(flagsStatePath()).Last.Result)
	assert.Len(t, sink.recorded(), 1)
}
