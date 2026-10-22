package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEventID = "1760000000000000000:0000000000000000000000000000000000000000000000000000000000000000"

func statusEnv(t *testing.T) {
	t.Helper()
	appConfig = Configuration{OsqueryFlagFile: filepath.Join(t.TempDir(), "osquery.flags"), OsctrlSecret: "S"}
	t.Cleanup(func() { appConfig = Configuration{}; osctrlURLs = OsctrlURLs{} })
}

func TestStatusReportMatchesWireContract(t *testing.T) {
	down := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)
	r := statusReport{
		Secret: "S", UUID: "U", OsqueryRunning: false, DownSince: &down,
		Flags:      statusStage{Stage: "exhausted", EventID: testEventID},
		Extensions: statusStage{Stage: "none", EventID: ""},
	}
	b, err := json.Marshal(r)
	require.NoError(t, err)
	assert.JSONEq(t, `{"secret":"S","uuid":"U","osquery_running":false,"down_since":"2026-10-22T10:00:00Z",
 "flags":{"stage":"exhausted","event_id":"`+testEventID+`"},
 "extensions":{"stage":"none","event_id":""}}`, string(b))
}

func TestBuildStatusReportReadsStages(t *testing.T) {
	statusEnv(t)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{Stage: stageLastKnownGood, EventID: testEventID}))
	require.NoError(t, saveExtState(extStatePath(), extState{Rollback: &rollbackEvent{Stage: "exhausted", EventID: "x:y"}}))
	down := time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)

	r := buildStatusReport("U", false, down)
	assert.Equal(t, "U", r.UUID)
	assert.False(t, r.OsqueryRunning)
	require.NotNil(t, r.DownSince)
	assert.True(t, r.DownSince.Equal(down))
	assert.Equal(t, statusStage{Stage: stageLastKnownGood, EventID: testEventID}, r.Flags)
	assert.Equal(t, statusStage{Stage: "exhausted", EventID: "x:y"}, r.Extensions)
}

func TestBuildStatusReportNoRollback(t *testing.T) {
	statusEnv(t)
	r := buildStatusReport("U", true, time.Now())
	assert.Equal(t, statusStage{Stage: "none"}, r.Flags)
	assert.Equal(t, statusStage{Stage: "none"}, r.Extensions)
	assert.Nil(t, r.DownSince)
	b, err := json.Marshal(r)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "down_since")

	// down but without a known start: still omitted
	assert.Nil(t, buildStatusReport("U", false, time.Time{}).DownSince)
}

// A released osctrl-tls answers 405 (its GET / pattern matches the path), an
// osctrl without the route at all 404: both mean "not supported"
func TestSendStatusReportUnsupportedOn404And405(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			statusEnv(t)
			var logs bytes.Buffer
			old := log.Logger
			log.Logger = zerolog.New(&logs)
			t.Cleanup(func() { log.Logger = old })
			var got map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&got)
				w.WriteHeader(code)
			}))
			defer srv.Close()
			osctrlURLs = genURLs(srv.URL, "env", false)

			err := sendStatusReport(statusReport{UUID: "U"})
			assert.ErrorIs(t, err, errStatusUnsupported)
			assert.Equal(t, "S", got["secret"], "sender fills the secret")
			assert.NotContains(t, logs.String(), `"level":"error"`)
			assert.NotContains(t, logs.String(), `"level":"warn"`)
		})
	}
}

func TestSendStatusReport429IsError(t *testing.T) {
	statusEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	osctrlURLs = genURLs(srv.URL, "env", false)

	err := sendStatusReport(statusReport{UUID: "U"})
	var se *httpStatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, http.StatusTooManyRequests, se.code)
	assert.NotErrorIs(t, err, errStatusUnsupported)
}

func TestSendStatusReportOK(t *testing.T) {
	statusEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/env/osctrld-status", r.URL.Path)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	osctrlURLs = genURLs(srv.URL, "env", false)
	assert.NoError(t, sendStatusReport(statusReport{UUID: "U"}))
}

// A stalled osctrl must not block the service loop for the package-download timeout
func TestSendStatusReportTimesOut(t *testing.T) {
	statusEnv(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)
	osctrlURLs = genURLs(srv.URL, "env", false)
	prev := statusTimeout
	t.Cleanup(func() { statusTimeout = prev })
	statusTimeout = 100 * time.Millisecond

	start := time.Now()
	err := sendStatusReport(statusReport{UUID: "U"})
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second)
}
