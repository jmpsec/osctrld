package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const contractResponse = `{"reason":"","source":"environment","request_id":"3f2a","target":{"version":"5.13.0","sha256":"aa"},"previous":{"version":"5.12.1","sha256":"bb"},"reported_version":"5.12.1"}`

func TestUpgradeResolutionMatchesWireContract(t *testing.T) {
	var r upgradeResolution
	require.NoError(t, json.Unmarshal([]byte(contractResponse), &r))
	assert.Equal(t, upgradeResolution{Source: "environment", RequestID: "3f2a",
		Target: &upgradeRef{"5.13.0", "aa"}, Previous: &upgradeRef{"5.12.1", "bb"}, ReportedVersion: "5.12.1"}, r)
	var n upgradeResolution
	require.NoError(t, json.Unmarshal([]byte(`{"reason":"no_target","reported_version":""}`), &n))
	assert.Equal(t, "no_target", n.Reason)
	assert.Nil(t, n.Target)
}

func setupUpgradeClient(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	appConfig = Configuration{OsctrlSecret: "S", OsqueryFlagFile: dir + "/flags"}
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{HostUUID: "U"}))
	osctrlURLs = genURLs(srv.URL, "env", false)
	pg, pa := upgradeGOOS, upgradeGOARCH
	upgradeGOOS, upgradeGOARCH = "linux", "amd64"
	t.Cleanup(func() { appConfig = Configuration{}; osctrlURLs = OsctrlURLs{}; upgradeGOOS, upgradeGOARCH = pg, pa })
}

func TestRequestUpgradeResolutionSendsContractBody(t *testing.T) {
	var body, rawURL, method string
	setupUpgradeClient(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body, rawURL, method = string(b), r.URL.String(), r.Method
		_, _ = w.Write([]byte(contractResponse))
	})
	upgradeGOOS, upgradeGOARCH = "darwin", "arm64"
	res, err := requestUpgradeResolution("5.12.1")
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, method)
	assert.Equal(t, "/env/osctrld-osquery", rawURL)
	assert.NotContains(t, rawURL, "S")
	var got map[string]string
	require.NoError(t, json.Unmarshal([]byte(body), &got))
	assert.Equal(t, map[string]string{"secret": "S", "uuid": "U", "platform": "darwin", "arch": "arm64", "format": "pkg", "installed_version": "5.12.1"}, got)
	assert.Equal(t, "3f2a", res.RequestID)
}

func TestRequestUpgradeResolutionUnsupportedOn404And405(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusMethodNotAllowed} {
		setupUpgradeClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) })
		pg := upgradeGOOS
		upgradeGOOS = "darwin"
		_, err := requestUpgradeResolution("5.12.1")
		upgradeGOOS = pg
		assert.ErrorIs(t, err, errUpgradeUnsupported)
	}
}

func TestRequestUpgradeResolutionTypedErrorAndTimeout(t *testing.T) {
	setupUpgradeClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	upgradeGOOS = "darwin"
	_, err := requestUpgradeResolution("5.12.1")
	var se *httpStatusError
	require.ErrorAs(t, err, &se)
	assert.Equal(t, 7*time.Second, se.retryAfter)
}

func TestRequestUpgradeResolutionTimesOut(t *testing.T) {
	done := make(chan struct{})
	setupUpgradeClient(t, func(w http.ResponseWriter, r *http.Request) { <-done })
	t.Cleanup(func() { close(done) })
	upgradeGOOS = "darwin"
	prev := upgradeRequestTimeout
	t.Cleanup(func() { upgradeRequestTimeout = prev })
	upgradeRequestTimeout = 100 * time.Millisecond
	start := time.Now()
	_, err := requestUpgradeResolution("5.12.1")
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}
