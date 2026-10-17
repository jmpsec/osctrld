package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testHostUUID = "4C4C4544-0042-3510-8051-B4C04F4E4B32"

// fakeExecOutput makes execCommand run a shell that prints out (or fails)
func fakeExecOutput(t *testing.T, out string, fail bool) {
	t.Helper()
	prev := execCommand
	t.Cleanup(func() { execCommand = prev })
	execCommand = func(name string, args ...string) *exec.Cmd {
		if fail {
			return exec.Command("false")
		}
		return exec.Command("printf", "%s", out)
	}
}

func TestReadHostUUID(t *testing.T) {
	fakeExecOutput(t, `[{"uuid":"`+testHostUUID+`"}]`+"\n", false)
	got, err := readHostUUID()
	require.NoError(t, err)
	assert.Equal(t, testHostUUID, got)
}

func TestReadHostUUIDFailures(t *testing.T) {
	tests := []struct {
		name string
		out  string
		fail bool
	}{
		{"command error", "", true},
		{"empty array", "[]", false},
		{"not json", "not json", false},
		{"not a uuid", `[{"uuid":"abc"}]`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeExecOutput(t, tt.out, tt.fail)
			_, err := readHostUUID()
			assert.Error(t, err)
		})
	}
}

// A hung osqueryd -S must never block the service loop
func TestReadHostUUIDTimeout(t *testing.T) {
	prevExec, prevTimeout := execCommand, hostUUIDTimeout
	t.Cleanup(func() { execCommand, hostUUIDTimeout = prevExec, prevTimeout })
	execCommand = func(name string, args ...string) *exec.Cmd { return exec.Command("sleep", "10") }
	hostUUIDTimeout = 50 * time.Millisecond

	start := time.Now()
	_, err := readHostUUID()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestRetrieveFlagsSendsIdentity(t *testing.T) {
	var got FlagsRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_, _ = w.Write([]byte("--flag=1"))
	}))
	defer server.Close()
	osctrlURLs.Flags = server.URL
	appConfig.Insecure = false

	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	_, err := retrieveFlags("s", "/sf", "/cf", testHostUUID,
		&ApplyStatus{Result: "rejected", SHA256: "ab", Error: "e", At: at})
	require.NoError(t, err)
	assert.Equal(t, testHostUUID, got.UUID)
	require.NotNil(t, got.Apply)
	assert.Equal(t, "rejected", got.Apply.Result)
	assert.Equal(t, "ab", got.Apply.SHA256)
	assert.Equal(t, "e", got.Apply.Error)
	assert.True(t, at.Equal(got.Apply.At))
}

func TestRetrieveFlagsOmitsEmptyIdentity(t *testing.T) {
	var raw []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte("--flag=1"))
	}))
	defer server.Close()
	osctrlURLs.Flags = server.URL
	appConfig.Insecure = false

	_, err := retrieveFlags("s", "/sf", "/cf", "", nil)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"uuid"`)
	assert.NotContains(t, string(raw), `"apply"`)
}
