package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func setupTestConfig(t *testing.T, server *httptest.Server) (cleanup func()) {
	dir := t.TempDir()

	appConfig = Configuration{
		OsctrlSecret:      "test-secret",
		OsquerySecretFile: filepath.Join(dir, "osquery.secret"),
		OsqueryFlagFile:   filepath.Join(dir, "osquery.flags"),
		OsqueryCertFile:   filepath.Join(dir, "osctrl.crt"),
		OsqueryPath:       dir,
		Environment:       "env",
		BaseURL:           server.URL,
		Insecure:          false,
		Verbose:           false,
		Force:             true,
		EnrollScript:      filepath.Join(dir, "osctrld-enroll.sh"),
		RemoveScript:      filepath.Join(dir, "osctrld-remove.sh"),
	}
	osctrlURLs = genURLs(server.URL, "env", false)

	return func() {
		appConfig = Configuration{}
		osctrlURLs = OsctrlURLs{}
	}
}

func newTestCLICommand() *cli.Command {
	return &cli.Command{Name: appName}
}

func TestGetFlags_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("--tls_hostname=osctrl.example.com"))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Flags = server.URL + "/flags"

	c := newTestCLICommand()
	changed, err := getFlags(context.Background(), c)
	assert.NoError(t, err)
	assert.True(t, changed, "new flags file should report changed")

	content, err := os.ReadFile(appConfig.OsqueryFlagFile)
	require.NoError(t, err)
	assert.Equal(t, "--tls_hostname=osctrl.example.com", string(content))
}

func TestGetFlags_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Flags = server.URL + "/flags"

	c := newTestCLICommand()
	_, err := getFlags(context.Background(), c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving flags")
}

func TestGetCert_Success(t *testing.T) {
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(certPEM))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Cert = server.URL + "/cert"

	c := newTestCLICommand()
	changed, err := getCert(context.Background(), c)
	assert.NoError(t, err)
	assert.True(t, changed, "new cert file should report changed")

	content, err := os.ReadFile(appConfig.OsqueryCertFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "BEGIN CERTIFICATE")
}

func TestGetCert_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Cert = server.URL + "/cert"

	c := newTestCLICommand()
	_, err := getCert(context.Background(), c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving cert")
}

func TestEnrollNode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("#!/bin/bash\necho enrolled"))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Enroll = server.URL + "/enroll"

	c := newTestCLICommand()
	err := enrollNode(context.Background(), c)
	assert.NoError(t, err)
}

func TestEnrollNode_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Enroll = server.URL + "/enroll"

	c := newTestCLICommand()
	err := enrollNode(context.Background(), c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving enroll")
}

func TestRemoveNode_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("#!/bin/bash\necho removed"))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Remove = server.URL + "/remove"

	c := newTestCLICommand()
	err := removeNode(context.Background(), c)
	assert.NoError(t, err)
}

func TestRemoveNode_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	cleanup := setupTestConfig(t, server)
	defer cleanup()
	osctrlURLs.Remove = server.URL + "/remove"

	c := newTestCLICommand()
	err := removeNode(context.Background(), c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving remove")
}

func TestVerifyNode(t *testing.T) {
	prevConfig, prevURLs := appConfig, osctrlURLs
	prevRunning, prevVersion := osquerydRunning, osqueryVersionReader
	prevDarwin, prevLinux, prevWindows := OsqueryDarwin, OsqueryLinux, OsqueryWindows
	t.Cleanup(func() {
		appConfig, osctrlURLs = prevConfig, prevURLs
		osquerydRunning, osqueryVersionReader = prevRunning, prevVersion
		OsqueryDarwin, OsqueryLinux, OsqueryWindows = prevDarwin, prevLinux, prevWindows
	})

	flagContent := "--tls_hostname=osctrl.example.com\n--tls_server_certs=/etc/osquery/osctrl.crt"
	certContent := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(VerifyResponse{Flags: flagContent, Certificate: certContent, OsqueryVersion: "5.0.0"})
	}))
	defer server.Close()
	osctrlURLs.Verify = server.URL + "/verify"

	tests := []struct {
		name      string
		secret    string
		flags     string
		cert      string
		installed bool
		version   string
		running   bool
		wantErr   string
	}{
		{"healthy", "test-secret", flagContent, certContent, true, "5.1.0", true, ""},
		{"secret mismatch", "other", flagContent, certContent, true, "5.1.0", true, "secret mismatch"},
		{"flags mismatch", "test-secret", "--other", certContent, true, "5.1.0", true, "flags mismatch"},
		{"cert mismatch", "test-secret", flagContent, "other", true, "5.1.0", true, "certificate mismatch"},
		{"not installed", "test-secret", flagContent, certContent, false, "5.1.0", true, "osquery is not installed"},
		{"version too low", "test-secret", flagContent, certContent, true, "4.9.0", true, "osquery version too low"},
		{"unknown version", "test-secret", flagContent, certContent, true, "", true, "unknown osquery version"},
		{"not running", "test-secret", flagContent, certContent, true, "5.1.0", false, "osqueryd is not running"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			secretPath := filepath.Join(dir, "osquery.secret")
			flagPath := filepath.Join(dir, "osquery.flags")
			certPath := filepath.Join(dir, "osctrl.crt")
			require.NoError(t, os.WriteFile(secretPath, []byte(tt.secret), 0644))
			require.NoError(t, os.WriteFile(flagPath, []byte(tt.flags), 0644))
			require.NoError(t, os.WriteFile(certPath, []byte(tt.cert), 0644))
			local := []string{filepath.Join(dir, "service"), filepath.Join(dir, "osqueryd")}
			if tt.installed {
				for _, l := range local {
					require.NoError(t, os.WriteFile(l, nil, 0644))
				}
			}
			OsqueryDarwin, OsqueryLinux, OsqueryWindows = local, local, local
			osqueryVersionReader = func() string { return tt.version }
			osquerydRunning = func() (bool, error) { return tt.running, nil }
			appConfig = Configuration{
				OsctrlSecret:      "test-secret",
				OsquerySecretFile: secretPath,
				OsqueryFlagFile:   flagPath,
				OsqueryCertFile:   certPath,
				OsqueryPath:       dir,
				Environment:       "env",
				BaseURL:           server.URL,
			}

			err := verifyNode(context.Background(), newTestCLICommand())
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
