package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func setupTestConfig(t *testing.T, server *httptest.Server) (cleanup func()) {
	dir := t.TempDir()

	appConfig = Configuration{
		Secret:       "test-secret",
		SecretFile:   filepath.Join(dir, "osquery.secret"),
		FlagFile:     filepath.Join(dir, "osquery.flags"),
		CertFile:     filepath.Join(dir, "osctrl.crt"),
		OsqueryPath:  dir,
		Environment:  "env",
		BaseURL:      server.URL,
		Insecure:     false,
		Verbose:      false,
		Force:        true,
		EnrollScript: filepath.Join(dir, "osctrld-enroll.sh"),
		RemoveScript: filepath.Join(dir, "osctrld-remove.sh"),
	}
	osctrlURLs = genURLs(server.URL, "env", false)

	return func() {
		appConfig = Configuration{}
		osctrlURLs = OsctrlURLs{}
	}
}

func newTestCLIContext() *cli.Context {
	app := cli.NewApp()
	return cli.NewContext(app, nil, nil)
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

	c := newTestCLIContext()
	changed, err := getFlags(c)
	assert.NoError(t, err)
	assert.True(t, changed, "new flags file should report changed")

	content, err := os.ReadFile(appConfig.FlagFile)
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

	c := newTestCLIContext()
	_, err := getFlags(c)
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

	c := newTestCLIContext()
	changed, err := getCert(c)
	assert.NoError(t, err)
	assert.True(t, changed, "new cert file should report changed")

	content, err := os.ReadFile(appConfig.CertFile)
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

	c := newTestCLIContext()
	_, err := getCert(c)
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

	c := newTestCLIContext()
	err := enrollNode(c)
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

	c := newTestCLIContext()
	err := enrollNode(c)
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

	c := newTestCLIContext()
	err := removeNode(c)
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

	c := newTestCLIContext()
	err := removeNode(c)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error retrieving remove")
}

func TestVerifyNode_Success(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "osquery.secret")
	flagPath := filepath.Join(dir, "osquery.flags")
	certPath := filepath.Join(dir, "osctrl.crt")

	flagContent := "--tls_hostname=osctrl.example.com\n--tls_server_certs=/etc/osquery/osctrl.crt"
	certContent := "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

	require.NoError(t, os.WriteFile(secretPath, []byte("test-secret"), 0644))
	require.NoError(t, os.WriteFile(flagPath, []byte(flagContent), 0644))
	require.NoError(t, os.WriteFile(certPath, []byte(certContent), 0644))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := VerifyResponse{
			Flags:          flagContent,
			Certificate:    certContent,
			OsqueryVersion: "5.0.0",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	appConfig = Configuration{
		Secret:      "test-secret",
		SecretFile:  secretPath,
		FlagFile:    flagPath,
		CertFile:    certPath,
		OsqueryPath: dir,
		Environment: "env",
		BaseURL:     server.URL,
		Verbose:     false,
	}
	osctrlURLs.Verify = server.URL + "/verify"

	c := newTestCLIContext()
	err := verifyNode(c)
	assert.NoError(t, err)
}
