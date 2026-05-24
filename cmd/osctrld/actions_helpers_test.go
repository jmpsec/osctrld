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
)

func TestWriteContentExists_NewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "newfile.txt")

	changed, err := writeContentExists(path, "hello", "test", false)
	assert.NoError(t, err)
	assert.True(t, changed, "new file should report changed")

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(content))
}

func TestWriteContentExists_SameContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0700))

	changed, err := writeContentExists(path, "hello", "test", false)
	assert.NoError(t, err)
	assert.False(t, changed, "same content should not report changed")
}

func TestWriteContentExists_DifferentContentNoForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0700))

	changed, err := writeContentExists(path, "new", "test", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "please use --force")
	assert.False(t, changed, "should not report changed on error")

	content, _ := os.ReadFile(path)
	assert.Equal(t, "old", string(content))
}

func TestWriteContentExists_DifferentContentWithForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0700))

	changed, err := writeContentExists(path, "new", "test", true)
	assert.NoError(t, err)
	assert.True(t, changed, "forced overwrite should report changed")

	content, _ := os.ReadFile(path)
	assert.Equal(t, "new", string(content))
}

func mockOsctrlServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/env/osctrld-flags", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("--tls_hostname=osctrl.example.com\n--tls_server_certs=/etc/osquery/osctrl.crt"))
	})
	mux.HandleFunc("/env/osctrld-cert", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nMIIBxTCCAWugAwIBAgIJALP...\n-----END CERTIFICATE-----"))
	})
	mux.HandleFunc("/env/osctrld-verify", func(w http.ResponseWriter, r *http.Request) {
		resp := VerifyResponse{
			Flags:          "--tls_hostname=osctrl.example.com",
			Certificate:    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			OsqueryVersion: "5.0.0",
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/env/enroll/darwin/osctrld-script", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("#!/bin/bash\necho enroll"))
	})
	mux.HandleFunc("/env/remove/darwin/osctrld-script", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("#!/bin/bash\necho remove"))
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	})
	return httptest.NewServer(mux)
}

func TestGenericRetrieve_Success(t *testing.T) {
	server := mockOsctrlServer()
	defer server.Close()

	data := ScriptRequest{Secret: "test-secret"}
	body, err := genericRetrieve(server.URL+"/env/enroll/darwin/osctrld-script", false, data)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "echo enroll")
}

func TestGenericRetrieve_ServerError(t *testing.T) {
	server := mockOsctrlServer()
	defer server.Close()

	data := ScriptRequest{Secret: "test-secret"}
	_, err := genericRetrieve(server.URL+"/error", false, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestGenericRetrieve_ConnectionRefused(t *testing.T) {
	data := ScriptRequest{Secret: "test-secret"}
	_, err := genericRetrieve("http://127.0.0.1:1/unreachable", false, data)
	assert.Error(t, err)
}

func TestRetrieveScript(t *testing.T) {
	server := mockOsctrlServer()
	defer server.Close()

	script, err := retrieveScript("test-secret", server.URL+"/env/enroll/darwin/osctrld-script", false)
	assert.NoError(t, err)
	assert.Contains(t, script, "echo enroll")
}

func TestRetrieveCert(t *testing.T) {
	server := mockOsctrlServer()
	defer server.Close()

	cert, err := retrieveCert("test-secret", server.URL+"/env/osctrld-cert", false)
	assert.NoError(t, err)
	assert.Contains(t, cert, "BEGIN CERTIFICATE")
}

func TestRetrieveVerify(t *testing.T) {
	server := mockOsctrlServer()
	defer server.Close()

	v, err := retrieveVerify("secret", "/tmp/secret", "/tmp/cert", server.URL+"/env/osctrld-verify", false)
	assert.NoError(t, err)
	assert.Equal(t, "5.0.0", v.OsqueryVersion)
	assert.Contains(t, v.Flags, "tls_hostname")
}

func TestRetrieveFlags(t *testing.T) {
	server := mockOsctrlServer()
	defer server.Close()

	osctrlURLs.Flags = server.URL + "/env/osctrld-flags"
	appConfig.Insecure = false

	flags, err := retrieveFlags("test-secret", "/tmp/secret", "/tmp/cert")
	assert.NoError(t, err)
	assert.Contains(t, flags, "tls_hostname")
}

func TestCheckFileExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "exists.txt")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0644))

	assert.True(t, checkFileExist(path))
	assert.False(t, checkFileExist(filepath.Join(dir, "nope.txt")))
}

func TestCheckFileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "content.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello world"), 0644))

	assert.True(t, checkFileContent(path, "hello world"))
	assert.False(t, checkFileContent(path, "different"))
	assert.False(t, checkFileContent(filepath.Join(dir, "nope.txt"), "anything"))
}

func TestCheckFileContent_Whitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ws.txt")
	require.NoError(t, os.WriteFile(path, []byte("  hello  \n"), 0644))

	assert.True(t, checkFileContent(path, "hello"))
}
