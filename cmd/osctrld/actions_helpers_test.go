package main

import (
	"encoding/json"
	"fmt"
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

	changed, err := writeContentExists(path, "hello", "test", false, 0700)
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

	changed, err := writeContentExists(path, "hello", "test", false, 0700)
	assert.NoError(t, err)
	assert.False(t, changed, "same content should not report changed")
}

func TestWriteContentExists_DifferentContentNoForce(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0700))

	changed, err := writeContentExists(path, "new", "test", false, 0700)
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

	changed, err := writeContentExists(path, "new", "test", true, 0700)
	assert.NoError(t, err)
	assert.True(t, changed, "forced overwrite should report changed")

	content, _ := os.ReadFile(path)
	assert.Equal(t, "new", string(content))
}

func TestWriteContentExistsHonorsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")

	changed, err := writeContentExists(path, "s3cr3t", "secret", false, 0600)
	require.NoError(t, err)
	assert.True(t, changed)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// os.WriteFile applies perm only at creation, so an existing file keeps its old
// mode unless we chmod explicitly. The realistic case is a secret written by the
// osctrl quick-add script at 0644, then migrated to osctrld install.
func TestWriteContentExistsTightensExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "osquery.secret")
	require.NoError(t, os.WriteFile(path, []byte("old-secret"), 0644))

	_, err := writeContentExists(path, "new-secret", "secret", true, 0600)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"an existing secret must be tightened, not left world-readable")
}

func TestWriteContentExistsTightensModeWhenContentUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "osquery.secret")
	require.NoError(t, os.WriteFile(path, []byte("same-secret"), 0644))

	_, err := writeContentExists(path, "same-secret", "secret", false, 0600)
	require.NoError(t, err)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"matching content must still leave the file at the requested mode")
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

	data := ScriptRequest{OsctrlSecret: "test-secret"}
	body, err := genericRetrieve(server.URL+"/env/enroll/darwin/osctrld-script", false, data)
	assert.NoError(t, err)
	assert.Contains(t, string(body), "echo enroll")
}

func TestGenericRetrieve_ServerError(t *testing.T) {
	server := mockOsctrlServer()
	defer server.Close()

	data := ScriptRequest{OsctrlSecret: "test-secret"}
	_, err := genericRetrieve(server.URL+"/error", false, data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestGenericRetrieve_ConnectionRefused(t *testing.T) {
	data := ScriptRequest{OsctrlSecret: "test-secret"}
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

	flags, err := retrieveFlags("test-secret", "/tmp/secret", "/tmp/cert", "", nil)
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

func TestParseOsqueryVersion(t *testing.T) {
	cases := []struct {
		name     string
		output   string
		expected string
	}{
		{"osqueryd output", "osqueryd version 5.12.1", "5.12.1"},
		{"trailing newline", "osqueryd version 5.12.1\n", "5.12.1"},
		{"extra whitespace", "  osqueryd   version   5.12.1  ", "5.12.1"},
		{"two fields", "osqueryd 5.12.1", ""},
		{"one field", "5.12.1", ""},
		{"empty output", "", ""},
		{"whitespace only", "   \n", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseOsqueryVersion(tt.output))
		})
	}
}

// fakeCreateTemp records every temp file the atomic writer creates and whether
// it asked for the restricted (secret) security descriptor
func fakeCreateTemp(t *testing.T) *[]string {
	t.Helper()
	recorded := &[]string{}
	prev := createTemp
	createTemp = func(dir, pattern string, restricted bool) (*os.File, error) {
		f, err := prev(dir, pattern, false)
		if err == nil {
			*recorded = append(*recorded, fmt.Sprintf("%s restricted=%v", f.Name(), restricted))
		}
		return f, err
	}
	t.Cleanup(func() { createTemp = prev })
	return recorded
}

func fakeApplySecretACL(t *testing.T) *[]string {
	t.Helper()
	recorded := &[]string{}
	prev := applySecretACL
	applySecretACL = func(p string) error { *recorded = append(*recorded, p); return nil }
	t.Cleanup(func() { applySecretACL = prev })
	return recorded
}

func withSecretFile(t *testing.T, path string) {
	t.Helper()
	prev := appConfig
	t.Cleanup(func() { appConfig = prev })
	appConfig.OsquerySecretFile = path
}

// A symlink at the target is replaced with a regular file, never written through
func TestWriteContentExistsReplacesSymlink(t *testing.T) {
	for _, content := range []string{"different", "same"} {
		t.Run(content, func(t *testing.T) {
			dir := t.TempDir()
			victim := filepath.Join(t.TempDir(), "victim")
			require.NoError(t, os.WriteFile(victim, []byte("same"), 0644))
			require.NoError(t, os.Chmod(victim, 0644))
			link := filepath.Join(dir, "osquery.flags")
			require.NoError(t, os.Symlink(victim, link))

			_, err := writeContentExists(link, content, "flags", false, 0700)
			assert.Error(t, err, "a symlink is never trusted as current without --force")

			changed, err := writeContentExists(link, content, "flags", true, 0700)
			require.NoError(t, err)
			assert.True(t, changed)
			info, err := os.Lstat(link)
			require.NoError(t, err)
			assert.True(t, info.Mode().IsRegular(), "the symlink itself is replaced")
			assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
			b, _ := os.ReadFile(link)
			assert.Equal(t, content, string(b))

			b, _ = os.ReadFile(victim)
			assert.Equal(t, "same", string(b), "the symlink target is untouched")
			vi, err := os.Stat(victim)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0644), vi.Mode().Perm())
		})
	}
}

func TestWriteContentExistsRefusesNonRegular(t *testing.T) {
	path := filepath.Join(t.TempDir(), "osquery.flags")
	require.NoError(t, os.Mkdir(path, 0755))
	_, err := writeContentExists(path, "x", "flags", true, 0700)
	assert.Error(t, err)
	info, err := os.Lstat(path)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// A write that fails half way leaves the previous content and no temp file
func TestWriteContentExistsNoPartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "osquery.flags")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0700))
	prev := createTemp
	t.Cleanup(func() { createTemp = prev })
	createTemp = func(dir, pattern string, restricted bool) (*os.File, error) {
		f, err := prev(dir, pattern, restricted)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
		return os.Open(f.Name()) // read-only: every write fails
	}
	_, err := writeContentExists(path, "new", "flags", true, 0700)
	require.Error(t, err)
	b, _ := os.ReadFile(path)
	assert.Equal(t, "old", string(b))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temp file left behind")
}

// The secret is written through a temp file created restricted, before any
// byte of it is written; other files keep the default
func TestWriteContentExistsSecretACL(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "osquery.secret")
	withSecretFile(t, secret)
	temps := fakeCreateTemp(t)
	applied := fakeApplySecretACL(t)

	_, err := writeContentExists(secret, "s3cr3t", "secret", true, 0600)
	require.NoError(t, err)
	_, err = writeContentExists(filepath.Join(dir, "osquery.flags"), "--x", "flags", true, 0700)
	require.NoError(t, err)
	require.Len(t, *temps, 2)
	assert.Contains(t, (*temps)[0], "restricted=true")
	assert.Contains(t, (*temps)[1], "restricted=false")
	assert.Empty(t, *applied, "a freshly created secret needs no second pass")

	// An existing secret with matching content is re-restricted in place
	_, err = writeContentExists(secret, "s3cr3t", "secret", true, 0600)
	require.NoError(t, err)
	assert.Equal(t, []string{secret}, *applied)
	assert.Len(t, *temps, 2)
}
