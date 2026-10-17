package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testExtSecret = "test-secret"

var testExtBody = []byte("#!/bin/sh\necho extension\n")

// fakeSetOwner records the paths handed to setOwner instead of chowning them,
// so the installer runs without root
func fakeSetOwner(t *testing.T) *[]string {
	t.Helper()
	recorded := &[]string{}
	prev := setOwner
	setOwner = func(path string) error {
		*recorded = append(*recorded, path)
		return nil
	}
	t.Cleanup(func() { setOwner = prev })
	return recorded
}

// extensionServer serves body at the osctrld download path for env "dev" and
// points the configured osctrl base at it. It fails the test on anything but a
// POST to /dev/osctrld-extension carrying the secret and the SHA-256 of
// testExtBody, which every caller's entry names. The returned counter is the number of requests.
func extensionServer(t *testing.T, body []byte, status int) *int {
	t.Helper()
	requests := new(int)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/dev/osctrld-extension", r.URL.Path, "the SHA-256 travels in the body, not the path")
		var req map[string]string
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, map[string]string{"secret": testExtSecret, "sha256": sha256Hex(string(testExtBody))}, req)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	prev := osctrlURLs
	t.Cleanup(func() { osctrlURLs = prev })
	osctrlURLs = genURLs(server.URL, "dev", false)
	return requests
}

// fakeFileSafe decides whether an existing file counts as safely owned, since
// tests do not run as root
func fakeFileSafe(t *testing.T, safe bool) {
	t.Helper()
	prev := extensionFileSafe
	extensionFileSafe = func(string) bool { return safe }
	t.Cleanup(func() { extensionFileSafe = prev })
}

func testEntry(body []byte) ExtensionEntry {
	return ExtensionEntry{Name: "osquery_exec", SHA256: sha256Hex(string(body)), Size: int64(len(body))}
}

// tempLeftovers lists any temporary download left behind in dir
func tempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var left []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			left = append(left, e.Name())
		}
	}
	return left
}

func TestExtensionFileName(t *testing.T) {
	tests := []struct {
		name, goos, want string
		wantErr          bool
	}{
		{"osquery_exec", "linux", "osquery_exec.ext", false},
		{"osquery_exec", "darwin", "osquery_exec.ext", false},
		{"osquery_exec", "windows", "osquery_exec.exe", false},
		{"my-ext_2", "linux", "my-ext_2.ext", false},
		{strings.Repeat("a", 64), "linux", strings.Repeat("a", 64) + ".ext", false},
		{"../x", "linux", "", true},
		{"a/b", "linux", "", true},
		{`a\b`, "windows", "", true},
		{"", "linux", "", true},
		{"..", "linux", "", true},
		{"a.ext", "linux", "", true},
		{strings.Repeat("a", 65), "linux", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.goos, func(t *testing.T) {
			got, err := extensionFileName(tt.name, tt.goos)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestInstallExtensionVerifiesHash(t *testing.T) {
	owned := fakeSetOwner(t)
	requests := extensionServer(t, testExtBody, http.StatusOK)
	dir := t.TempDir()

	path, changed, err := installExtension(dir, testEntry(testExtBody), "linux", testExtSecret, false)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, 1, *requests)
	assert.Equal(t, filepath.Join(dir, "osquery_exec.ext"), path)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, testExtBody, content)
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	require.Len(t, *owned, 1)
	assert.Equal(t, dir, filepath.Dir((*owned)[0]))
	assert.NotEqual(t, path, (*owned)[0], "ownership is set on the temp file, before it replaces the target")
	assert.Empty(t, tempLeftovers(t, dir))
}

func TestInstallExtensionRejectsMismatch(t *testing.T) {
	fakeSetOwner(t)
	// Same size, so only the hash differs
	tampered := append([]byte{}, testExtBody...)
	tampered[0] ^= 0xff
	extensionServer(t, tampered, http.StatusOK)
	dir := t.TempDir()
	entry := testEntry(testExtBody)

	_, changed, err := installExtension(dir, entry, "linux", testExtSecret, false)
	assert.Error(t, err)
	assert.False(t, changed)
	assert.NoFileExists(t, filepath.Join(dir, "osquery_exec.ext"))
	assert.Empty(t, tempLeftovers(t, dir))
}

func TestInstallExtensionRejectsOversize(t *testing.T) {
	fakeSetOwner(t)
	extensionServer(t, append(append([]byte{}, testExtBody...), []byte("more bytes")...), http.StatusOK)
	dir := t.TempDir()

	_, _, err := installExtension(dir, testEntry(testExtBody), "linux", testExtSecret, false)
	assert.Error(t, err)
	assert.NoFileExists(t, filepath.Join(dir, "osquery_exec.ext"))
	assert.Empty(t, tempLeftovers(t, dir))
}

func TestInstallExtensionRejectsBadEntry(t *testing.T) {
	fakeSetOwner(t)
	requests := extensionServer(t, testExtBody, http.StatusOK)
	dir := t.TempDir()
	good := testEntry(testExtBody)
	for name, e := range map[string]ExtensionEntry{
		"zero size":     {Name: good.Name, SHA256: good.SHA256, Size: 0},
		"over 64 MiB":   {Name: good.Name, SHA256: good.SHA256, Size: 64<<20 + 1},
		"short sha":     {Name: good.Name, SHA256: "abc", Size: good.Size},
		"sha with path": {Name: good.Name, SHA256: "../" + good.SHA256[3:], Size: good.Size},
		"bad name":      {Name: "../x", SHA256: good.SHA256, Size: good.Size},
	} {
		_, _, err := installExtension(dir, e, "linux", testExtSecret, false)
		assert.Error(t, err, name)
	}
	assert.Equal(t, 0, *requests)
}

func TestInstallExtensionUnchanged(t *testing.T) {
	fakeSetOwner(t)
	fakeFileSafe(t, true)
	requests := extensionServer(t, testExtBody, http.StatusOK)
	dir := t.TempDir()
	target := filepath.Join(dir, "osquery_exec.ext")
	require.NoError(t, os.WriteFile(target, testExtBody, 0755))

	path, changed, err := installExtension(dir, testEntry(testExtBody), "linux", testExtSecret, false)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, target, path)
	assert.Equal(t, 0, *requests)
}

// The published bytes are no secret: a file with the right hash but the wrong
// owner or mode could be rewritten later by whoever owns it, so it is replaced
// with a fresh, root-owned download rather than trusted
func TestInstallExtensionReplacesUnsafeMatchingFile(t *testing.T) {
	owned := fakeSetOwner(t)
	fakeFileSafe(t, false)
	requests := extensionServer(t, testExtBody, http.StatusOK)
	dir := t.TempDir()
	target := filepath.Join(dir, "osquery_exec.ext")
	require.NoError(t, os.WriteFile(target, testExtBody, 0644))
	require.NoError(t, os.Chmod(target, 0777))
	before, err := os.Stat(target)
	require.NoError(t, err)

	path, changed, err := installExtension(dir, testEntry(testExtBody), "linux", testExtSecret, false)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, target, path)
	assert.Equal(t, 1, *requests)
	after, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), after.Mode().Perm())
	assert.False(t, os.SameFile(before, after), "a new inode defeats any write handle still open on the old one")
	require.Len(t, *owned, 1)
	assert.NotEqual(t, target, (*owned)[0])
	assert.Empty(t, tempLeftovers(t, dir))
}

func TestInstallExtensionReplacesDifferentFile(t *testing.T) {
	fakeSetOwner(t)
	extensionServer(t, testExtBody, http.StatusOK)
	dir := t.TempDir()
	target := filepath.Join(dir, "osquery_exec.ext")
	require.NoError(t, os.WriteFile(target, []byte("old version"), 0700))

	_, changed, err := installExtension(dir, testEntry(testExtBody), "linux", testExtSecret, false)
	require.NoError(t, err)
	assert.True(t, changed)
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, testExtBody, content)
}

func TestInstallExtensionRefusesSymlink(t *testing.T) {
	fakeSetOwner(t)
	requests := extensionServer(t, testExtBody, http.StatusOK)
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(outside, []byte("do not touch"), 0644))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "osquery_exec.ext")))

	_, _, err := installExtension(dir, testEntry(testExtBody), "linux", testExtSecret, false)
	assert.Error(t, err)
	assert.Equal(t, 0, *requests)
	content, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, []byte("do not touch"), content)
	info, err := os.Stat(outside)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

func TestInstallExtensionDownload404(t *testing.T) {
	fakeSetOwner(t)
	extensionServer(t, []byte("not found"), http.StatusNotFound)
	dir := t.TempDir()

	_, _, err := installExtension(dir, testEntry(testExtBody), "linux", testExtSecret, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "osquery_exec")
	assert.NoFileExists(t, filepath.Join(dir, "osquery_exec.ext"))
	assert.Empty(t, tempLeftovers(t, dir))
}

// The list comes from the network: its url must never decide where osctrld
// connects, or a tampered list could send the secret and the download elsewhere
func TestInstallExtensionIgnoresEntryURL(t *testing.T) {
	fakeSetOwner(t)
	requests := extensionServer(t, testExtBody, http.StatusOK)
	otherRequests := 0
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherRequests++
		_, _ = w.Write(testExtBody)
	}))
	defer other.Close()
	dir := t.TempDir()
	entry := testEntry(testExtBody)
	entry.URL = other.URL + "/dev/osctrld-extension"

	_, changed, err := installExtension(dir, entry, "linux", testExtSecret, false)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, 1, *requests)
	assert.Equal(t, 0, otherRequests)
}

func TestEnsureExtensionsDir(t *testing.T) {
	t.Run("missing is created 0755", func(t *testing.T) {
		owned := fakeSetOwner(t)
		dir := filepath.Join(t.TempDir(), "extensions")
		require.NoError(t, ensureExtensionsDir(dir+"/"))
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
		assert.Equal(t, []string{dir}, *owned)
	})
	t.Run("world writable is repaired", func(t *testing.T) {
		fakeSetOwner(t)
		dir := filepath.Join(t.TempDir(), "extensions")
		require.NoError(t, os.Mkdir(dir, 0755))
		require.NoError(t, os.Chmod(dir, 0777))
		require.NoError(t, ensureExtensionsDir(dir))
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
	})
	t.Run("symlink is refused", func(t *testing.T) {
		owned := fakeSetOwner(t)
		linkTarget := t.TempDir()
		require.NoError(t, os.Chmod(linkTarget, 0777))
		dir := filepath.Join(t.TempDir(), "extensions")
		require.NoError(t, os.Symlink(linkTarget, dir))
		// A trailing slash would make Lstat follow the link
		assert.Error(t, ensureExtensionsDir(dir+"/"))
		assert.Empty(t, *owned)
		info, err := os.Stat(linkTarget)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0777), info.Mode().Perm(), "the link target is left alone")
	})
	t.Run("regular file is refused", func(t *testing.T) {
		fakeSetOwner(t)
		dir := filepath.Join(t.TempDir(), "extensions")
		require.NoError(t, os.WriteFile(dir, nil, 0644))
		assert.Error(t, ensureExtensionsDir(dir))
	})
}

func TestRemoveManagedFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	require.NoError(t, os.WriteFile(outside, []byte("keep"), 0644))
	link := filepath.Join(dir, "evil.ext")
	require.NoError(t, os.Symlink(outside, link))

	assert.Error(t, removeManagedFile(dir, "evil.ext"))
	_, err := os.Lstat(link)
	assert.NoError(t, err, "the symlink itself is not removed either")
	assert.FileExists(t, outside)

	// Nothing outside dir, nor dir itself, can be named
	require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(dir), "sibling.ext"), nil, 0644))
	t.Cleanup(func() { _ = os.Remove(filepath.Join(filepath.Dir(dir), "sibling.ext")) })
	for _, name := range []string{"../sibling.ext", "", ".", "..", "sub/x.ext"} {
		assert.Error(t, removeManagedFile(dir, name), name)
	}
	assert.FileExists(t, filepath.Join(filepath.Dir(dir), "sibling.ext"))

	// A regular file is removed, and an absent one is already done
	require.NoError(t, os.WriteFile(filepath.Join(dir, "good.ext"), nil, 0755))
	require.NoError(t, removeManagedFile(dir, "good.ext"))
	assert.NoFileExists(t, filepath.Join(dir, "good.ext"))
	assert.NoError(t, removeManagedFile(dir, "good.ext"))
}

func TestRetrieveExtensionManifestRequest(t *testing.T) {
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		got = nil
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_ = json.NewEncoder(w).Encode([]ExtensionEntry{testEntry(testExtBody)})
	}))
	defer server.Close()

	entries, err := retrieveExtensionManifest(ExtensionsRequest{OsctrlSecret: testExtSecret, Platform: "linux", Arch: "amd64"}, server.URL, false)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, testEntry(testExtBody), entries[0])
	assert.Equal(t, map[string]any{"secret": testExtSecret, "platform": "linux", "arch": "amd64"}, got,
		"uuid and status are omitted when empty")

	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	_, err = retrieveExtensionManifest(ExtensionsRequest{
		OsctrlSecret: testExtSecret, UUID: "u-1", Platform: "darwin", Arch: "arm64",
		Status: []ExtensionStatus{{Name: "osquery_exec", SHA256: "abc", Result: "rejected", Error: "boom", At: at}},
	}, server.URL, false)
	require.NoError(t, err)
	assert.Equal(t, "u-1", got["uuid"])
	assert.Equal(t, []any{map[string]any{
		"name": "osquery_exec", "sha256": "abc", "result": "rejected", "error": "boom", "at": "2026-10-19T12:00:00Z",
	}}, got["status"])

	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	entries, err = retrieveExtensionManifest(ExtensionsRequest{OsctrlSecret: testExtSecret}, notFound.URL, false)
	assert.NoError(t, err)
	assert.Empty(t, entries)

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	_, err = retrieveExtensionManifest(ExtensionsRequest{OsctrlSecret: testExtSecret}, failing.URL, false)
	assert.Error(t, err)
}
