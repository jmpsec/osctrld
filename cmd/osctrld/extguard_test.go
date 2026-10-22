package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extServer is a fake osctrl serving an extensions list and downloads for env "dev"
type extServer struct {
	mu       sync.Mutex
	list     []ExtensionEntry
	files    map[string][]byte // sha256 → body
	listCode int
	requests []ExtensionsRequest
}

func (s *extServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/dev/osctrld-extensions" {
		var req ExtensionsRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.requests = append(s.requests, req)
		if s.listCode != 0 {
			w.WriteHeader(s.listCode)
			return
		}
		_ = json.NewEncoder(w).Encode(s.list)
		return
	}
	if r.URL.Path == "/dev/osctrld-extension" {
		var req struct {
			Secret string `json:"secret"`
			SHA256 string `json:"sha256"`
		}
		if json.NewDecoder(r.Body).Decode(&req) == nil && req.Secret != "" && s.files[req.SHA256] != nil {
			_, _ = w.Write(s.files[req.SHA256])
			return
		}
	}
	http.NotFound(w, r)
}

// serve replaces the served list; each pair is a name and the file body
func (s *extServer) serve(pairs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = nil
	for i := 0; i+1 < len(pairs); i += 2 {
		body := []byte(pairs[i+1])
		sha := sha256Hex(pairs[i+1])
		s.files[sha] = body
		s.list = append(s.list, ExtensionEntry{Name: pairs[i], SHA256: sha, Size: int64(len(body)), URL: "https://elsewhere.example/" + sha})
	}
}

func (s *extServer) recorded() []ExtensionsRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ExtensionsRequest(nil), s.requests...)
}

// extEnv is one test's wiring: fake osctrl, temp dirs and fake processes
type extEnv struct {
	srv      *extServer
	flags    *flagsServer
	dir      string
	autoload string
	restarts *[][]string
	running  map[string]bool // extension path → running
	mu       sync.Mutex
}

func (e *extEnv) setRunning(path string, running bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.running[path] = running
}

// extPath is where the named extension lands for the configured goos
func (e *extEnv) extPath(t *testing.T, name string) string {
	t.Helper()
	f, err := extensionFileName(name, extensionsGOOS)
	require.NoError(t, err)
	return filepath.Join(e.dir, f)
}

// setupExt builds on the flags guard wiring and adds an extensions server, an
// extensions directory and an autoload file named in the flagfile
func setupExt(t *testing.T) *extEnv {
	t.Helper()
	fs, recorded := setupGuard(t, testOverrideFlags, nil)
	fakeSetOwner(t)
	fakeFileSafe(t, true)
	fakeDirSafe(t, true)

	srv := &extServer{files: map[string][]byte{}}
	server := httptest.NewServer(srv)
	t.Cleanup(server.Close)
	notFound := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(notFound.Close)
	flagsURL := osctrlURLs.Flags
	osctrlURLs = genURLs(server.URL, "dev", false)
	osctrlURLs.Flags = flagsURL
	osctrlURLs.Cert = notFound.URL

	prevGOOS, prevExtRunning := extensionsGOOS, extensionRunning
	t.Cleanup(func() { extensionsGOOS, extensionRunning = prevGOOS, prevExtRunning })
	extensionsGOOS = "linux"

	root := filepath.Dir(appConfig.OsqueryFlagFile)
	e := &extEnv{
		srv:      srv,
		flags:    fs,
		dir:      filepath.Join(root, "extensions"),
		autoload: filepath.Join(root, "extensions.load"),
		restarts: recorded,
		running:  map[string]bool{},
	}
	appConfig.ExtensionsDir = e.dir + "/"
	appConfig.OsqueryPath = root + "/"
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(e.flagfile("")), 0700))
	extensionRunning = func(path string) (bool, error) {
		e.mu.Lock()
		defer e.mu.Unlock()
		return e.running[path], nil
	}
	return e
}

// flagfile is a flagfile pointing osquery at the test autoload file
func (e *extEnv) flagfile(extra string) string {
	s := testOverrideFlags + "\n--extensions_autoload=" + e.autoload
	if extra != "" {
		s += "\n" + extra
	}
	return s
}

func (e *extEnv) autoloadLines(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(e.autoload)
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	return strings.Fields(string(b))
}

// stepAndVerify runs one extensions step and, if it changed anything, the check
func (e *extEnv) stepAndVerify(t *testing.T) bool {
	t.Helper()
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	if changed {
		require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	}
	return changed
}

func readExtState(t *testing.T) extState {
	t.Helper()
	return loadExtState(extStatePath())
}

func statusFor(st extState, name string) *ExtensionStatus {
	for i := range st.Status {
		if st.Status[i].Name == name {
			return &st.Status[i]
		}
	}
	return nil
}

func extProcessDownError() string {
	return fmt.Sprintf("extension process was not running %gs after restart", restartCheckTimeout.Seconds())
}

func removalDownExtError() string {
	return fmt.Sprintf("osqueryd was not running %gs after the extension was removed", restartCheckTimeout.Seconds())
}

func osquerydDownExtError() string {
	return fmt.Sprintf("osqueryd was not running %gs after extensions changed", restartCheckTimeout.Seconds())
}

func TestAutoloadPath(t *testing.T) {
	dir := t.TempDir()
	withFlag := filepath.Join(dir, "with.flags")
	require.NoError(t, os.WriteFile(withFlag, []byte("--tls_hostname=x\n--extensions_autoload=/x/y.load\n"), 0600))
	without := filepath.Join(dir, "without.flags")
	require.NoError(t, os.WriteFile(without, []byte("--tls_hostname=x\n"), 0600))
	empty := filepath.Join(dir, "empty.flags")
	require.NoError(t, os.WriteFile(empty, []byte("--extensions_autoload=\n"), 0600))
	missing := filepath.Join(dir, "missing.flags")

	tests := []struct {
		name, flagfile, goos, want string
	}{
		{"flag linux", withFlag, "linux", "/x/y.load"},
		{"flag windows", withFlag, "windows", "/x/y.load"},
		{"default linux", without, "linux", "/etc/osquery/extensions.load"},
		{"default darwin", without, "darwin", "/private/var/osquery/extensions.load"},
		{"default windows", without, "windows", `C:\Program Files\osquery\extensions.load`},
		{"empty value", empty, "linux", "/etc/osquery/extensions.load"},
		{"missing flagfile", missing, "darwin", "/private/var/osquery/extensions.load"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, autoloadPath(tt.flagfile, tt.goos))
		})
	}
}

// fakeDirSafe decides whether the autoload directory counts as admin-only,
// since tests do not run as root
func fakeDirSafe(t *testing.T, safe bool) {
	t.Helper()
	prev := autoloadDirSafe
	autoloadDirSafe = func(string) bool { return safe }
	t.Cleanup(func() { autoloadDirSafe = prev })
}

// fakeOsqueryPath makes dir osquery's base directory, where autoload files live
func fakeOsqueryPath(t *testing.T, dir string) {
	t.Helper()
	prev := appConfig.OsqueryPath
	appConfig.OsqueryPath = dir
	t.Cleanup(func() { appConfig.OsqueryPath = prev })
}

func TestWriteAutoloadKeepsOperatorLines(t *testing.T) {
	fakeSetOwner(t)
	fakeDirSafe(t, true)
	dir := t.TempDir()
	fakeOsqueryPath(t, dir)
	path := filepath.Join(dir, "extensions.load")
	require.NoError(t, os.WriteFile(path, []byte("/opt/b.ext\n/opt/a.ext\n/e/c.ext\n"), 0644))

	require.NoError(t, writeAutoload(path, []string{"/e/z.ext", "/e/d.ext"}, []string{"/e/c.ext"}))
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "/opt/b.ext\n/opt/a.ext\n/e/d.ext\n/e/z.ext\n", string(b))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())

	// A missing file is created; nothing to write creates nothing
	created := filepath.Join(dir, "new.load")
	require.NoError(t, writeAutoload(filepath.Join(dir, "none.load"), nil, nil))
	assert.NoFileExists(t, filepath.Join(dir, "none.load"))
	require.NoError(t, writeAutoload(created, []string{"/e/d.ext"}, nil))
	b, err = os.ReadFile(created)
	require.NoError(t, err)
	assert.Equal(t, "/e/d.ext\n", string(b))

	// A symlinked autoload file is refused and its target left alone
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("keep\n"), 0644))
	link := filepath.Join(dir, "link.load")
	require.NoError(t, os.Symlink(target, link))
	assert.Error(t, writeAutoload(link, []string{"/e/d.ext"}, nil))
	b, err = os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "keep\n", string(b))

	assert.Error(t, writeAutoload("relative.load", []string{"/e/d.ext"}, nil))
}

func TestSyncExtensionsInstallsAndRemoves(t *testing.T) {
	e := setupExt(t)
	require.NoError(t, os.MkdirAll(e.dir, 0755))
	operatorFile := filepath.Join(e.dir, "z.ext")
	require.NoError(t, os.WriteFile(operatorFile, []byte("operator"), 0755))
	require.NoError(t, os.WriteFile(e.autoload, []byte("/opt/operator.ext\n"), 0644))
	x, y := e.extPath(t, "x"), e.extPath(t, "y")
	e.setRunning(x, true)
	e.setRunning(y, true)

	e.srv.serve("x", "x-v1", "../escape", "bad")
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	assert.True(t, changed)
	assert.FileExists(t, x)
	assert.NoFileExists(t, filepath.Join(filepath.Dir(e.dir), "escape.ext"))
	assert.Equal(t, []string{"/opt/operator.ext", x}, e.autoloadLines(t))
	st := readExtState(t)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, st.Installed)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, st.Pending)
	assert.Equal(t, []string{x}, st.Lines)
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))

	e.srv.serve("y", "y-v1")
	assert.True(t, e.stepAndVerify(t))
	assert.NoFileExists(t, x)
	assert.NoFileExists(t, x+".prev")
	assert.FileExists(t, y)
	assert.Equal(t, []string{"/opt/operator.ext", y}, e.autoloadLines(t))
	assert.Equal(t, map[string]string{"y": sha256Hex("y-v1")}, readExtState(t).Installed)

	// Nothing changed: no restart, nothing pending
	assert.False(t, e.stepAndVerify(t))

	e.srv.serve()
	assert.True(t, e.stepAndVerify(t))
	assert.NoFileExists(t, y)
	assert.Equal(t, []string{"/opt/operator.ext"}, e.autoloadLines(t))
	assert.FileExists(t, operatorFile)
	b, err := os.ReadFile(operatorFile)
	require.NoError(t, err)
	assert.Equal(t, "operator", string(b))
	st = readExtState(t)
	assert.Empty(t, st.Installed)
	assert.Empty(t, st.Lines)
	assert.Empty(t, *e.restarts, "the steps alone never restart")

	// An osctrl without extensions (404) also removes what osctrld installed
	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	assert.FileExists(t, x)
	e.srv.listCode = http.StatusNotFound
	assert.True(t, e.stepAndVerify(t))
	assert.NoFileExists(t, x)
	assert.FileExists(t, operatorFile)
	assert.Equal(t, []string{"/opt/operator.ext"}, e.autoloadLines(t))
}

// A host that never had extensions is left alone: no directory, no autoload file
func TestSyncExtensionsNothingAssigned(t *testing.T) {
	e := setupExt(t)
	e.srv.listCode = http.StatusNotFound
	assert.False(t, e.stepAndVerify(t))
	assert.NoDirExists(t, e.dir)
	assert.NoFileExists(t, e.autoload)
	assert.NoFileExists(t, extStatePath())
}

func TestSyncExtensionsSweepsStaleTemp(t *testing.T) {
	e := setupExt(t)
	require.NoError(t, os.MkdirAll(e.dir, 0755))
	stale := filepath.Join(e.dir, ".x.ext.tmp-123456")
	require.NoError(t, os.WriteFile(stale, []byte("partial"), 0600))
	operatorTmp := filepath.Join(e.dir, ".notes.tmp-1")
	require.NoError(t, os.WriteFile(operatorTmp, []byte("mine"), 0600))
	e.setRunning(e.extPath(t, "x"), true)

	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	assert.NoFileExists(t, stale)
	assert.FileExists(t, operatorTmp, "only osctrld's own temp names are swept")
	assert.Equal(t, []string{e.extPath(t, "x")}, e.autoloadLines(t))
}

func TestVerifyExtensionsOK(t *testing.T) {
	e := setupExt(t)
	x := e.extPath(t, "x")
	e.setRunning(x, true)
	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))

	e.srv.serve("x", "x-v2")
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	b, err := os.ReadFile(x + ".prev")
	require.NoError(t, err)
	assert.Equal(t, "x-v1", string(b), "the previous version is kept until verified")
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, readExtState(t).Previous)

	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	assert.NoFileExists(t, x+".prev")
	b, err = os.ReadFile(x)
	require.NoError(t, err)
	assert.Equal(t, "x-v2", string(b))
	st := readExtState(t)
	assert.Empty(t, st.Pending)
	assert.Empty(t, st.Previous)
	assert.Empty(t, st.Rejected)
	s := statusFor(st, "x")
	require.NotNil(t, s)
	assert.Equal(t, applyOK, s.Result)
	assert.Equal(t, sha256Hex("x-v2"), s.SHA256)
	assert.Empty(t, s.Error)
	assert.Empty(t, *e.restarts)
	assert.Empty(t, tempLeftovers(t, e.dir))
}

func TestVerifyExtensionsRemovesFailedOne(t *testing.T) {
	e := setupExt(t)
	x, y := e.extPath(t, "x"), e.extPath(t, "y")
	e.setRunning(x, true)
	e.srv.serve("x", "x-v1", "y", "y-v1")
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)

	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))

	assert.FileExists(t, x)
	assert.NoFileExists(t, y)
	assert.Equal(t, []string{x}, e.autoloadLines(t))
	assert.Len(t, *e.restarts, 1, "one restart without the failed extension")
	st := readExtState(t)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, st.Installed)
	assert.Equal(t, map[string]string{"y": sha256Hex("y-v1")}, st.Rejected)
	assert.Equal(t, []string{x}, st.Lines)
	assert.Empty(t, st.Pending)
	sx, sy := statusFor(st, "x"), statusFor(st, "y")
	require.NotNil(t, sx)
	require.NotNil(t, sy)
	assert.Equal(t, applyOK, sx.Result)
	assert.Equal(t, applyRejected, sy.Result)
	assert.Equal(t, sha256Hex("y-v1"), sy.SHA256)
	assert.Equal(t, extProcessDownError(), sy.Error)
	assert.Empty(t, tempLeftovers(t, e.dir))
}

func TestVerifyExtensionsOsquerydDown(t *testing.T) {
	e := setupExt(t)
	x, y, w := e.extPath(t, "x"), e.extPath(t, "y"), e.extPath(t, "w")
	e.setRunning(x, true)
	e.setRunning(w, true)
	e.srv.serve("x", "x-v1", "w", "w-v1")
	assert.True(t, e.stepAndVerify(t))

	// Update x, add y, remove w; osqueryd then never comes back
	e.srv.serve("x", "x-v2", "y", "y-v1")
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	assert.NoFileExists(t, w)
	osquerydRunning = neverRunning

	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))

	b, err := os.ReadFile(x)
	require.NoError(t, err)
	assert.Equal(t, "x-v1", string(b), "previous version restored")
	b, err = os.ReadFile(w)
	require.NoError(t, err)
	assert.Equal(t, "w-v1", string(b), "removed extension restored")
	assert.NoFileExists(t, y)
	assert.NoFileExists(t, x+".prev")
	assert.Equal(t, []string{w, x}, e.autoloadLines(t))
	assert.Len(t, *e.restarts, 1, "one rollback restart")

	st := readExtState(t)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1"), "w": sha256Hex("w-v1")}, st.Installed)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v2"), "y": sha256Hex("y-v1")}, st.Rejected)
	assert.Equal(t, map[string]string{"w": sha256Hex("w-v1")}, st.RejectedRemovals)
	assert.Empty(t, st.Pending)
	assert.Empty(t, st.Previous)
	for _, name := range []string{"x", "y"} {
		s := statusFor(st, name)
		require.NotNil(t, s, name)
		assert.Equal(t, applyRejected, s.Result)
		assert.Equal(t, osquerydDownExtError(), s.Error)
	}
	assert.Equal(t, sha256Hex("x-v2"), statusFor(st, "x").SHA256)
	sw := statusFor(st, "w")
	require.NotNil(t, sw)
	assert.Equal(t, applyKept, sw.Result, "a removal that failed is reported as kept")
	assert.Equal(t, sha256Hex("w-v1"), sw.SHA256)
	assert.Equal(t, removalDownExtError(), sw.Error)
	assert.Empty(t, tempLeftovers(t, e.dir))

	// The same list again keeps the last good set: x stays at v1, w stays,
	// nothing changes and osquery is not restarted
	osquerydRunning = func() (bool, error) { return true, nil }
	*e.restarts = nil
	assert.False(t, e.stepAndVerify(t))
	b, err = os.ReadFile(x)
	require.NoError(t, err)
	assert.Equal(t, "x-v1", string(b))
	assert.FileExists(t, w)
	assert.Equal(t, []string{w, x}, e.autoloadLines(t))
	assert.Empty(t, *e.restarts)
}

// A removal that keeps osqueryd down (e.g. flags with --extensions_require) is
// rolled back, reported once and not retried while the list stays the same
func TestRejectedRemovalKept(t *testing.T) {
	e := setupExt(t)
	w := e.extPath(t, "w")
	e.setRunning(w, true)
	e.srv.serve("w", "w-v1")
	assert.True(t, e.stepAndVerify(t))

	e.srv.serve()
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	osquerydRunning = neverRunning
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	assert.FileExists(t, w)
	assert.Equal(t, []string{w}, e.autoloadLines(t))
	assert.Len(t, *e.restarts, 1, "rollback restart")

	osquerydRunning = func() (bool, error) { return true, nil }
	*e.restarts = nil
	assert.False(t, e.stepAndVerify(t), "same list: removal not retried")
	assert.False(t, e.stepAndVerify(t))
	assert.FileExists(t, w)
	assert.Equal(t, []string{w}, e.autoloadLines(t))
	assert.Empty(t, *e.restarts)
	reqs := e.srv.recorded()
	require.Len(t, reqs, 4)
	// Reported on the next request and on every one after, so osctrl never
	// loses the evidence while the extension stays
	for i, r := range reqs[2:] {
		require.Len(t, r.Status, 1, i)
		assert.Equal(t, "w", r.Status[0].Name)
		assert.Equal(t, applyKept, r.Status[0].Result)
		assert.Equal(t, sha256Hex("w-v1"), r.Status[0].SHA256)
		assert.Equal(t, removalDownExtError(), r.Status[0].Error)
	}

	// Once osctrl serves w again the memory goes, the kept version is
	// reported ok, and a later removal is retried
	e.srv.serve("w", "w-v1")
	assert.False(t, e.stepAndVerify(t))
	assert.Empty(t, readExtState(t).RejectedRemovals)
	sw := statusFor(readExtState(t), "w")
	require.NotNil(t, sw, "served again: reported ok")
	assert.Equal(t, applyOK, sw.Result)
	assert.Equal(t, sha256Hex("w-v1"), sw.SHA256)
	assert.Empty(t, sw.Error)
	assert.False(t, e.stepAndVerify(t))
	sent := e.srv.recorded()[5].Status
	require.Len(t, sent, 1, "the ok is sent, without a kept")
	assert.Equal(t, applyOK, sent[0].Result)
	assert.Empty(t, readExtState(t).Status, "ok reported once")
	e.srv.serve()
	assert.True(t, e.stepAndVerify(t))
	assert.NoFileExists(t, w)
	sw = statusFor(readExtState(t), "w")
	require.NotNil(t, sw)
	assert.Equal(t, applyRemoved, sw.Result, "the retried removal worked")
}

// A successful removal of an extension osctrld installed is reported as
// removed, with the removed version, whether or not the file was still there
func TestRemovalReported(t *testing.T) {
	for _, gone := range []bool{false, true} {
		t.Run(fmt.Sprintf("file gone %v", gone), func(t *testing.T) {
			e := setupExt(t)
			x := e.extPath(t, "x")
			e.setRunning(x, true)
			e.srv.serve("x", "x-v1")
			assert.True(t, e.stepAndVerify(t))
			if gone {
				require.NoError(t, os.Remove(x))
			}

			e.srv.serve()
			assert.True(t, e.stepAndVerify(t))
			assert.NoFileExists(t, x)
			st := readExtState(t)
			require.Len(t, st.Status, 1, "the ok was sent with the removal's request")
			s := st.Status[0]
			assert.Equal(t, "x", s.Name)
			assert.Equal(t, applyRemoved, s.Result)
			assert.Equal(t, sha256Hex("x-v1"), s.SHA256)
			assert.Empty(t, s.Error)
			assert.Empty(t, *e.restarts)
		})
	}
}

// A removal whose file cannot be moved aside leaves the extension installed
// and is reported as kept
func TestRemovalMoveAsideFailsKept(t *testing.T) {
	e := setupExt(t)
	x := e.extPath(t, "x")
	e.setRunning(x, true)
	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	// Something that is not a regular file now sits at the extension's path
	require.NoError(t, os.Remove(x))
	require.NoError(t, os.Mkdir(x, 0755))

	e.srv.serve()
	assert.False(t, e.stepAndVerify(t))
	assert.DirExists(t, x)
	assert.Equal(t, []string{x}, e.autoloadLines(t))
	st := readExtState(t)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, st.Installed)
	s := statusFor(st, "x")
	require.NotNil(t, s)
	assert.Equal(t, applyKept, s.Result)
	assert.Equal(t, sha256Hex("x-v1"), s.SHA256)
	assert.Contains(t, s.Error, "not a regular file")
}

func TestSyncSkipsRejectedUntilChanged(t *testing.T) {
	e := setupExt(t)
	y := e.extPath(t, "y")
	e.setRunning(y, true)
	require.NoError(t, saveExtState(extStatePath(), extState{Rejected: map[string]string{"y": sha256Hex("y-v1")}}))

	e.srv.serve("y", "y-v1")
	assert.False(t, e.stepAndVerify(t))
	assert.NoFileExists(t, y)
	assert.Equal(t, map[string]string{"y": sha256Hex("y-v1")}, readExtState(t).Rejected, "kept while served")

	e.srv.serve("y", "y-v2")
	assert.True(t, e.stepAndVerify(t))
	assert.FileExists(t, y)
	assert.Empty(t, readExtState(t).Rejected)
}

func TestStatusReportedOnce(t *testing.T) {
	e := setupExt(t)
	cached := "11111111-2222-3333-4444-555555555555"
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{HostUUID: cached}))
	at := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	sent := ExtensionStatus{Name: "x", SHA256: sha256Hex("x-v1"), Result: applyOK, At: at}
	require.NoError(t, saveExtState(extStatePath(), extState{Status: []ExtensionStatus{sent}}))

	// A failed request keeps the status for the next one
	e.srv.listCode = http.StatusInternalServerError
	_, err := syncExtensionsStep(context.Background())
	assert.Error(t, err)
	assert.Len(t, readExtState(t).Status, 1)

	e.srv.listCode = 0
	_, err = syncExtensionsStep(context.Background())
	require.NoError(t, err)
	assert.Empty(t, readExtState(t).Status)

	_, err = syncExtensionsStep(context.Background())
	require.NoError(t, err)

	reqs := e.srv.recorded()
	require.Len(t, reqs, 3)
	for _, r := range reqs[:2] {
		require.Len(t, r.Status, 1)
		assert.Equal(t, "x", r.Status[0].Name)
		assert.True(t, at.Equal(r.Status[0].At))
	}
	assert.Empty(t, reqs[2].Status, "sent once")
	assert.Equal(t, cached, reqs[2].UUID, "the flags step's cached host uuid")
	assert.Equal(t, testExtSecret, reqs[2].OsctrlSecret)
	assert.Equal(t, "linux", reqs[2].Platform)
	assert.NotEmpty(t, reqs[2].Arch)
}

func TestResumePendingExtensionsCheck(t *testing.T) {
	for name, restarted := range map[string]bool{"not restarted": false, "restarted": true} {
		t.Run(name, func(t *testing.T) {
			e := setupExt(t)
			x := e.extPath(t, "x")
			ev := &events{}
			execCommand = func(string, ...string) *exec.Cmd { ev.add("restart"); return exec.Command("true") }
			extensionRunning = func(path string) (bool, error) { ev.add("extension"); return path == x, nil }
			e.srv.serve("x", "x-v1")
			changed, err := syncExtensionsStep(context.Background())
			require.NoError(t, err)
			require.True(t, changed)
			assert.False(t, readExtState(t).Restarted, "a new step is not restarted yet")
			if restarted {
				restartForExtensions()
				require.True(t, readExtState(t).Restarted)
				ev.take()
			}

			// A pending change blocks a new step until it is verified
			_, err = syncExtensionsStep(context.Background())
			assert.Error(t, err)

			require.NoError(t, resumeExtensionsCheck(context.Background()))
			if restarted {
				assert.Equal(t, []string{"extension"}, ev.take(), "osquery already loaded the change")
			} else {
				assert.Equal(t, []string{"restart", "extension"}, ev.take(), "restart first, then check")
			}
			st := readExtState(t)
			assert.Empty(t, st.Pending)
			assert.False(t, st.Restarted)
			require.NotNil(t, statusFor(st, "x"))
			assert.Equal(t, applyOK, statusFor(st, "x").Result)

			// Nothing pending: nothing to do
			require.NoError(t, resumeExtensionsCheck(context.Background()))
			assert.Empty(t, ev.take())
		})
	}
}

func TestVerifyExtensionsStopsOnCancel(t *testing.T) {
	e := setupExt(t)
	e.srv.serve("x", "x-v1")
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	restartCheckTimeout = time.Minute
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.ErrorIs(t, verifyExtensionsAfterRestart(ctx), context.Canceled)
	assert.NotEmpty(t, readExtState(t).Pending, "resumed on the next sync")
}

func TestDisabledByFlags(t *testing.T) {
	e := setupExt(t)
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(e.flagfile("--disable_extensions=true")), 0700))
	checks := 0
	extensionRunning = func(string) (bool, error) { checks++; return false, nil }

	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	assert.FileExists(t, e.extPath(t, "x"))
	assert.Zero(t, checks, "no process check")
	assert.Empty(t, *e.restarts)
	st := readExtState(t)
	s := statusFor(st, "x")
	require.NotNil(t, s)
	assert.Equal(t, applyOK, s.Result)
	assert.Equal(t, "extensions are disabled by flags", s.Error)
	assert.Empty(t, st.Rejected)
}

func TestDisabledByFlagsParsing(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		content string
		want    bool
	}{
		{"--disable_extensions=true", true},
		{"--disable_extensions", true},
		{"--disable_extensions=1", true},
		{"--disable_extensions=false", false},
		{"--disable_extensions=true\n--disable_extensions=false", false},
		{"--tls_hostname=x", false},
		{"--disable_extensions_foo=true", false},
	}
	for i, tt := range tests {
		t.Run(tt.content, func(t *testing.T) {
			path := filepath.Join(dir, fmt.Sprintf("%d.flags", i))
			require.NoError(t, os.WriteFile(path, []byte(tt.content+"\n"), 0600))
			assert.Equal(t, tt.want, disabledByFlags(path))
		})
	}
	assert.False(t, disabledByFlags(filepath.Join(dir, "missing")))
}

// events records restarts and process checks in order, collapsing repeats
type events struct {
	mu  sync.Mutex
	log []string
}

func (ev *events) add(s string) {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	if n := len(ev.log); n > 0 && ev.log[n-1] == s {
		return
	}
	ev.log = append(ev.log, s)
}

func (ev *events) take() []string {
	ev.mu.Lock()
	defer ev.mu.Unlock()
	l := ev.log
	ev.log = nil
	return l
}

func TestSyncOnceFlagsThenExtensions(t *testing.T) {
	e := setupExt(t)
	ev := &events{}
	execCommand = func(name string, args ...string) *exec.Cmd {
		ev.add("restart")
		return exec.Command("true")
	}
	osquerydRunning = func() (bool, error) { ev.add("osqueryd"); return true, nil }
	extensionRunning = func(string) (bool, error) { ev.add("extension"); return true, nil }
	// Served flags carry the test autoload path, as a real flagfile would
	e.flags.override = e.flagfile("")
	e.flags.env = e.flagfile("")
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testEnvFlags), 0700))

	e.srv.serve("x", "x-v1")
	syncOnce(context.Background(), newTestCLICommand())
	// The trailing osqueryd poll is the end-of-sync status observation
	assert.Equal(t, []string{"restart", "osqueryd", "restart", "osqueryd", "extension", "osqueryd"}, ev.take(),
		"flags restart and check, then extensions restart and check")
	assert.Equal(t, applyOK, loadFlagsState(flagsStatePath()).Last.Result)
	assert.Equal(t, applyOK, statusFor(readExtState(t), "x").Result)

	// Only the extensions change: one restart
	e.srv.serve("x", "x-v2")
	syncOnce(context.Background(), newTestCLICommand())
	assert.Equal(t, []string{"restart", "osqueryd", "extension", "osqueryd"}, ev.take())

	// Nothing changes: no restart, no restart check, only the status poll
	syncOnce(context.Background(), newTestCLICommand())
	assert.Equal(t, []string{"osqueryd"}, ev.take())
}

func TestSyncOnceResumesExtensionsCheck(t *testing.T) {
	e := setupExt(t)
	// The flags step keeps the flagfile as is
	e.flags.override = e.flagfile("")
	x := e.extPath(t, "x")
	require.NoError(t, os.MkdirAll(e.dir, 0755))
	require.NoError(t, os.WriteFile(x, []byte("x-v1"), 0755))
	require.NoError(t, os.WriteFile(e.autoload, []byte(x+"\n"), 0644))
	require.NoError(t, saveExtState(extStatePath(), extState{
		Installed: map[string]string{"x": sha256Hex("x-v1")},
		Lines:     []string{x},
		Autoload:  e.autoload,
		Pending:   map[string]string{"x": sha256Hex("x-v1")},
		Restarted: true,
	}))
	e.setRunning(x, true)
	e.srv.serve("x", "x-v1")

	syncOnce(context.Background(), newTestCLICommand())

	assert.Empty(t, *e.restarts, "resumed without a restart")
	assert.Empty(t, readExtState(t).Pending)
	// The same sync's extensions request already reports the outcome
	reqs := e.srv.recorded()
	require.Len(t, reqs, 1)
	require.Len(t, reqs[0].Status, 1)
	assert.Equal(t, applyOK, reqs[0].Status[0].Result)
}

// Windows cannot overwrite or delete a running executable but can rename it,
// so osctrld moves a replaced or removed extension aside instead
func TestSyncExtensionsWindowsMovesAside(t *testing.T) {
	e := setupExt(t)
	extensionsGOOS = WindowsOS
	x := e.extPath(t, "x")
	assert.True(t, strings.HasSuffix(x, "x.exe"))
	e.setRunning(x, true)

	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	assert.Equal(t, []string{x}, e.autoloadLines(t))
	before, err := os.Stat(x)
	require.NoError(t, err)

	e.srv.serve("x", "x-v2")
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	prev, err := os.Stat(x + ".prev")
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, prev), "the running file was renamed, not rewritten")
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	assert.NoFileExists(t, x+".prev")

	before, err = os.Stat(x)
	require.NoError(t, err)
	e.srv.serve()
	changed, err = syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	prev, err = os.Stat(x + ".prev")
	require.NoError(t, err)
	assert.True(t, os.SameFile(before, prev), "a removed extension is renamed aside until osquery restarted")
	assert.Empty(t, e.autoloadLines(t))
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	assert.NoFileExists(t, x+".prev")
	assert.Empty(t, tempLeftovers(t, e.dir))
}

func TestIsExtensionRunningMatchesExe(t *testing.T) {
	prevExes, prevGOOS := processExes, extensionsGOOS
	t.Cleanup(func() { processExes, extensionsGOOS = prevExes, prevGOOS })

	tests := []struct {
		name, goos, exe, path string
		want                  bool
	}{
		{"same", "linux", "/opt/ext/x.ext", "/opt/ext/x.ext", true},
		{"cleaned", "linux", "/opt/ext/x.ext", "/opt/ext/../ext//x.ext", true},
		{"case differs posix", "linux", "/opt/ext/X.ext", "/opt/ext/x.ext", false},
		{"other file", "linux", "/opt/ext/y.ext", "/opt/ext/x.ext", false},
		{"prefix only", "linux", "/opt/ext/x.ext.prev", "/opt/ext/x.ext", false},
		{"case differs windows", WindowsOS, `C:\Program Files\osquery\Extensions\X.EXE`, `c:\program files\osquery\extensions\x.exe`, true},
		{"other file windows", WindowsOS, `C:\osquery\y.exe`, `C:\osquery\x.exe`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extensionsGOOS = tt.goos
			processExes = func() ([]string, error) { return []string{"/sbin/launchd", tt.exe}, nil }
			got, err := isExtensionRunning(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	processExes = func() ([]string, error) { return nil, errors.New("boom") }
	_, err := isExtensionRunning("/opt/ext/x.ext")
	assert.Error(t, err)
}

func TestExtStateCorrupt(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{not json"), 0600))
	for _, path := range []string{corrupt, filepath.Join(dir, "missing.json"), dir} {
		st := loadExtState(path)
		assert.Empty(t, st.Installed)
		assert.Empty(t, st.Pending)
		assert.NotNil(t, st.Installed, "maps are ready to use")
		assert.NotNil(t, st.Rejected)
	}

	prev := appConfig
	t.Cleanup(func() { appConfig = prev })
	appConfig.OsqueryFlagFile = "/etc/osquery/osquery.flags"
	assert.Equal(t, "/etc/osquery/osquery.flags.osctrld-extensions-state.json", extStatePath())
}

// The autoload path comes from served flags and osctrld writes it as root, so
// it must not name a file osctrld or osquery depend on, or a loose directory
func TestAutoloadPathRefused(t *testing.T) {
	e := setupExt(t)
	appConfig.OsquerySecretFile = filepath.Join(filepath.Dir(e.autoload), "osquery.secret")
	appConfig.OsqueryCertFile = filepath.Join(filepath.Dir(e.autoload), "osctrl.crt")
	for _, p := range []string{appConfig.OsquerySecretFile, appConfig.OsqueryCertFile} {
		require.NoError(t, os.WriteFile(p, []byte("keep"), 0600))
	}
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{}))
	require.NoError(t, saveExtState(extStatePath(), extState{}))
	hardlink := filepath.Join(filepath.Dir(e.autoload), "hardlink.load")
	require.NoError(t, os.Link(appConfig.OsqueryFlagFile, hardlink))
	require.NoError(t, os.MkdirAll(e.dir, 0755))

	refused := map[string]string{
		"flagfile":           appConfig.OsqueryFlagFile,
		"flagfile uncleaned": filepath.Dir(appConfig.OsqueryFlagFile) + "/./" + filepath.Base(appConfig.OsqueryFlagFile),
		"hardlink":           hardlink,
		"secret":             appConfig.OsquerySecretFile,
		"cert":               appConfig.OsqueryCertFile,
		"flags state":        flagsStatePath(),
		"extensions state":   extStatePath(),
		"extensions dir":     filepath.Join(e.dir, "x.ext"),
		"relative":           "extensions.load",
	}
	for name, path := range refused {
		t.Run(name, func(t *testing.T) {
			before, _ := os.ReadFile(path)
			assert.Error(t, writeAutoload(path, []string{"/e/x.ext"}, nil))
			after, _ := os.ReadFile(path)
			assert.Equal(t, before, after, "left alone")
		})
	}

	t.Run("loose directory", func(t *testing.T) {
		fakeDirSafe(t, false)
		assert.Error(t, writeAutoload(e.autoload, []string{"/e/x.ext"}, nil))
		assert.NoFileExists(t, e.autoload)
	})

	t.Run("step skips changes and reports", func(t *testing.T) {
		require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile,
			[]byte(testOverrideFlags+"\n--extensions_autoload="+appConfig.OsquerySecretFile), 0700))
		e.srv.serve("x", "x-v1")
		changed, err := syncExtensionsStep(context.Background())
		assert.Error(t, err)
		assert.False(t, changed)
		assert.NoFileExists(t, e.extPath(t, "x"))
		b, err := os.ReadFile(appConfig.OsquerySecretFile)
		require.NoError(t, err)
		assert.Equal(t, "keep", string(b))
		st := readExtState(t)
		assert.Empty(t, st.Installed)
		assert.Empty(t, st.Pending)
		s := statusFor(st, "x")
		require.NotNil(t, s)
		assert.Equal(t, applyRejected, s.Result)
		assert.Contains(t, s.Error, "autoload")
	})
}

func TestWriteAutoloadKeepsMode(t *testing.T) {
	fakeSetOwner(t)
	fakeDirSafe(t, true)
	dir := t.TempDir()
	fakeOsqueryPath(t, dir)
	path := filepath.Join(dir, "extensions.load")
	require.NoError(t, os.WriteFile(path, []byte("/opt/a.ext\n"), 0600))
	require.NoError(t, os.Chmod(path, 0640))
	require.NoError(t, writeAutoload(path, []string{"/e/d.ext"}, nil))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), info.Mode().Perm())
}

// osctrld's autoload lines are reconciled every sync: a moved or edited
// autoload file is fixed, and osquery restarted and checked
func TestAutoloadDriftRepaired(t *testing.T) {
	e := setupExt(t)
	x := e.extPath(t, "x")
	e.setRunning(x, true)
	require.NoError(t, os.WriteFile(e.autoload, []byte("/opt/operator.ext\n"), 0644))
	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	assert.Equal(t, e.autoload, readExtState(t).Autoload)

	// The flags move the autoload file: lines follow, the old file keeps only
	// the operator's lines
	moved := filepath.Join(filepath.Dir(e.autoload), "moved.load")
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile,
		[]byte(testOverrideFlags+"\n--extensions_autoload="+moved), 0700))
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	assert.True(t, changed, "needs a restart and a check")
	b, err := os.ReadFile(moved)
	require.NoError(t, err)
	assert.Equal(t, x+"\n", string(b))
	assert.Equal(t, []string{"/opt/operator.ext"}, e.autoloadLines(t))
	assert.Equal(t, moved, readExtState(t).Autoload)
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	assert.Equal(t, applyOK, statusFor(readExtState(t), "x").Result)
	assert.FileExists(t, x)

	// Deleted behind osctrld's back: written again
	require.NoError(t, os.Remove(moved))
	assert.True(t, e.stepAndVerify(t))
	b, err = os.ReadFile(moved)
	require.NoError(t, err)
	assert.Equal(t, x+"\n", string(b))

	// In place: nothing to do
	assert.False(t, e.stepAndVerify(t))
	assert.Empty(t, *e.restarts)
}

// Environment admins edit flags, so the autoload path may only name a .load
// file directly in osquery's base directory, never e.g. /etc/sudoers
func TestAutoloadPathOutsideBase(t *testing.T) {
	e := setupExt(t)
	base := filepath.Dir(e.autoload)
	require.NoError(t, os.MkdirAll(filepath.Join(base, "sub"), 0755))
	for _, path := range []string{
		"/etc/ld.so.preload",
		"/etc/sudoers",
		filepath.Join(base, "sub", "x.load"),
		filepath.Join(base, "x.txt"),
		filepath.Join(base, "x.load.txt"),
		"/tmp/x.load",
	} {
		t.Run(path, func(t *testing.T) {
			before, _ := os.ReadFile(path)
			assert.Error(t, writeAutoload(path, []string{"/e/x.ext"}, nil))
			after, _ := os.ReadFile(path)
			assert.Equal(t, before, after, "left alone")
		})
	}

	custom := filepath.Join(base, "custom.load")
	require.NoError(t, writeAutoload(custom, []string{"/e/x.ext"}, nil))
	assert.FileExists(t, custom)

	appConfig.OsqueryPath = ""
	assert.Error(t, checkAutoloadPath(custom), "no base directory configured, nothing accepted")

	// Windows paths are case-insensitive
	appConfig.OsqueryPath = "/Program Files/Osquery/"
	assert.Error(t, checkAutoloadPath("/program files/osquery/Custom.LOAD"))
	extensionsGOOS = WindowsOS
	assert.NoError(t, checkAutoloadPath("/program files/osquery/Custom.LOAD"))
	assert.Error(t, checkAutoloadPath("/program files/osquery/sub/custom.load"))
}

// A refused autoload path is reported for every served extension, once per path
func TestRefusedAutoloadReportedOnce(t *testing.T) {
	e := setupExt(t)
	x, y := e.extPath(t, "x"), e.extPath(t, "y")
	e.setRunning(x, true)
	e.setRunning(y, true)
	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	_, err := syncExtensionsStep(context.Background()) // sends and clears x's ok
	require.NoError(t, err)

	e.srv.serve("x", "x-v1", "y", "y-v1")
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(e.flagfile("--extensions_autoload=/etc/sudoers")), 0700))
	for i := 0; i < 3; i++ {
		changed, err := syncExtensionsStep(context.Background())
		assert.Error(t, err)
		assert.False(t, changed)
	}
	assert.NoFileExists(t, y)
	reqs := e.srv.recorded()
	require.Len(t, reqs, 5)
	assert.Empty(t, reqs[2].Status)
	require.Len(t, reqs[3].Status, 2, "every served extension, installed or not")
	for _, st := range reqs[3].Status {
		assert.Equal(t, applyRejected, st.Result)
		assert.Contains(t, st.Error, "/etc/sudoers")
	}
	assert.Empty(t, reqs[4].Status, "not repeated for the same path")
	assert.Equal(t, "/etc/sudoers", readExtState(t).RefusedAutoload)

	// Fixed: the normal flow resumes and the memory is cleared
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(e.flagfile("")), 0700))
	assert.True(t, e.stepAndVerify(t))
	assert.FileExists(t, y)
	assert.Equal(t, []string{x, y}, e.autoloadLines(t))
	assert.Empty(t, readExtState(t).RefusedAutoload)
}

// An update whose process never runs puts the last good version back instead
// of leaving the host without the extension
func TestVerifyExtensionsUpdateFailsKeepsPrevious(t *testing.T) {
	e := setupExt(t)
	x := e.extPath(t, "x")
	e.setRunning(x, true)
	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))

	e.setRunning(x, false)
	e.srv.serve("x", "x-v2")
	assert.True(t, e.stepAndVerify(t))

	b, err := os.ReadFile(x)
	require.NoError(t, err)
	assert.Equal(t, "x-v1", string(b), "the last good version is back")
	assert.NoFileExists(t, x+".prev")
	assert.Equal(t, []string{x}, e.autoloadLines(t))
	assert.Len(t, *e.restarts, 1, "one restart with the last good version")
	st := readExtState(t)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, st.Installed)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v2")}, st.Rejected)
	assert.Equal(t, []string{x}, st.Lines)
	assert.Empty(t, st.Pending)
	assert.Empty(t, st.Previous)
	s := statusFor(st, "x")
	require.NotNil(t, s)
	assert.Equal(t, applyRejected, s.Result)
	assert.Equal(t, sha256Hex("x-v2"), s.SHA256)
	assert.Equal(t, extProcessDownError(), s.Error)
	assert.Empty(t, tempLeftovers(t, e.dir))

	// v2 still served: nothing changes, v1 keeps running
	e.setRunning(x, true)
	*e.restarts = nil
	assert.False(t, e.stepAndVerify(t))
	b, err = os.ReadFile(x)
	require.NoError(t, err)
	assert.Equal(t, "x-v1", string(b))
	assert.Equal(t, []string{x}, e.autoloadLines(t))
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, readExtState(t).Installed)
	assert.Empty(t, *e.restarts)
}

// A status error is capped so a long path cannot grow the request
func TestStatusErrorCapped(t *testing.T) {
	long := strings.Repeat("é", 200) // 400 bytes
	s := newStatus("x", sha256Hex("x"), applyRejected, long)
	assert.LessOrEqual(t, len(s.Error), maxStatusError)
	assert.True(t, utf8.ValidString(s.Error), "cut on a rune boundary")
	assert.True(t, strings.HasPrefix(long, s.Error))
	assert.Equal(t, "short", newStatus("x", "", applyOK, "short").Error)
}

// Only the newest statuses are sent, so the request stays under osctrl-tls's
// 16 KiB body limit
func TestStatusCountCapped(t *testing.T) {
	e := setupExt(t)
	var queued []ExtensionStatus
	for i := 0; i < 100; i++ {
		queued = append(queued, newStatus(fmt.Sprintf("s%03d", i), sha256Hex("x"), applyRejected, "e"))
	}
	require.NoError(t, saveExtState(extStatePath(), extState{Status: queued}))
	_, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	reqs := e.srv.recorded()
	require.Len(t, reqs, 1)
	require.Len(t, reqs[0].Status, maxStatusPerRequest)
	assert.Equal(t, "s099", reqs[0].Status[maxStatusPerRequest-1].Name, "the newest are kept")
	assert.Equal(t, fmt.Sprintf("s%03d", 100-maxStatusPerRequest), reqs[0].Status[0].Name)
	assert.Empty(t, readExtState(t).Status)

	// The largest request osctrld sends fits the body limit
	full := ExtensionsRequest{OsctrlSecret: strings.Repeat("s", 64), UUID: strings.Repeat("u", 36), Platform: "windows", Arch: "arm64"}
	for i := 0; i < maxStatusPerRequest; i++ {
		full.Status = append(full.Status, newStatus(strings.Repeat("n", 64), sha256Hex("x"), applyRejected, strings.Repeat("e", 1000)))
	}
	b, err := json.Marshal(full)
	require.NoError(t, err)
	assert.Less(t, len(b), 16*1024)
}

// osctrl refusing the request as malformed (400) or too large (413) drops the
// queued status, which would otherwise be refused forever; 401/403 (e.g. a
// rotated secret), network errors and 5xx keep it
func TestStatusDroppedOnClientError(t *testing.T) {
	queued := []ExtensionStatus{newStatus("x", sha256Hex("x-v1"), applyOK, "")}
	for _, tt := range []struct {
		name string
		code int
		keep bool
	}{
		{"too large", http.StatusRequestEntityTooLarge, false},
		{"bad request", http.StatusBadRequest, false},
		{"unauthorized", http.StatusUnauthorized, true},
		{"forbidden", http.StatusForbidden, true},
		{"server error", http.StatusInternalServerError, true},
		{"bad gateway", http.StatusBadGateway, true},
		{"network error", -1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := setupExt(t)
			require.NoError(t, saveExtState(extStatePath(), extState{Status: queued}))
			if tt.code == -1 {
				down := httptest.NewServer(http.NotFoundHandler())
				down.Close()
				osctrlURLs.Extensions = down.URL
			} else {
				e.srv.listCode = tt.code
			}
			_, err := syncExtensionsStep(context.Background())
			assert.Error(t, err)
			if tt.keep {
				assert.Len(t, readExtState(t).Status, 1)
			} else {
				assert.Empty(t, readExtState(t).Status)
			}
		})
	}
}

// A removal undone because the autoload file could not be written leaves the
// extension installed and is reported as kept
func TestRemovalAutoloadFailsKept(t *testing.T) {
	e := setupExt(t)
	x := e.extPath(t, "x")
	e.setRunning(x, true)
	e.srv.serve("x", "x-v1")
	assert.True(t, e.stepAndVerify(t))
	setOwner = func(path string) error {
		if strings.Contains(filepath.Base(path), "extensions.load.tmp-") {
			return errors.New("chown refused")
		}
		return nil
	}

	e.srv.serve()
	_, err := syncExtensionsStep(context.Background())
	require.Error(t, err)
	assert.FileExists(t, x)
	st := readExtState(t)
	assert.Equal(t, map[string]string{"x": sha256Hex("x-v1")}, st.Installed)
	s := statusFor(st, "x")
	require.NotNil(t, s)
	assert.Equal(t, applyKept, s.Result)
	assert.Equal(t, sha256Hex("x-v1"), s.SHA256)
	assert.Contains(t, s.Error, "chown refused")
}

// Only the newest status per name is sent, before the count cap applies
func TestStatusDeduped(t *testing.T) {
	e := setupExt(t)
	var queued []ExtensionStatus
	for i := 0; i < 100; i++ {
		queued = append(queued, newStatus("x", sha256Hex("x"), applyRejected, fmt.Sprintf("e%d", i)))
	}
	queued = append(queued, newStatus("y", sha256Hex("y"), applyOK, ""), newStatus("x", sha256Hex("x"), applyKept, "last"))
	require.NoError(t, saveExtState(extStatePath(), extState{Status: queued}))
	_, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	reqs := e.srv.recorded()
	require.Len(t, reqs, 1)
	require.Len(t, reqs[0].Status, 2)
	assert.Equal(t, "y", reqs[0].Status[0].Name)
	assert.Equal(t, "x", reqs[0].Status[1].Name)
	assert.Equal(t, applyKept, reqs[0].Status[1].Result, "the newest wins")
	assert.Equal(t, "last", reqs[0].Status[1].Error)
}

// The autoload path is used as validated: <base>/x/../extensions.load names
// <base>/extensions.load even when x is a symlink elsewhere
func TestAutoloadCleanedPath(t *testing.T) {
	e := setupExt(t)
	base := filepath.Dir(e.autoload)
	elsewhere := filepath.Join(t.TempDir(), "a", "b")
	require.NoError(t, os.MkdirAll(elsewhere, 0755))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(base, "x")))
	spelled := base + "/x/../extensions.load"
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags+"\n--extensions_autoload="+spelled), 0700))
	y := e.extPath(t, "y")
	e.setRunning(y, true)

	e.srv.serve("y", "y-v1")
	assert.True(t, e.stepAndVerify(t))
	assert.Equal(t, []string{y}, e.autoloadLines(t))
	assert.NoFileExists(t, filepath.Join(filepath.Dir(elsewhere), "extensions.load"))
	assert.Equal(t, e.autoload, readExtState(t).Autoload, "stored cleaned")

	// Another spelling of the same file changes nothing
	require.NoError(t, os.WriteFile(appConfig.OsqueryFlagFile, []byte(testOverrideFlags+"\n--extensions_autoload="+base+"//extensions.load"), 0700))
	assert.False(t, e.stepAndVerify(t))
	assert.Empty(t, *e.restarts)
}

var rollbackEventIDRe = regexp.MustCompile(`^[0-9]+:[0-9a-f]{64}$`)

// rollbackFixture leaves x and y pending with osqueryd down, so the check ends in a rollback restart
func rollbackFixture(t *testing.T, osqueryd func() (bool, error)) *extEnv {
	t.Helper()
	e := setupExt(t)
	e.srv.serve("x", "x-v1", "y", "y-v1")
	e.setRunning(e.extPath(t, "x"), true)
	changed, err := syncExtensionsStep(context.Background())
	require.NoError(t, err)
	require.True(t, changed)
	osquerydRunning = osqueryd
	return e
}

func TestExtensionsRollbackRestartIsVerified(t *testing.T) {
	e := rollbackFixture(t, neverRunning)
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	assert.Len(t, *e.restarts, 1, "the rollback restart is not repeated")
	st := readExtState(t)
	require.NotNil(t, st.Rollback)
	assert.Equal(t, stageExhausted, st.Rollback.Stage)
	assert.Regexp(t, rollbackEventIDRe, st.Rollback.EventID)
	assert.True(t, strings.HasSuffix(st.Rollback.EventID, ":"+sha256Hex("x-v1")), "smallest rejected name")
}

func TestExtensionsRollbackRestored(t *testing.T) {
	var e *extEnv
	// osqueryd is down until the rollback restart happens
	e = rollbackFixture(t, func() (bool, error) { return len(*e.restarts) > 0, nil })
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	st := readExtState(t)
	require.NotNil(t, st.Rollback)
	assert.Equal(t, stageRestored, st.Rollback.Stage)
	assert.Regexp(t, rollbackEventIDRe, st.Rollback.EventID)
	assert.Len(t, *e.restarts, 1)
}

func TestExtensionsOKHasNoRollbackEvent(t *testing.T) {
	e := rollbackFixture(t, neverRunning)
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	require.NotNil(t, readExtState(t).Rollback)

	osquerydRunning = func() (bool, error) { return true, nil }
	e.setRunning(e.extPath(t, "y"), true)
	e.srv.serve("x", "x-v1", "y", "y-v2")
	assert.True(t, e.stepAndVerify(t))
	assert.Nil(t, readExtState(t).Rollback, "a clean check clears the event")
}

func TestExtensionsExhaustedDoesNotRestartAgain(t *testing.T) {
	e := rollbackFixture(t, neverRunning)
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	require.NoError(t, verifyExtensionsAfterRestart(context.Background()))
	assert.Len(t, *e.restarts, 1)
	assert.Equal(t, stageExhausted, readExtState(t).Rollback.Stage)
}
