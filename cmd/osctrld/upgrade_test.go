package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	upTarget   = "5.13.0"
	upPrevious = "5.12.1"
	upReq1     = "0123456789abcdef0123456789abcdef"
	upReq2     = "fedcba9876543210fedcba9876543210"
)

var (
	upTargetBody   = []byte("osquery package " + upTarget)
	upPreviousBody = []byte("osquery package " + upPrevious)
)

// upgradeHarness fakes the host (osqueryd, the package manager, the config
// files), the package server and the osctrl route for one upgrade test
type upgradeHarness struct {
	t       *testing.T
	dir     string
	tmp     string
	files   map[string]os.FileMode // config file path → mode
	before  map[string][]byte      // config file path → content before the upgrade
	owners  *[]string
	owner   map[string]fileOwnerIDs // config file path → owner before the upgrade
	chowns  []string                // "path uid:gid" handed to lchownPath
	pkgHits int

	mu           sync.Mutex
	events       []string
	installed    string
	running      bool
	pkgs         map[string][]byte                   // version → served body
	failInstall  map[string]bool                     // version → installer fails
	runsAfter    func(installed string) bool         // osqueryd survives a start
	reported     func(installed string) string       // what osctrl reports
	onInstall    func(h *upgradeHarness, ver string) // extra install side effect
	routeHook    func()
	resolve      func(req upgradeRequest) upgradeResolution // route answer, ahead_of_target when nil
	routeHits    int
	badSignature bool
	startConfigs [][]byte // flagfile content at every start
}

func (h *upgradeHarness) event(e string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, e)
}

func (h *upgradeHarness) recorded() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.events...)
}

func (h *upgradeHarness) flagfile() string { return filepath.Join(h.dir, "osquery.flags") }

func (h *upgradeHarness) res() upgradeResolution {
	return upgradeResolution{
		Source:    "environment",
		RequestID: upReq1,
		Target:    &upgradeRef{Version: upTarget, SHA256: sha256Hex(string(upTargetBody))},
		Previous:  &upgradeRef{Version: upPrevious, SHA256: sha256Hex(string(upPreviousBody))},
	}
}

func (h *upgradeHarness) versionOf(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for v, body := range map[string][]byte{upTarget: upTargetBody, upPrevious: upPreviousBody} {
		if string(b) == string(body) {
			return v
		}
	}
	return "garbage"
}

// install simulates the package: it overwrites the packaged config with its
// defaults and starts osqueryd, as some packages do
func (h *upgradeHarness) install(path string, downgrade bool) *exec.Cmd {
	h.checkInstallOrder(downgrade)
	ver := h.versionOf(path)
	if downgrade {
		h.event("downgrade:" + ver)
	} else {
		h.event("install:" + ver)
	}
	h.mu.Lock()
	fail := h.failInstall[ver]
	h.mu.Unlock()
	if fail {
		return exec.Command("false")
	}
	for p := range h.files {
		require.NoError(h.t, os.WriteFile(p, []byte("packaged default"), 0644))
		require.NoError(h.t, os.Chmod(p, 0644))
	}
	if h.onInstall != nil {
		h.onInstall(h, ver)
	}
	h.mu.Lock()
	h.installed, h.running = ver, true
	h.mu.Unlock()
	return exec.Command("true")
}

func setupUpgrade(t *testing.T) *upgradeHarness {
	t.Helper()
	dir := t.TempDir()
	h := &upgradeHarness{
		t:           t,
		dir:         dir,
		tmp:         tempPackages(t),
		installed:   upPrevious,
		running:     true,
		pkgs:        map[string][]byte{upTarget: upTargetBody, upPrevious: upPreviousBody},
		failInstall: map[string]bool{},
		runsAfter:   func(string) bool { return true },
		reported:    func(installed string) string { return installed },
	}
	autoload := filepath.Join(dir, "extensions.load")
	h.files = map[string]os.FileMode{
		h.flagfile():                   0640,
		filepath.Join(dir, "secret"):   0600,
		filepath.Join(dir, "cert.pem"): 0604,
		autoload:                       0644,
	}
	contents := map[string]string{
		h.flagfile():                   "--tls_hostname=osctrl.example.com\n--extensions_autoload=" + autoload + "\n",
		filepath.Join(dir, "secret"):   "s3cret",
		filepath.Join(dir, "cert.pem"): "CERT",
		autoload:                       filepath.Join(dir, "ext", "a.ext") + "\n",
	}
	h.before = map[string][]byte{}
	for p, m := range h.files {
		require.NoError(t, os.WriteFile(p, []byte(contents[p]), m))
		require.NoError(t, os.Chmod(p, m))
		h.before[p] = []byte(contents[p])
	}
	h.owner = map[string]fileOwnerIDs{}
	for p := range h.files {
		fi, err := os.Lstat(p)
		require.NoError(t, err)
		if o, ok := fileOwner(fi); ok {
			h.owner[p] = *o
		}
	}
	require.NoError(t, os.Mkdir(filepath.Join(dir, "ext"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ext", "a.ext"), []byte("ext a"), 0755))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := strings.CutPrefix(r.URL.Path, "/pkg/"); ok {
			h.mu.Lock()
			h.pkgHits++
			body, found := h.pkgs[v]
			h.mu.Unlock()
			if !found {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
			return
		}
		if r.URL.Path == "/env/osctrld-osquery" {
			var req upgradeRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if h.routeHook != nil {
				h.routeHook()
			}
			h.mu.Lock()
			h.routeHits++
			rep := h.reported(h.installed)
			resolve := h.resolve
			h.mu.Unlock()
			res := upgradeResolution{Reason: "ahead_of_target", ReportedVersion: rep}
			if resolve != nil {
				res = resolve(req)
				res.ReportedVersion = rep
			}
			_ = json.NewEncoder(w).Encode(res)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	prevCfg, prevURLs := appConfig, osctrlURLs
	appConfig = Configuration{
		OsctrlSecret:      "S",
		OsqueryFlagFile:   h.flagfile(),
		OsquerySecretFile: filepath.Join(dir, "secret"),
		OsqueryCertFile:   filepath.Join(dir, "cert.pem"),
		ExtensionsDir:     filepath.Join(dir, "ext"),
		OsqueryPath:       dir,
	}
	osctrlURLs = genURLs(srv.URL, "env", false)
	require.NoError(t, saveFlagsState(flagsStatePath(), flagsState{HostUUID: "U"}))

	pg, pa := upgradeGOOS, upgradeGOARCH
	pFormat, pURL, pStop, pStart := upgradePackageFormat, upgradePackageURL, upgradeStopOsquery, upgradeStartOsquery
	pReader, pRunning, pExec, pChown, pBackoff := osqueryVersionReader, osquerydRunning, execCommand, lchownPath, upgradeSkipBackoff
	pTimeout, pInterval, pWindow, pConfirm := restartCheckTimeout, restartCheckInterval, upgradeConfirmWindow, upgradeConfirmInterval
	t.Cleanup(func() {
		appConfig, osctrlURLs = prevCfg, prevURLs
		upgradeGOOS, upgradeGOARCH = pg, pa
		upgradePackageFormat, upgradePackageURL, upgradeStopOsquery, upgradeStartOsquery = pFormat, pURL, pStop, pStart
		osqueryVersionReader, osquerydRunning, execCommand, lchownPath, upgradeSkipBackoff = pReader, pRunning, pExec, pChown, pBackoff
		restartCheckTimeout, restartCheckInterval, upgradeConfirmWindow, upgradeConfirmInterval = pTimeout, pInterval, pWindow, pConfirm
	})
	upgradeGOOS, upgradeGOARCH = LinuxOS, "amd64"
	upgradePackageFormat = func() (packageFormat, error) { return pkgRPM, nil }
	upgradePackageURL = func(_ packageFormat, version, _ string) (string, error) { return srv.URL + "/pkg/" + version, nil }
	lchownPath = func(path string, uid, gid int) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.chowns = append(h.chowns, fmt.Sprintf("%s %d:%d", path, uid, gid))
		return nil
	}
	upgradeStopOsquery = func() error {
		h.checkStopOrder()
		h.event("stop")
		h.mu.Lock()
		h.running = false
		h.mu.Unlock()
		return nil
	}
	upgradeStartOsquery = func() error {
		h.event("start")
		b, _ := os.ReadFile(h.flagfile())
		h.mu.Lock()
		h.startConfigs = append(h.startConfigs, b)
		h.running = h.runsAfter(h.installed)
		h.mu.Unlock()
		return nil
	}
	osqueryVersionReader = func() string {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.installed
	}
	osquerydRunning = func() (bool, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.running, nil
	}
	execCommand = func(name string, args ...string) *exec.Cmd {
		switch name {
		case "rpm":
			return h.install(args[len(args)-1], len(args) > 0 && args[1] == "--oldpackage")
		case "msiexec":
			return h.install(args[1], false)
		case "pkgutil", "powershell":
			h.event("sigcheck")
			if h.badSignature {
				return exec.Command("false")
			}
			return exec.Command("true")
		case "installer":
			return h.install(args[1], false)
		}
		h.event("exec:" + name)
		return exec.Command("false")
	}
	restartCheckTimeout, restartCheckInterval = 100*time.Millisecond, time.Millisecond
	upgradeConfirmWindow, upgradeConfirmInterval = 60*time.Millisecond, 2*time.Millisecond
	h.owners = fakeSetOwner(t)
	fakeDirSafe(t, true)
	resetHealth(t)
	return h
}

// checkStopOrder asserts what must be saved before osquery is stopped: the
// snapshot and the pending marker, not installed before the first install,
// installed right after a successful one
func (h *upgradeHarness) checkStopOrder() {
	t := h.t
	assert.FileExists(t, snapshotPath(), "snapshot saved before any stop")
	st := h.state()
	if !assert.NotNil(t, st.Pending, "pending marker saved before any stop") {
		return
	}
	ev := h.recorded()
	switch {
	case len(ev) == 0 && st.Pending.Rollback == "":
		assert.False(t, st.Pending.Installed, "first stop: marker not installed yet")
	case len(ev) > 0 && ev[len(ev)-1] == "install:"+upTarget && !h.failInstall[upTarget]:
		assert.True(t, st.Pending.Installed, "Installed saved before the stop after the install")
	}
}

// checkInstallOrder asserts the marker and snapshot are saved before an
// install, and the rollback reason before a downgrade
func (h *upgradeHarness) checkInstallOrder(downgrade bool) {
	t := h.t
	assert.FileExists(t, snapshotPath(), "snapshot saved before any install")
	st := h.state()
	if !assert.NotNil(t, st.Pending, "pending marker saved before any install") {
		return
	}
	if downgrade {
		assert.NotEmpty(t, st.Pending.Rollback, "rollback reason saved before the downgrade")
	} else {
		assert.False(t, st.Pending.Installed)
		assert.Empty(t, st.Pending.Rollback)
	}
}

// assertConfigIntact checks every config file is byte-identical to before
// the upgrade, with its mode, and was handed to setOwner
func (h *upgradeHarness) assertConfigIntact(t *testing.T) {
	t.Helper()
	for p, m := range h.files {
		b, err := os.ReadFile(p)
		require.NoError(t, err)
		assert.Equal(t, string(h.before[p]), string(b), p)
		fi, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, m, fi.Mode().Perm(), p)
		if o, ok := h.owner[p]; ok {
			assert.Contains(t, h.chowns, fmt.Sprintf("%s %d:%d", p, o.UID, o.GID), "original owner restored")
		} else {
			assert.Contains(t, *h.owners, p)
		}
	}
	for _, c := range h.startConfigs {
		assert.Equal(t, string(h.before[h.flagfile()]), string(c), "osqueryd must never start with packaged defaults")
	}
}

// assertNoPackages checks no downloaded or stashed package is left behind
func (h *upgradeHarness) assertNoPackages(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(h.tmp)
	require.NoError(t, err)
	assert.Empty(t, entries, "temporary downloads left behind")
	_, err = os.Lstat(upgradeDir())
	assert.True(t, os.IsNotExist(err), "upgrade directory left behind")
}

func (h *upgradeHarness) state() upgradeState { return loadUpgradeState(upgradeStatePath()) }

func TestUpgradeHappyPathKeepsFlagsAndConfirms(t *testing.T) {
	h := setupUpgrade(t)
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "ok", r.Result)
	assert.Equal(t, upTarget, r.Version)
	assert.Equal(t, upReq1, r.RequestID)
	assert.Empty(t, r.Reason)
	assert.Empty(t, r.EventID)
	// stop → install → (stop the package's osqueryd) → restore → start
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start"}, h.recorded())
	h.assertConfigIntact(t)
	h.assertNoPackages(t)
	st := h.state()
	assert.Nil(t, st.Pending)
	assert.Nil(t, st.Rejected)
	require.NotNil(t, st.Last)
	assert.Equal(t, r, *st.Last)
	require.NotNil(t, verified)
	assert.True(t, *verified)
}

func TestUpgradeHappyPathClearsEarlierRejection(t *testing.T) {
	h := setupUpgrade(t)
	require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Rejected: &rejectedUpgrade{Version: "5.11.0", SHA256: strings.Repeat("a", 64), RequestID: upReq2}}))
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "ok", r.Result)
	assert.Nil(t, h.state().Rejected)
}

func TestUpgradeRefusesWithoutDigestOrOnMismatch(t *testing.T) {
	t.Run("no digest", func(t *testing.T) {
		h := setupUpgrade(t)
		res := h.res()
		res.Target.SHA256 = ""
		_, err := upgradeOsquery(context.Background(), res)
		require.Error(t, err)
		assert.Empty(t, h.recorded())
		assert.Equal(t, upgradeState{}, h.state())
		h.assertNoPackages(t)
	})
	for _, which := range []string{upTarget, upPrevious} {
		t.Run("mismatch "+which, func(t *testing.T) {
			h := setupUpgrade(t)
			h.pkgs[which] = []byte("tampered")
			r, err := upgradeOsquery(context.Background(), h.res())
			require.NoError(t, err)
			assert.Equal(t, upgradeResult{Result: "skipped", Version: upTarget, Reason: "digest_mismatch", RequestID: upReq1, At: r.At}, r)
			assert.Empty(t, h.recorded(), "no stop, no install")
			st := h.state()
			assert.Equal(t, &r, st.Last)
			assert.Nil(t, st.Rejected, "a skipped target is not remembered as rejected")
			assert.Nil(t, st.Pending)
			h.assertNoPackages(t)
		})
	}
}

func TestUpgradePreviousUnavailableSkipsBeforeTouchingAnything(t *testing.T) {
	for which, reason := range map[string]string{upPrevious: "previous_unavailable", upTarget: "target_unavailable"} {
		t.Run(reason, func(t *testing.T) {
			h := setupUpgrade(t)
			delete(h.pkgs, which)
			r, err := upgradeOsquery(context.Background(), h.res())
			require.NoError(t, err)
			assert.Equal(t, "skipped", r.Result)
			assert.Equal(t, reason, r.Reason)
			assert.Empty(t, h.recorded(), "no stop, no install")
			assert.Nil(t, h.state().Pending)
			h.assertNoPackages(t)
		})
	}
}

func TestUpgradeSignatureFailureSkipsBeforeTouchingAnything(t *testing.T) {
	h := setupUpgrade(t)
	upgradePackageFormat = func() (packageFormat, error) { return pkgPKG, nil }
	h.badSignature = true
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "skipped", r.Result)
	assert.Equal(t, "target_unavailable", r.Reason)
	assert.Equal(t, []string{"sigcheck"}, h.recorded())
	h.assertNoPackages(t)
}

func TestUpgradeMacPackageChecksSignaturesFirst(t *testing.T) {
	h := setupUpgrade(t)
	upgradePackageFormat = func() (packageFormat, error) { return pkgPKG, nil }
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "ok", r.Result)
	assert.Equal(t, []string{"sigcheck", "sigcheck", "stop", "sigcheck", "install:" + upTarget, "stop", "start"}, h.recorded())
}

func assertRejected(t *testing.T, h *upgradeHarness, r upgradeResult, reason string) {
	t.Helper()
	assert.Equal(t, "rejected", r.Result)
	assert.Equal(t, upTarget, r.Version)
	assert.Equal(t, reason, r.Reason)
	assert.Equal(t, upReq1, r.RequestID)
	assert.Regexp(t, eventIDRe, r.EventID)
	assert.True(t, strings.HasSuffix(r.EventID, ":"+h.res().Target.SHA256))
	st := h.state()
	assert.Nil(t, st.Pending)
	require.NotNil(t, st.Last)
	assert.Equal(t, r, *st.Last)
	rr := r
	assert.Equal(t, &rejectedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq1, Result: &rr}, st.Rejected)
	h.assertConfigIntact(t)
	h.assertNoPackages(t)
}

func TestUpgradeRollsBackWhenOsquerydDoesNotStart(t *testing.T) {
	h := setupUpgrade(t)
	h.runsAfter = func(installed string) bool { return installed == upPrevious }
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assertRejected(t, h, r, "osqueryd_not_running")
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start",
		"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded())
	assert.Equal(t, upPrevious, osqueryVersionReader())
	require.NotNil(t, verified)
	assert.True(t, *verified, "osqueryd runs again after the rollback")
}

func TestUpgradeRollsBackWhenVersionNeverReported(t *testing.T) {
	h := setupUpgrade(t)
	h.reported = func(string) string { return upPrevious }
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assertRejected(t, h, r, "version_not_reported")
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start",
		"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded())
}

func TestUpgradeRollbackRestoresConfigOverwrittenByPackage(t *testing.T) {
	h := setupUpgrade(t)
	h.reported = func(string) string { return upPrevious }
	_, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	// both installs overwrote the config; both starts saw it restored
	assert.Len(t, h.startConfigs, 2)
	h.assertConfigIntact(t)
}

func TestUpgradeDetectsExtensionsChange(t *testing.T) {
	h := setupUpgrade(t)
	h.onInstall = func(h *upgradeHarness, ver string) {
		if ver == upTarget {
			require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ext", "packaged.ext"), []byte("x"), 0755))
		}
	}
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assertRejected(t, h, r, "config_changed")
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop",
		"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded(), "never started with a changed extensions directory")
}

func TestUpgradeInstallFailureRestoresAndReports(t *testing.T) {
	// A failed install that left the previous version in place (e.g. the
	// package manager lock was held) is a skip to retry later, not a rejection
	h := setupUpgrade(t)
	h.failInstall[upTarget] = true
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, upgradeResult{Result: "skipped", Version: upTarget, Reason: "install_failed", RequestID: upReq1, At: r.At}, r)
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start"}, h.recorded(), "no downgrade")
	running, _ := osquerydRunning()
	assert.True(t, running, "the osqueryd the upgrade stopped runs again")
	h.assertConfigIntact(t)
	h.assertNoPackages(t)
	st := h.state()
	assert.Nil(t, st.Pending)
	assert.Nil(t, st.Rejected)
	assert.Equal(t, &r, st.Last)
	assert.Equal(t, &skippedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq1, Reason: "install_failed", At: r.At}, st.Skipped)

	hits := h.pkgHits
	r2, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, r, r2)
	assert.Equal(t, hits, h.pkgHits, "retried only after the backoff")
}

func TestUpgradeInstallFailureWithChangedVersionRollsBack(t *testing.T) {
	for _, v := range []string{"", upTarget, "5.0.0"} {
		t.Run("version "+v, func(t *testing.T) {
			h := setupUpgrade(t)
			h.failInstall[upTarget] = true
			osqueryVersionReader = func() string { return v }
			r, err := upgradeOsquery(context.Background(), h.res())
			require.NoError(t, err)
			assertRejected(t, h, r, "install_failed")
			assert.Equal(t, []string{"stop", "install:" + upTarget,
				"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded())
		})
	}
}

func TestUpgradeRollbackInstallErrorIsOnlyLogged(t *testing.T) {
	// rpm --oldpackage of a version that is already installed fails: logged,
	// and the rollback still restores, starts and records the rejection
	h := setupUpgrade(t)
	h.reported = func(string) string { return upPrevious }
	h.failInstall[upPrevious] = true
	logs := captureLogs(t)
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assertRejected(t, h, r, "version_not_reported")
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start",
		"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded())
	assert.Contains(t, logs.String(), "failed to reinstall the previous osquery package")
}

func TestUpgradeLocalFailureIsRemembered(t *testing.T) {
	h := setupUpgrade(t)
	cert := appConfig.OsqueryCertFile
	require.NoError(t, os.Remove(cert))
	require.NoError(t, os.Symlink(filepath.Join(h.dir, "secret"), cert))
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	require.Equal(t, "install_failed", r.Reason)
	assert.Equal(t, "skipped", r.Result)
	hits := h.pkgHits
	require.Positive(t, hits)
	r2, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, r, r2)
	assert.Equal(t, hits, h.pkgHits, "nothing downloaded again within the backoff")
	assert.Empty(t, h.recorded())
}

func TestUpgradeDownloadsVerifyCertificateEvenWhenInsecure(t *testing.T) {
	h := setupUpgrade(t)
	var served int
	var mu sync.Mutex
	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		_, _ = w.Write(h.pkgs[strings.TrimPrefix(r.URL.Path, "/pkg/")])
	}))
	tlsSrv.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
	tlsSrv.StartTLS()
	defer tlsSrv.Close()
	upgradePackageURL = func(_ packageFormat, version, _ string) (string, error) { return tlsSrv.URL + "/pkg/" + version, nil }
	appConfig.Insecure = true
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "skipped", r.Result)
	assert.Equal(t, "target_unavailable", r.Reason, "a self-signed certificate is refused despite --insecure")
	mu.Lock()
	assert.Zero(t, served)
	mu.Unlock()
	assert.Empty(t, h.recorded())
}

func TestUpgradeConfirmDefaults(t *testing.T) {
	assert.Equal(t, 5*time.Minute, upgradeConfirmWindow)
	assert.Equal(t, 30*time.Second, upgradeConfirmInterval)
}

// fakeConfirmWait records every wait between confirmation polls and returns
// almost at once
func fakeConfirmWait(t *testing.T) *[]time.Duration {
	t.Helper()
	waits := &[]time.Duration{}
	prev := upgradeConfirmWait
	upgradeConfirmWait = func(d time.Duration) <-chan time.Time {
		*waits = append(*waits, d)
		return time.After(time.Millisecond)
	}
	t.Cleanup(func() { upgradeConfirmWait = prev })
	return waits
}

// confirmServer answers the osctrl route with answers in turn, repeating the last
func confirmServer(t *testing.T, answers ...func(w http.ResponseWriter)) func() int {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		i := calls
		calls++
		mu.Unlock()
		if i >= len(answers) {
			i = len(answers) - 1
		}
		answers[i](w)
	}))
	t.Cleanup(srv.Close)
	osctrlURLs = genURLs(srv.URL, "env", false)
	return func() int { mu.Lock(); defer mu.Unlock(); return calls }
}

func tooMany(retry string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(http.StatusTooManyRequests)
	}
}

func reports(v string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"reason":"ahead_of_target","reported_version":"` + v + `"}`))
	}
}

func TestConfirmNewVersionHonoursRetryAfter(t *testing.T) {
	t.Run("waits at least Retry-After, then confirms", func(t *testing.T) {
		setupUpgrade(t)
		upgradeConfirmWindow, upgradeConfirmInterval = time.Minute, 2*time.Second
		waits := fakeConfirmWait(t)
		calls := confirmServer(t, tooMany("7"), tooMany("7"), reports(upTarget))
		ok, err := confirmNewVersion(context.Background(), upTarget)
		require.NoError(t, err)
		assert.True(t, ok, "confirmed on the poll after the 429s")
		assert.Equal(t, 3, calls(), "a 429 never counts as confirmation")
		assert.Equal(t, []time.Duration{7 * time.Second, 7 * time.Second}, *waits)
	})
	t.Run("short or missing Retry-After keeps the interval", func(t *testing.T) {
		setupUpgrade(t)
		upgradeConfirmWindow, upgradeConfirmInterval = time.Minute, 3*time.Second
		waits := fakeConfirmWait(t)
		confirmServer(t, tooMany("1"), tooMany(""), reports(upTarget))
		ok, err := confirmNewVersion(context.Background(), upTarget)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, []time.Duration{3 * time.Second, 3 * time.Second}, *waits)
	})
	t.Run("capped by the remaining window", func(t *testing.T) {
		setupUpgrade(t)
		upgradeConfirmWindow, upgradeConfirmInterval = time.Minute, time.Second
		waits := fakeConfirmWait(t)
		confirmServer(t, tooMany("3600"), reports(upTarget))
		ok, err := confirmNewVersion(context.Background(), upTarget)
		require.NoError(t, err)
		assert.True(t, ok)
		require.Len(t, *waits, 1)
		assert.LessOrEqual(t, (*waits)[0], time.Minute)
		assert.Greater(t, (*waits)[0], 50*time.Second)
	})
	t.Run("only 429s for the whole window", func(t *testing.T) {
		setupUpgrade(t)
		upgradeConfirmWindow, upgradeConfirmInterval = 60*time.Millisecond, 10*time.Millisecond
		calls := confirmServer(t, tooMany(""))
		ok, err := confirmNewVersion(context.Background(), upTarget)
		require.NoError(t, err)
		assert.False(t, ok)
		assert.LessOrEqual(t, calls(), 8, "polls bounded by window / interval")
	})
	t.Run("cancel stays prompt during a long Retry-After", func(t *testing.T) {
		setupUpgrade(t)
		upgradeConfirmWindow, upgradeConfirmInterval = time.Minute, time.Millisecond
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		confirmServer(t, func(w http.ResponseWriter) { cancel(); tooMany("30")(w) })
		start := time.Now()
		_, err := confirmNewVersion(ctx, upTarget)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Less(t, time.Since(start), 5*time.Second)
	})
}

func TestUpgradeWrongVersionAfterInstallRollsBack(t *testing.T) {
	h := setupUpgrade(t)
	osqueryVersionReader = func() string { return "5.0.0" }
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "install_failed", r.Reason)
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop",
		"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded())
}

func TestUpgradeRollbackSkipsTamperedPreviousPackage(t *testing.T) {
	h := setupUpgrade(t)
	h.runsAfter = func(installed string) bool { return installed == upPrevious }
	h.onInstall = func(h *upgradeHarness, ver string) {
		p := h.state().Pending
		require.NotNil(t, p)
		require.NoError(t, os.WriteFile(p.PreviousPkg, []byte("tampered"), 0600))
	}
	logs := captureLogs(t)
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assertRejected(t, h, r, "osqueryd_not_running")
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start",
		"stop", "stop", "start"}, h.recorded(), "an unverified previous package is never installed")
	assert.Contains(t, logs.String(), `"level":"error"`)
}

func TestUpgradeRetriesOnlyWithNewRequestId(t *testing.T) {
	h := setupUpgrade(t)
	h.reported = func(string) string { return upPrevious }
	res := h.res()
	_, err := upgradeOsquery(context.Background(), res)
	require.NoError(t, err)
	ok, why := shouldAttempt(res, h.state())
	assert.False(t, ok)
	assert.Equal(t, "rejected", why)
	res.RequestID = upReq2
	ok, _ = shouldAttempt(res, h.state())
	assert.True(t, ok)
}

func TestUpgradeCancelledRecordsNothingAndResumes(t *testing.T) {
	h := setupUpgrade(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.reported = func(string) string { return upPrevious }
	h.routeHook = cancel
	upgradeConfirmWindow = time.Minute
	_, err := upgradeOsquery(ctx, h.res())
	require.ErrorIs(t, err, context.Canceled)
	st := h.state()
	assert.Nil(t, st.Last, "a cancelled upgrade records no outcome")
	require.NotNil(t, st.Pending)
	assert.True(t, st.Pending.Installed)
	assert.FileExists(t, st.Pending.PreviousPkg)
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start"}, h.recorded())
}

func TestResumeUpgradeAfterRestartContinuesVerification(t *testing.T) {
	h := setupUpgrade(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.reported = func(string) string { return upPrevious }
	h.routeHook = cancel
	upgradeConfirmWindow = time.Minute
	_, err := upgradeOsquery(ctx, h.res())
	require.ErrorIs(t, err, context.Canceled)

	// osctrld restarted; osctrl now sees the new version
	h.routeHook = nil
	h.reported = func(installed string) string { return installed }
	upgradeConfirmWindow = 60 * time.Millisecond
	require.NoError(t, resumeUpgrade(context.Background()))
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop", "start", "stop", "start"}, h.recorded())
	st := h.state()
	assert.Nil(t, st.Pending)
	require.NotNil(t, st.Last)
	assert.Equal(t, "ok", st.Last.Result)
	assert.Equal(t, upReq1, st.Last.RequestID)
	h.assertConfigIntact(t)
	h.assertNoPackages(t)
}

func TestResumeUpgradeRestoresConfigBeforeVerifying(t *testing.T) {
	h := setupUpgrade(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.reported = func(string) string { return upPrevious }
	h.routeHook = cancel
	upgradeConfirmWindow = time.Minute
	_, err := upgradeOsquery(ctx, h.res())
	require.ErrorIs(t, err, context.Canceled)
	// the host rebooted half way: packaged defaults are back on disk
	require.NoError(t, os.WriteFile(h.flagfile(), []byte("packaged default"), 0644))
	h.routeHook = nil
	h.reported = func(installed string) string { return installed }
	upgradeConfirmWindow = 60 * time.Millisecond
	require.NoError(t, resumeUpgrade(context.Background()))
	h.assertConfigIntact(t)
	assert.Equal(t, "ok", h.state().Last.Result)
}

func TestResumeUpgradeRollsBackWhenVersionNeverReported(t *testing.T) {
	h := setupUpgrade(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.reported = func(string) string { return upPrevious }
	h.routeHook = cancel
	upgradeConfirmWindow = time.Minute
	_, err := upgradeOsquery(ctx, h.res())
	require.ErrorIs(t, err, context.Canceled)
	h.routeHook = nil
	upgradeConfirmWindow = 60 * time.Millisecond
	require.NoError(t, resumeUpgrade(context.Background()))
	assertRejected(t, h, *h.state().Last, "version_not_reported")
}

// pendingBeforeInstall leaves the state an osctrld that died between the
// pending marker and the install leaves behind
func pendingBeforeInstall(t *testing.T, h *upgradeHarness) {
	t.Helper()
	res := h.res()
	dir, err := ensureUpgradeDir()
	require.NoError(t, err)
	snap, err := snapshotOsqueryConfig()
	require.NoError(t, err)
	require.NoError(t, saveSnapshot(snap))
	prev := filepath.Join(dir, res.Previous.SHA256+".rpm")
	require.NoError(t, os.WriteFile(prev, upPreviousBody, 0600))
	require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Pending: &pendingUpgrade{
		Target: *res.Target, Previous: *res.Previous, PreviousPkg: prev, RequestID: res.RequestID, StartedAt: time.Now()}}))
}

func TestResumeUpgradeClearsMarkerWhenInstallNeverHappened(t *testing.T) {
	t.Run("osqueryd stopped by the upgrade", func(t *testing.T) {
		h := setupUpgrade(t)
		pendingBeforeInstall(t, h)
		h.running = false
		require.NoError(t, resumeUpgrade(context.Background()))
		assert.Equal(t, []string{"start"}, h.recorded(), "only the osqueryd the upgrade stopped is started")
		assert.Equal(t, upgradeState{}, h.state(), "nothing recorded")
		h.assertConfigIntact(t)
		h.assertNoPackages(t)
	})
	t.Run("osqueryd running", func(t *testing.T) {
		h := setupUpgrade(t)
		pendingBeforeInstall(t, h)
		require.NoError(t, resumeUpgrade(context.Background()))
		assert.Empty(t, h.recorded())
		assert.Equal(t, upgradeState{}, h.state())
		h.assertNoPackages(t)
	})
}

func TestResumeUpgradeUnknownVersionRollsBack(t *testing.T) {
	h := setupUpgrade(t)
	pendingBeforeInstall(t, h)
	h.installed, h.running = "", false
	require.NoError(t, resumeUpgrade(context.Background()))
	assert.Equal(t, []string{"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded())
	assertRejected(t, h, *h.state().Last, "install_failed")
}

func TestResumeUpgradeContinuesInterruptedRollback(t *testing.T) {
	h := setupUpgrade(t)
	pendingBeforeInstall(t, h)
	st := h.state()
	st.Pending.Installed, st.Pending.Rollback = true, "osqueryd_not_running"
	require.NoError(t, saveUpgradeState(upgradeStatePath(), st))
	require.NoError(t, resumeUpgrade(context.Background()))
	assertRejected(t, h, *h.state().Last, "osqueryd_not_running")
}

func TestUpgradeLeavesNoTempPackagesBehind(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		h := setupUpgrade(t)
		_, err := upgradeOsquery(context.Background(), h.res())
		require.NoError(t, err)
		h.assertNoPackages(t)
	})
	t.Run("rollback", func(t *testing.T) {
		h := setupUpgrade(t)
		h.runsAfter = func(string) bool { return false }
		_, err := upgradeOsquery(context.Background(), h.res())
		require.NoError(t, err)
		h.assertNoPackages(t)
	})
}

func TestUpgradeNeverRestartsOsquerydOnItsOwnWhenNothingToDo(t *testing.T) {
	for _, goos := range []string{LinuxOS, WindowsOS} {
		t.Run(goos, func(t *testing.T) {
			h := setupUpgrade(t)
			if goos == WindowsOS {
				h.windows()
			}
			h.running = false
			require.NoError(t, resumeUpgrade(context.Background()))
			assert.Empty(t, h.recorded())
			assert.Equal(t, upgradeState{}, h.state())
		})
	}
}

func TestUpgradeRefusesWhileAnotherIsPending(t *testing.T) {
	h := setupUpgrade(t)
	pendingBeforeInstall(t, h)
	_, err := upgradeOsquery(context.Background(), h.res())
	require.Error(t, err)
	assert.Empty(t, h.recorded())
	assert.NotNil(t, h.state().Pending)
}

func TestUpgradeDirRefusesSymlinkAndNonDirectory(t *testing.T) {
	setupUpgrade(t)
	target := t.TempDir()
	require.NoError(t, os.Symlink(target, upgradeDir()))
	assert.Error(t, checkUpgradeDir(true))
	require.NoError(t, os.Remove(upgradeDir()))
	require.NoError(t, os.WriteFile(upgradeDir(), nil, 0600))
	assert.Error(t, checkUpgradeDir(true))
	require.NoError(t, os.Remove(upgradeDir()))
	dir, err := ensureUpgradeDir()
	require.NoError(t, err)
	fi, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), fi.Mode().Perm())
}

func TestConfirmNewVersion(t *testing.T) {
	t.Run("polls until reported", func(t *testing.T) {
		h := setupUpgrade(t)
		calls := 0
		h.reported = func(installed string) string {
			calls++
			if calls < 3 {
				return upPrevious
			}
			return upTarget
		}
		ok, err := confirmNewVersion(context.Background(), upTarget)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("route errors then confirms", func(t *testing.T) {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			switch calls {
			case 1:
				w.WriteHeader(http.StatusInternalServerError)
			case 2:
				http.NotFound(w, r)
			default:
				_, _ = w.Write([]byte(`{"reason":"ahead_of_target","reported_version":"5.13.0"}`))
			}
		}))
		defer srv.Close()
		setupUpgrade(t)
		osctrlURLs = genURLs(srv.URL, "env", false)
		ok, err := confirmNewVersion(context.Background(), upTarget)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, 3, calls)
	})
	t.Run("window ends", func(t *testing.T) {
		h := setupUpgrade(t)
		h.reported = func(string) string { return "5.13" }
		start := time.Now()
		ok, err := confirmNewVersion(context.Background(), upTarget)
		require.NoError(t, err)
		assert.False(t, ok, "plain string equality only")
		assert.Less(t, time.Since(start), 5*time.Second)
	})
	t.Run("cancelled", func(t *testing.T) {
		setupUpgrade(t)
		upgradeConfirmWindow = time.Minute
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ok, err := confirmNewVersion(ctx, upTarget)
		assert.False(t, ok)
		assert.True(t, errors.Is(err, context.Canceled))
	})
}

func TestSnapshotRestoreKeepsMissingFilesMissing(t *testing.T) {
	setupUpgrade(t)
	require.NoError(t, os.Remove(appConfig.OsqueryCertFile))
	snap, err := snapshotOsqueryConfig()
	require.NoError(t, err)
	assert.Len(t, snap.Files, 3)
	require.NoError(t, snap.restore())
	assert.NoFileExists(t, appConfig.OsqueryCertFile)
}

func TestExtensionsListing(t *testing.T) {
	h := setupUpgrade(t)
	l, err := extensionsListing()
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a.ext": sha256Hex("ext a")}, l)
	appConfig.ExtensionsDir = filepath.Join(h.dir, "missing")
	l, err = extensionsListing()
	require.NoError(t, err)
	assert.Empty(t, l)
}

func TestUpgradeCancelledDuringRollbackResumesAsRollback(t *testing.T) {
	h := setupUpgrade(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.runsAfter = func(installed string) bool { return installed == upPrevious }
	h.onInstall = func(_ *upgradeHarness, ver string) {
		if ver == upPrevious {
			cancel()
		}
	}
	_, err := upgradeOsquery(ctx, h.res())
	require.ErrorIs(t, err, context.Canceled)
	st := h.state()
	assert.Nil(t, st.Last, "a cancelled rollback records no outcome")
	require.NotNil(t, st.Pending)
	assert.Equal(t, "osqueryd_not_running", st.Pending.Rollback, "the rollback reason is saved before it starts")

	h.onInstall = nil
	require.NoError(t, resumeUpgrade(context.Background()))
	assertRejected(t, h, *h.state().Last, "osqueryd_not_running")
}

func TestUpgradeSnapshotSkipsUnsafeAutoload(t *testing.T) {
	h := setupUpgrade(t)
	outside := filepath.Join(t.TempDir(), "victim.load")
	require.NoError(t, os.WriteFile(outside, []byte("not osquery's"), 0640))
	require.NoError(t, os.WriteFile(h.flagfile(), []byte("--extensions_autoload="+outside+"\n"), 0640))
	snap, err := snapshotOsqueryConfig()
	require.NoError(t, err)
	for _, f := range snap.Files {
		assert.NotEqual(t, outside, f.Path)
		assert.NotContains(t, string(f.Content), "not osquery's")
	}
	assert.Len(t, snap.Files, 3)
	require.NoError(t, os.WriteFile(outside, []byte("changed since"), 0600))
	require.NoError(t, os.Chmod(outside, 0600))
	require.NoError(t, snap.restore())
	b, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, "changed since", string(b), "restore never rewrites an unchecked autoload path")
	fi, err := os.Stat(outside)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	for _, c := range h.chowns {
		assert.NotContains(t, c, outside)
	}
	assert.NotContains(t, *h.owners, outside)
}

func TestUpgradeSnapshotKeepsAutoloadUnderOsqueryPath(t *testing.T) {
	h := setupUpgrade(t)
	autoload := filepath.Join(h.dir, "extensions.load")
	snap, err := snapshotOsqueryConfig()
	require.NoError(t, err)
	var found bool
	for _, f := range snap.Files {
		found = found || f.Path == autoload
	}
	assert.True(t, found)
	require.NoError(t, os.WriteFile(autoload, []byte("packaged"), 0600))
	require.NoError(t, snap.restore())
	b, _ := os.ReadFile(autoload)
	assert.Equal(t, string(h.before[autoload]), string(b))
}

func TestSnapshotRecordsAndRestoresOwner(t *testing.T) {
	h := setupUpgrade(t)
	snap, err := snapshotOsqueryConfig()
	require.NoError(t, err)
	require.Len(t, snap.Files, 4)
	for i, f := range snap.Files {
		require.NotNil(t, f.Owner, f.Path)
		assert.Equal(t, fileOwnerIDs{UID: os.Getuid(), GID: os.Getgid()}, *f.Owner)
		if f.Path == h.flagfile() {
			snap.Files[i].Owner = &fileOwnerIDs{UID: 0, GID: 4242}
		}
		if f.Path == appConfig.OsqueryCertFile {
			snap.Files[i].Owner = nil // unknown: handed to the administrator
		}
	}
	require.NoError(t, snap.restore())
	assert.Contains(t, h.chowns, h.flagfile()+" 0:4242")
	assert.Contains(t, *h.owners, appConfig.OsqueryCertFile)
	assert.NotContains(t, *h.owners, h.flagfile())
}

func TestUpgradeSkipIsRememberedWithinBackoff(t *testing.T) {
	h := setupUpgrade(t)
	delete(h.pkgs, upPrevious)
	r1, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	require.Equal(t, "previous_unavailable", r1.Reason)
	hits := h.pkgHits
	require.Positive(t, hits)
	st := h.state()
	require.NotNil(t, st.Skipped)
	assert.Equal(t, skippedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq1, Reason: "previous_unavailable", At: r1.At}, *st.Skipped)

	r2, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, r1, r2, "same skipped result")
	assert.Equal(t, hits, h.pkgHits, "nothing downloaded within the backoff")

	res := h.res()
	res.RequestID = upReq2
	_, err = upgradeOsquery(context.Background(), res)
	require.NoError(t, err)
	assert.Greater(t, h.pkgHits, hits, "a new request id retries")

	hits = h.pkgHits
	other := h.res()
	other.Target.SHA256 = strings.Repeat("c", 64)
	_, err = upgradeOsquery(context.Background(), other)
	require.NoError(t, err)
	assert.Greater(t, h.pkgHits, hits, "a new digest retries")
	assert.Empty(t, h.recorded())
}

func TestUpgradeSkipBackoffElapsedRetriesAndSuccessClears(t *testing.T) {
	h := setupUpgrade(t)
	h.pkgs[upTarget] = []byte("tampered")
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	require.Equal(t, "digest_mismatch", r.Reason)
	require.NotNil(t, h.state().Skipped)

	h.pkgs[upTarget] = upTargetBody
	upgradeSkipBackoff = time.Nanosecond
	hits := h.pkgHits
	r, err = upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Greater(t, h.pkgHits, hits, "an elapsed backoff retries")
	assert.Equal(t, "ok", r.Result)
	assert.Nil(t, h.state().Skipped, "a successful upgrade clears the memory")
}

func TestUpgradeRollbackClearsSkipMemory(t *testing.T) {
	h := setupUpgrade(t)
	require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Skipped: &skippedUpgrade{Version: upTarget, SHA256: h.res().Target.SHA256, RequestID: upReq2, Reason: "digest_mismatch", At: time.Now()}}))
	h.runsAfter = func(installed string) bool { return installed == upPrevious }
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "rejected", r.Result)
	assert.Nil(t, h.state().Skipped)
}

// plantStaleDownload leaves an interrupted download of two hours ago in dir
func plantStaleDownload(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "osctrld-pkg-interrupted.rpm")
	require.NoError(t, os.WriteFile(p, []byte("half a package"), 0600))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))
	return p
}

func TestUpgradeSweepsStaleDownloadsFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows test runner's temp files are not owned by Administrators or SYSTEM, nothing is swept")
	}
	h := setupUpgrade(t)
	stale := plantStaleDownload(t, h.tmp)
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "ok", r.Result)
	assert.NoFileExists(t, stale)
	h.assertNoPackages(t)
}

func TestUpgradeRollbackRemovesFilesThePackageAddedToExtensions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows, and ctime is not available")
	}
	h := setupUpgrade(t)
	ext := appConfig.ExtensionsDir
	outside := filepath.Join(t.TempDir(), "outside.ext")
	require.NoError(t, os.WriteFile(outside, []byte("not in ext"), 0644))
	old := time.Now().Add(-24 * time.Hour)
	// A file whose inode changed before the upgrade (faked: no portable way to
	// create one) is left alone, whatever its name
	prev := changeTime
	t.Cleanup(func() { changeTime = prev })
	changeTime = func(info os.FileInfo) time.Time {
		if info.Name() == "kept.ext" {
			return old
		}
		return prev(info)
	}
	h.onInstall = func(h *upgradeHarness, ver string) {
		if ver != upTarget {
			return
		}
		require.NoError(t, os.WriteFile(filepath.Join(ext, "new.ext"), []byte("packaged"), 0755))
		// package managers set mtime from the payload's build time
		require.NoError(t, os.WriteFile(filepath.Join(ext, "payload.ext"), []byte("packaged"), 0755))
		require.NoError(t, os.Chtimes(filepath.Join(ext, "payload.ext"), old, old))
		require.NoError(t, os.WriteFile(filepath.Join(ext, "kept.ext"), []byte("other tool"), 0755))
		require.NoError(t, os.Symlink(outside, filepath.Join(ext, "link.ext")))
		require.NoError(t, os.Mkdir(filepath.Join(ext, "subdir"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(ext, "subdir", "inner.ext"), []byte("inner"), 0755))
	}
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assertRejected(t, h, r, "config_changed")
	assert.NoFileExists(t, filepath.Join(ext, "new.ext"), "added by the package, removed on rollback")
	assert.NoFileExists(t, filepath.Join(ext, "payload.ext"), "an old payload mtime does not hide a fresh ctime")
	assert.FileExists(t, filepath.Join(ext, "a.ext"), "in the snapshot listing")
	assert.FileExists(t, filepath.Join(ext, "kept.ext"), "ctime older than the upgrade")
	_, err = os.Lstat(filepath.Join(ext, "link.ext"))
	assert.NoError(t, err, "symlink left alone")
	assert.FileExists(t, outside)
	assert.FileExists(t, filepath.Join(ext, "subdir", "inner.ext"))
}

func TestFileChangeTime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	old := time.Now().Add(-24 * time.Hour)
	require.NoError(t, os.Chtimes(p, old, old))
	info, err := os.Lstat(p)
	require.NoError(t, err)
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		assert.WithinDuration(t, time.Now(), fileChangeTime(info), time.Minute, "ctime, not the mtime Chtimes set")
	} else {
		assert.Equal(t, info.ModTime(), fileChangeTime(info), "mtime where ctime is unavailable")
	}
}

func TestUpgradeRollbackExtensionRemovalErrorIsOnlyLogged(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the test cannot write")
	}
	h := setupUpgrade(t)
	ext := appConfig.ExtensionsDir
	h.onInstall = func(h *upgradeHarness, ver string) {
		if ver == upTarget {
			require.NoError(t, os.WriteFile(filepath.Join(ext, "new.ext"), []byte("packaged"), 0755))
			require.NoError(t, os.Chmod(ext, 0555))
		}
	}
	t.Cleanup(func() { _ = os.Chmod(ext, 0755) })
	logs := captureLogs(t)
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assertRejected(t, h, r, "config_changed")
	assert.Equal(t, []string{"stop", "install:" + upTarget, "stop",
		"stop", "downgrade:" + upPrevious, "stop", "start"}, h.recorded(), "the rollback finished")
	assert.FileExists(t, filepath.Join(ext, "new.ext"))
	assert.Contains(t, logs.String(), "failed to remove a file the osquery package added")
}

func TestConfirmNewVersionStopsOnceWindowRanOut(t *testing.T) {
	// A 429 that arrives after the window ends must not race the deadline
	// against a zero wait: no poll is ever sent once the window is over
	setupUpgrade(t)
	upgradeConfirmWindow, upgradeConfirmInterval = 20*time.Millisecond, time.Millisecond
	prev := upgradeConfirmWait
	ready := make(chan time.Time)
	close(ready)
	upgradeConfirmWait = func(time.Duration) <-chan time.Time { return ready }
	t.Cleanup(func() { upgradeConfirmWait = prev })
	for _, retry := range []string{"1", ""} {
		calls := confirmServer(t, func(w http.ResponseWriter) {
			time.Sleep(40 * time.Millisecond)
			tooMany(retry)(w)
		})
		for i := 0; i < 10; i++ {
			before := calls()
			ok, err := confirmNewVersion(context.Background(), upTarget)
			require.NoError(t, err)
			assert.False(t, ok)
			assert.Equal(t, 1, calls()-before, "Retry-After %q: one poll, then the window is over", retry)
		}
	}
}

func TestSnapshotRecordsAutoloadEntry(t *testing.T) {
	h := setupUpgrade(t)
	snap, err := snapshotOsqueryConfig()
	require.NoError(t, err)
	for _, f := range snap.Files {
		assert.Equal(t, f.Path == filepath.Join(h.dir, "extensions.load"), f.Autoload, f.Path)
	}
	b, err := json.Marshal(snap.Files[0])
	require.NoError(t, err)
	assert.NotContains(t, string(b), "autoload", "omitted when false, as in older snapshots")
}

func TestSnapshotRestoreRechecksAutoloadPath(t *testing.T) {
	setupAutoloadRestore := func(t *testing.T) (*upgradeHarness, osquerySnapshot, string) {
		h := setupUpgrade(t)
		snap, err := snapshotOsqueryConfig()
		require.NoError(t, err)
		require.Len(t, snap.Files, 4)
		_, err = ensureUpgradeDir()
		require.NoError(t, err)
		for p := range h.files {
			require.NoError(t, os.WriteFile(p, []byte("packaged default"), 0644))
		}
		return h, snap, filepath.Join(h.dir, "extensions.load")
	}
	t.Run("tampered autoload entry outside OsqueryPath is skipped", func(t *testing.T) {
		for _, legacy := range []bool{false, true} {
			h, snap, autoload := setupAutoloadRestore(t)
			victim := filepath.Join(t.TempDir(), "victim")
			require.NoError(t, os.WriteFile(victim, []byte("untouched"), 0600))
			for i := range snap.Files {
				if snap.Files[i].Path == autoload {
					snap.Files[i].Path = victim
					snap.Files[i].Autoload = !legacy
				}
			}
			require.NoError(t, saveSnapshot(snap))
			loaded, err := loadSnapshot()
			require.NoError(t, err)
			logs := captureLogs(t)
			require.NoError(t, loaded.restore())
			b, err := os.ReadFile(victim)
			require.NoError(t, err)
			assert.Equal(t, "untouched", string(b), "legacy=%v", legacy)
			fi, err := os.Stat(victim)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
			assert.NotContains(t, *h.owners, victim)
			for _, c := range h.chowns {
				assert.NotContains(t, c, victim)
			}
			assert.Contains(t, logs.String(), `"level":"warn"`)
			assert.Contains(t, logs.String(), `"path":"`+victim+`"`)
			for p := range h.files {
				if p == autoload {
					continue
				}
				b, err := os.ReadFile(p)
				require.NoError(t, err)
				assert.Equal(t, string(h.before[p]), string(b), "the rest is still restored")
			}
		}
	})
	t.Run("valid autoload entry restores", func(t *testing.T) {
		h, snap, autoload := setupAutoloadRestore(t)
		require.NoError(t, snap.restore())
		b, _ := os.ReadFile(autoload)
		assert.Equal(t, string(h.before[autoload]), string(b))
	})
	t.Run("older snapshot without the field still restores", func(t *testing.T) {
		h, snap, autoload := setupAutoloadRestore(t)
		for i := range snap.Files {
			snap.Files[i].Autoload = false
		}
		require.NoError(t, saveSnapshot(snap))
		raw, err := os.ReadFile(snapshotPath())
		require.NoError(t, err)
		require.NotContains(t, string(raw), "autoload\":")
		loaded, err := loadSnapshot()
		require.NoError(t, err)
		require.NoError(t, loaded.restore())
		for p := range h.files {
			b, _ := os.ReadFile(p)
			assert.Equal(t, string(h.before[p]), string(b), p)
		}
		assert.FileExists(t, autoload)
	})
}

// windows turns the harness into a Windows host: MSI packages, the stash ACL
// stubbed; msiexec and the Authenticode check are faked by execCommand
func (h *upgradeHarness) windows() {
	upgradeGOOS = WindowsOS
	upgradePackageFormat = func() (packageFormat, error) { return pkgMSI, nil }
	prevACL := applyStashACL
	h.t.Cleanup(func() { applyStashACL = prevACL })
	applyStashACL = func(string) error { return nil }
	prevService := upgradeEnsureService
	h.t.Cleanup(func() { upgradeEnsureService = prevService })
	upgradeEnsureService = func(string) error { return nil }
}

// winRes is what osctrl answers a Windows host: a target and no previous
func (h *upgradeHarness) winRes() upgradeResolution {
	r := h.res()
	r.Previous = nil
	return r
}

// Windows: stop, Authenticode check before msiexec, install, stop the
// package's osqueryd, restore, start
var winInstalled = []string{"sigcheck", "stop", "sigcheck", "install:" + upTarget, "stop"}

func TestWindowsUpgradeTargetOnlyHappyPath(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	h.onInstall = func(h *upgradeHarness, _ string) {
		entries, err := os.ReadDir(upgradeDir())
		require.NoError(t, err)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		assert.ElementsMatch(t, []string{"snapshot.json", h.res().Target.SHA256 + ".msi"}, names, "only the target is stashed")
		p := h.state().Pending
		require.NotNil(t, p)
		assert.Empty(t, p.PreviousPkg)
		assert.Equal(t, upPrevious, p.Previous.Version, "the version installed before is remembered")
	}
	r, err := upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assert.Equal(t, upgradeResult{Result: "ok", Version: upTarget, RequestID: upReq1, At: r.At}, r)
	assert.Equal(t, append(append([]string{}, winInstalled...), "start"), h.recorded())
	assert.Equal(t, 1, h.pkgHits, "only the target downloaded")
	h.assertConfigIntact(t)
	h.assertNoPackages(t)
	st := h.state()
	assert.Nil(t, st.Pending)
	assert.Nil(t, st.Rejected)
	assert.Equal(t, &r, st.Last)
}

func TestWindowsUpgradeNeverDownloadsPrevious(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	delete(h.pkgs, upPrevious)
	// A previous sent anyway is ignored
	r, err := upgradeOsquery(context.Background(), h.res())
	require.NoError(t, err)
	assert.Equal(t, "ok", r.Result)
	assert.Equal(t, 1, h.pkgHits)
}

func TestWindowsVerifyFailureRestoresConfigAndReportsRollbackUnavailable(t *testing.T) {
	// The service settings are reapplied before every start
	restored := append(append([]string{}, winInstalled...), "stop", "service", "start")
	for _, tc := range []struct {
		name   string
		setup  func(h *upgradeHarness)
		events []string
	}{
		{"version mismatch", func(h *upgradeHarness) {
			real := osqueryVersionReader
			osqueryVersionReader = func() string {
				if v := real(); v != upTarget {
					return v
				}
				return "5.0.0"
			}
		}, restored},
		{"extensions changed", func(h *upgradeHarness) {
			h.onInstall = func(h *upgradeHarness, _ string) {
				require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ext", "packaged.ext"), []byte("x"), 0755))
			}
		}, restored},
		{"never confirmed", func(h *upgradeHarness) { h.reported = func(string) string { return upPrevious } },
			append(append([]string{}, winInstalled...), "service", "start", "stop", "service", "start")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setupUpgrade(t)
			h.windows()
			h.recordService(nil)
			tc.setup(h)
			logs := captureLogs(t)
			r, err := upgradeOsquery(context.Background(), h.winRes())
			require.NoError(t, err)
			assertRejected(t, h, r, "rollback_unavailable")
			assert.Equal(t, tc.events, h.recorded(), "msiexec runs once, never a downgrade")
			assert.Equal(t, 1, h.count("install:"+upTarget))
			assert.NotContains(t, logs.String(), "failed to reinstall the previous osquery package")
			running, _ := osquerydRunning()
			assert.True(t, running, "osqueryd started on the restored config")
			assert.NoFileExists(t, filepath.Join(h.dir, "ext", "packaged.ext"))
		})
	}
}

func TestWindowsOsquerydFailsToStartReportsRollbackUnavailable(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	h.runsAfter = func(installed string) bool { return installed != upTarget }
	r, err := upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assertRejected(t, h, r, "rollback_unavailable")
	assert.Equal(t, append(append([]string{}, winInstalled...), "start", "stop", "start"), h.recorded())
	assert.Equal(t, upTarget, osqueryVersionReader(), "nothing reinstalled")
}

// winPending leaves what a Windows osctrld that died mid-upgrade leaves behind
func winPending(t *testing.T, h *upgradeHarness, installed bool, rollback string) {
	t.Helper()
	res := h.winRes()
	_, err := ensureUpgradeDir()
	require.NoError(t, err)
	snap, err := snapshotOsqueryConfig()
	require.NoError(t, err)
	require.NoError(t, saveSnapshot(snap))
	require.NoError(t, saveUpgradeState(upgradeStatePath(), upgradeState{Pending: &pendingUpgrade{
		Target: *res.Target, Previous: upgradeRef{Version: upPrevious}, RequestID: res.RequestID,
		StartedAt: time.Now(), Installed: installed, Rollback: rollback}}))
}

func TestWindowsResumeAfterCrashUsesFailurePath(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed string
		marker    bool
		rollback  string
		setup     func(h *upgradeHarness)
	}{
		{"new version never confirmed", upTarget, true, "", func(h *upgradeHarness) {
			h.reported = func(string) string { return upPrevious }
		}},
		{"new version does not start", upTarget, true, "", func(h *upgradeHarness) {
			h.runsAfter = func(installed string) bool { return installed != upTarget }
		}},
		{"interrupted failure path", upTarget, true, "osqueryd_not_running", func(*upgradeHarness) {}},
		{"unknown version", "", false, "", func(*upgradeHarness) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setupUpgrade(t)
			h.windows()
			winPending(t, h, tc.marker, tc.rollback)
			h.installed, h.running = tc.installed, false
			// The crashed run's events: not a first stop of a fresh upgrade
			h.events = []string{"crash"}
			h.recordService(nil)
			tc.setup(h)
			logs := captureLogs(t)
			require.NoError(t, resumeUpgrade(context.Background()))
			ev := h.recorded()
			assert.Equal(t, []string{"service", "start"}, ev[len(ev)-2:], "service settings reapplied before the final start")
			assertRejected(t, h, *h.state().Last, "rollback_unavailable")
			assert.Zero(t, h.count("install:"+upTarget)+h.count("install:"+upPrevious)+h.count("downgrade:"+upPrevious), "msiexec never runs on resume")
			assert.NotContains(t, logs.String(), "failed to reinstall the previous osquery package")
			assert.Equal(t, "start", h.recorded()[len(h.recorded())-1])
		})
	}
	t.Run("old version, never installed: forgotten", func(t *testing.T) {
		h := setupUpgrade(t)
		h.windows()
		winPending(t, h, false, "")
		h.running = false
		h.recordService(nil)
		require.NoError(t, resumeUpgrade(context.Background()))
		assert.Equal(t, []string{"service", "start"}, h.recorded())
		assert.Equal(t, upgradeState{}, h.state(), "nothing recorded")
		h.assertConfigIntact(t)
		h.assertNoPackages(t)
	})
}

func TestWindowsRejectedIsNotRetriedSameRequestID(t *testing.T) {
	h, _ := syncUpgradeEnv(t)
	h.windows()
	h.resolve = func(upgradeRequest) upgradeResolution { return h.winRes() }
	h.reported = func(string) string { return upPrevious }
	upgradeStep(context.Background(), false)
	require.Equal(t, "rollback_unavailable", h.state().Last.Reason)
	hits, events := h.pkgHits, len(h.recorded())

	h.reported = func(installed string) string { return installed }
	upgradeStep(context.Background(), false)
	assert.Equal(t, hits, h.pkgHits, "not downloaded again for the same request")
	assert.Len(t, h.recorded(), events, "nothing installed again")
	assert.Equal(t, "rollback_unavailable", h.state().Last.Reason)

	ok, why := shouldAttempt(h.winRes(), h.state())
	assert.False(t, ok)
	assert.Equal(t, "rejected", why)
	res := h.winRes()
	res.RequestID = upReq2
	ok, _ = shouldAttempt(res, h.state())
	assert.True(t, ok, "a new request id may try again")
}

func TestWindowsStashACLErrorSkipsAsInstallFailed(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	applyStashACL = func(string) error { return errors.New("access denied") }
	r, err := upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assert.Equal(t, upgradeResult{Result: "skipped", Version: upTarget, Reason: "install_failed", RequestID: upReq1, At: r.At}, r)
	assert.Empty(t, h.recorded(), "osqueryd never stopped")
	assert.Equal(t, upPrevious, osqueryVersionReader())
	st := h.state()
	assert.Nil(t, st.Pending)
	assert.Nil(t, st.Rejected)
	require.NotNil(t, st.Skipped)
	assert.Equal(t, "install_failed", st.Skipped.Reason)
	hits := h.pkgHits
	_, err = upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assert.Equal(t, hits, h.pkgHits, "not downloaded again within the backoff")
}

func TestWindowsInstallErrorWithOldVersionIsInstallFailedSkip(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	h.failInstall[upTarget] = true
	r, err := upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assert.Equal(t, upgradeResult{Result: "skipped", Version: upTarget, Reason: "install_failed", RequestID: upReq1, At: r.At}, r)
	assert.Equal(t, append(append([]string{}, winInstalled...), "start"), h.recorded())
	h.assertConfigIntact(t)
	h.assertNoPackages(t)
	assert.Nil(t, h.state().Rejected)
}

func TestNonWindowsMissingPreviousStillSkips(t *testing.T) {
	for _, goos := range []string{LinuxOS, DarwinOS} {
		t.Run(goos, func(t *testing.T) {
			h, sink := syncUpgradeEnv(t)
			upgradeGOOS = goos
			h.resolve = func(upgradeRequest) upgradeResolution { return h.winRes() }
			ok, why := shouldAttempt(h.winRes(), upgradeState{})
			assert.False(t, ok)
			assert.Equal(t, "invalid_resolution", why)
			_, err := upgradeOsquery(context.Background(), h.winRes())
			require.Error(t, err)
			syncOnce(context.Background(), newTestCLICommand())
			assert.Zero(t, h.pkgHits)
			assert.Empty(t, h.recorded())
			assert.Equal(t, upgradeState{}, h.state())
			assert.Nil(t, onlyReport(t, sink).Upgrade)
		})
	}
}

// The stash is secured when it is created; failing to re-apply its ACL when
// read back must not keep the config from being restored
func TestWindowsFailurePathRestoresEvenIfACLReapplyFails(t *testing.T) {
	denied := func(string) error { return errors.New("access denied") }
	t.Run("failure path", func(t *testing.T) {
		h := setupUpgrade(t)
		h.windows()
		h.onInstall = func(h *upgradeHarness, _ string) {
			require.NoError(t, os.WriteFile(filepath.Join(h.dir, "ext", "packaged.ext"), []byte("x"), 0755))
			applyStashACL = denied
		}
		r, err := upgradeOsquery(context.Background(), h.winRes())
		require.NoError(t, err)
		assertRejected(t, h, r, "rollback_unavailable")
		assert.NoFileExists(t, filepath.Join(h.dir, "ext", "packaged.ext"), "the reloaded snapshot still drives the cleanup")
		assert.Equal(t, "start", h.recorded()[len(h.recorded())-1])
		running, _ := osquerydRunning()
		assert.True(t, running)
	})
	t.Run("resume", func(t *testing.T) {
		h := setupUpgrade(t)
		h.windows()
		winPending(t, h, true, "osqueryd_not_running")
		h.installed, h.running = upTarget, false
		h.events = []string{"crash"}
		applyStashACL = denied
		require.NoError(t, resumeUpgrade(context.Background()))
		assertRejected(t, h, *h.state().Last, "rollback_unavailable")
		running, _ := osquerydRunning()
		assert.True(t, running)
	})
}

// An unreadable version is not "the old version is still installed"
func TestWindowsResumeUnknownVersionNotForgotten(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	winPending(t, h, false, "")
	st := h.state()
	st.Pending.Previous.Version = ""
	require.NoError(t, saveUpgradeState(upgradeStatePath(), st))
	h.installed, h.running = "", false
	h.events = []string{"crash"}
	require.NoError(t, resumeUpgrade(context.Background()))
	assertRejected(t, h, *h.state().Last, "rollback_unavailable")
}

// fakeMSI replaces msiexec for one test
func fakeMSI(t *testing.T, run func(path string) (bool, error)) {
	prev := msiInstaller
	t.Cleanup(func() { msiInstaller = prev })
	msiInstaller = func(_ context.Context, path string) (bool, error) { return run(path) }
}

// recordService records the service settings check as an event
func (h *upgradeHarness) recordService(err error) {
	upgradeEnsureService = func(flagFile string) error {
		assert.Equal(h.t, h.flagfile(), flagFile)
		h.event("service")
		return err
	}
}

// assertInstallFailedSkip: config restored, osqueryd started, skipped with
// the backoff memory, no rejection, nothing pending
func assertInstallFailedSkip(t *testing.T, h *upgradeHarness, r upgradeResult) {
	t.Helper()
	assert.Equal(t, upgradeResult{Result: "skipped", Version: upTarget, Reason: "install_failed", RequestID: upReq1, At: r.At}, r)
	assert.Equal(t, upPrevious, osqueryVersionReader())
	h.assertConfigIntact(t)
	h.assertNoPackages(t)
	running, _ := osquerydRunning()
	assert.True(t, running, "osqueryd left running")
	assert.Equal(t, "start", h.recorded()[len(h.recorded())-1])
	st := h.state()
	assert.Nil(t, st.Pending)
	assert.Nil(t, st.Rejected)
	assert.Equal(t, &r, st.Last)
	require.NotNil(t, st.Skipped)
	assert.Equal(t, "install_failed", st.Skipped.Reason)
	hits := h.pkgHits
	_, err := upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assert.Equal(t, hits, h.pkgHits, "not downloaded again within the backoff")
}

func TestWindowsInstall3010NewVersionRunningSucceeds(t *testing.T) {
	for _, code := range []int{3010, 1641} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			h := setupUpgrade(t)
			h.windows()
			h.recordService(nil)
			logs := captureLogs(t)
			fakeMSI(t, func(path string) (bool, error) {
				_ = h.install(path, false).Run()
				return msiExitResult(code, "")
			})
			r, err := upgradeOsquery(context.Background(), h.winRes())
			require.NoError(t, err)
			assert.Equal(t, upgradeResult{Result: "ok", Version: upTarget, RequestID: upReq1, At: r.At}, r)
			assert.Equal(t, append(append([]string{}, winInstalled...), "service", "start"), h.recorded(), "service checked after restore, before start")
			assert.Contains(t, logs.String(), "reboot")
			h.assertConfigIntact(t)
			st := h.state()
			assert.Nil(t, st.Pending)
			assert.Nil(t, st.Rejected)
		})
	}
}

func TestWindowsInstall3010OldVersionStillInstalledSkipsInstallFailed(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	h.recordService(nil)
	fakeMSI(t, func(path string) (bool, error) {
		h.event("msiexec")
		// the swap waits for the reboot: old binary, packaged defaults
		for p := range h.files {
			require.NoError(t, os.WriteFile(p, []byte("packaged default"), 0644))
		}
		return msiExitResult(3010, "")
	})
	r, err := upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assert.Equal(t, []string{"sigcheck", "stop", "sigcheck", "msiexec", "stop", "service", "start"}, h.recorded())
	assertInstallFailedSkip(t, h, r)
}

func TestWindowsInstallNonElevatedFailureSkips(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"access denied", errors.New("msiexec exit code 1925")},
		{"timeout", errors.New("msiexec timed out after 10m0s")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := setupUpgrade(t)
			h.windows()
			h.recordService(nil)
			stop := upgradeStopOsquery
			upgradeStopOsquery = func() error { _ = stop(); return errors.New("access denied") }
			fakeMSI(t, func(string) (bool, error) { h.event("msiexec"); return false, tc.err })
			r, err := upgradeOsquery(context.Background(), h.winRes())
			require.NoError(t, err)
			assert.Equal(t, []string{"sigcheck", "stop", "sigcheck", "msiexec", "stop", "service", "start"}, h.recorded())
			assertInstallFailedSkip(t, h, r)
		})
	}
}

func TestWindowsServiceSettingsErrorFailurePath(t *testing.T) {
	t.Run("new version", func(t *testing.T) {
		h := setupUpgrade(t)
		h.windows()
		h.recordService(errors.New("access denied"))
		r, err := upgradeOsquery(context.Background(), h.winRes())
		require.NoError(t, err)
		assertRejected(t, h, r, "rollback_unavailable")
		assert.Equal(t, append(append([]string{}, winInstalled...), "service", "stop", "service", "start"), h.recorded(), "a failing check does not stop the restart")
		running, _ := osquerydRunning()
		assert.True(t, running)
		h.assertConfigIntact(t)
	})
	t.Run("old version still installed", func(t *testing.T) {
		h := setupUpgrade(t)
		h.windows()
		h.recordService(errors.New("access denied"))
		fakeMSI(t, func(string) (bool, error) { h.event("msiexec"); return true, nil })
		r, err := upgradeOsquery(context.Background(), h.winRes())
		require.NoError(t, err)
		assertInstallFailedSkip(t, h, r)
	})
}

func TestUpgradeOsqueryPackageURL(t *testing.T) {
	for _, arch := range []string{"arm64", "386"} {
		_, err := upgradeOsqueryPackageURL(pkgMSI, "5.12.1", arch)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no msi package for architecture "+arch)
	}
	for _, tc := range []struct {
		format packageFormat
		arch   string
	}{{pkgMSI, "amd64"}, {pkgDeb, "arm64"}, {pkgRPM, "amd64"}, {pkgPKG, "arm64"}} {
		got, err := upgradeOsqueryPackageURL(tc.format, "5.12.1", tc.arch)
		require.NoError(t, err)
		want, _ := osqueryPackageURL(tc.format, "5.12.1", tc.arch)
		assert.Equal(t, want, got, "other packages unchanged")
	}
}

// Only the x64 MSI is known: an ARM64 host skips without downloading
func TestWindowsARM64SkipsTargetUnavailable(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	upgradeGOARCH = "arm64"
	// The real URL builder decides; a URL it builds is served by the harness,
	// never fetched from the network
	harnessURL := upgradePackageURL
	upgradePackageURL = func(f packageFormat, version, arch string) (string, error) {
		if _, err := upgradeOsqueryPackageURL(f, version, arch); err != nil {
			return "", err
		}
		return harnessURL(f, version, arch)
	}
	r, err := upgradeOsquery(context.Background(), h.winRes())
	require.NoError(t, err)
	assert.Equal(t, upgradeResult{Result: "skipped", Version: upTarget, Reason: "target_unavailable", RequestID: upReq1, At: r.At}, r)
	assert.Empty(t, h.recorded(), "osqueryd never stopped")
	assert.Zero(t, h.pkgHits)
	st := h.state()
	assert.Nil(t, st.Pending)
	assert.Nil(t, st.Rejected)
	require.NotNil(t, st.Skipped, "the skip backoff is remembered")
	assert.Equal(t, "target_unavailable", st.Skipped.Reason)
}

// A Windows install that never took effect is forgotten even when the
// snapshot is gone: no rollback_unavailable for an unchanged host
func TestWindowsResumeNeverInstalledWithoutSnapshotIsForgotten(t *testing.T) {
	h := setupUpgrade(t)
	h.windows()
	h.recordService(nil)
	winPending(t, h, false, "")
	require.NoError(t, os.Remove(snapshotPath()))
	h.running = false
	require.NoError(t, resumeUpgrade(context.Background()))
	assert.Equal(t, []string{"service", "start"}, h.recorded())
	assert.Equal(t, upgradeState{}, h.state(), "nothing recorded")
	running, _ := osquerydRunning()
	assert.True(t, running)
	h.assertNoPackages(t)
}
