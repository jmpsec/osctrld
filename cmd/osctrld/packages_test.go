package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsqueryPackageURL(t *testing.T) {
	const base = "https://osquery-packages.s3.amazonaws.com"
	cases := []struct {
		name     string
		format   packageFormat
		version  string
		goarch   string
		expected string
	}{
		{"deb amd64", pkgDeb, "5.12.1", "amd64", base + "/deb/osquery_5.12.1-1.linux_amd64.deb"},
		{"deb arm64", pkgDeb, "5.12.1", "arm64", base + "/deb/osquery_5.12.1-1.linux_arm64.deb"},
		{"rpm amd64 is x86_64", pkgRPM, "5.12.1", "amd64", base + "/rpm/osquery-5.12.1-1.linux.x86_64.rpm"},
		{"rpm arm64 is aarch64", pkgRPM, "5.12.1", "arm64", base + "/rpm/osquery-5.12.1-1.linux.aarch64.rpm"},
		{"darwin pkg is arch independent", pkgPKG, "5.12.1", "arm64", base + "/darwin/osquery-5.12.1.pkg"},
		{"windows msi is arch independent", pkgMSI, "5.12.1", "amd64", base + "/windows/osquery-5.12.1.msi"},
		// install keeps the x64 MSI on ARM64, which runs it under emulation
		{"windows msi on arm64 is the x64 package for install", pkgMSI, "5.12.1", "arm64", base + "/windows/osquery-5.12.1.msi"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := osqueryPackageURL(tt.format, tt.version, tt.goarch)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestOsqueryPackageURLUnsupportedArch(t *testing.T) {
	_, err := osqueryPackageURL(pkgDeb, "5.12.1", "mips")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mips")
}

func TestLinuxPackageFormat(t *testing.T) {
	t.Run("rpm when /usr/bin/rpm exists", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "usr/bin"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "usr/bin/rpm"), []byte("x"), 0755))
		assert.Equal(t, pkgRPM, linuxPackageFormat(root))
	})

	t.Run("rpm when /etc/redhat-release exists", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "etc"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(root, "etc/redhat-release"), []byte("x"), 0644))
		assert.Equal(t, pkgRPM, linuxPackageFormat(root))
	})

	t.Run("deb when neither marker is present", func(t *testing.T) {
		assert.Equal(t, pkgDeb, linuxPackageFormat(t.TempDir()))
	})
}

func TestPackageFormatFor(t *testing.T) {
	f, err := packageFormatFor(DarwinOS, "")
	require.NoError(t, err)
	assert.Equal(t, pkgPKG, f)

	f, err = packageFormatFor(WindowsOS, "")
	require.NoError(t, err)
	assert.Equal(t, pkgMSI, f)

	f, err = packageFormatFor(LinuxOS, t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, pkgDeb, f)

	_, err = packageFormatFor("freebsd", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "freebsd")
}

// linuxPackageFormat must probe ABSOLUTE paths. Planting a decoy marker reachable
// only through a CWD-relative path proves it: with relative markers the decoy is
// found and the answer flips; with absolute markers it is ignored.
func TestLinuxPackageFormatIgnoresWorkingDirectory(t *testing.T) {
	hostAnswer := linuxPackageFormat("")

	decoy := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(decoy, "usr/bin"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(decoy, "usr/bin/rpm"), []byte("decoy"), 0755))
	t.Chdir(decoy)

	assert.Equal(t, hostAnswer, linuxPackageFormat(""),
		"a marker reachable only via a relative path must not change the result")
}

func TestResolveDigest(t *testing.T) {
	assert.Equal(t, "server", resolveDigest("server", "config"), "server value must win")
	assert.Equal(t, "config", resolveDigest("", "config"))
	assert.Equal(t, "", resolveDigest("", ""))
}

func TestDownloadPackageVerifies(t *testing.T) {
	payload := []byte("pretend this is an osquery package")
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	t.Run("matching digest downloads", func(t *testing.T) {
		path, err := downloadPackage(server.URL+"/osquery.deb", sum, false, false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(path) })

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("mismatched digest is refused", func(t *testing.T) {
		_, err := downloadPackage(server.URL+"/osquery.deb", "00"+sum[2:], false, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mismatch")
	})

	t.Run("missing digest is refused by default", func(t *testing.T) {
		_, err := downloadPackage(server.URL+"/osquery.deb", "", false, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--osquery-sha256")
		assert.Contains(t, err.Error(), "--allow-unverified")
	})

	t.Run("missing digest proceeds when explicitly allowed", func(t *testing.T) {
		path, err := downloadPackage(server.URL+"/osquery.deb", "", true, false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Remove(path) })
		assert.FileExists(t, path)
	})
}

func TestPackageURLExt(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		expected string
	}{
		{"plain url", "https://example.com/osquery-5.12.1.msi", ".msi"},
		{"url with query string", "https://mirror.internal/osquery-5.12.1.msi?token=abc", ".msi"},
		{"url with no extension", "https://example.com/osquery-package", ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, packageURLExt(tt.url))
		})
	}
}

func TestDownloadPackageHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := downloadPackage(server.URL+"/missing.deb", "", true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestInstallPackageCommands(t *testing.T) {
	cases := []struct {
		name     string
		format   packageFormat
		expected []string
	}{
		{"deb", pkgDeb, []string{"dpkg", "-i", "/tmp/osquery.deb"}},
		{"rpm", pkgRPM, []string{"rpm", "-Uvh", "/tmp/osquery.deb"}},
		{"pkg", pkgPKG, []string{"installer", "-pkg", "/tmp/osquery.deb", "-target", "/"}},
		{"msi", pkgMSI, []string{"msiexec", "/i", "/tmp/osquery.deb", "/passive", "/norestart", "/qn"}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			recorded := fakeExec(t)
			require.NoError(t, installPackage(tt.format, "/tmp/osquery.deb"))
			// deb and rpm record only the installer; pkg and msi record a
			// signature check first, so assert on the last command either way
			require.NotEmpty(t, *recorded)
			assert.Equal(t, tt.expected, (*recorded)[len(*recorded)-1])
		})
	}
}

func TestVerifyPackageSignature(t *testing.T) {
	cases := []struct {
		name     string
		format   packageFormat
		expected []string
	}{
		{"darwin pkg uses pkgutil", pkgPKG, []string{"pkgutil", "--check-signature", "/tmp/osquery.pkg"}},
		{"windows msi uses Authenticode", pkgMSI, []string{
			"powershell", "-NoProfile", "-NonInteractive", "-Command", authenticodeScript,
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			recorded := fakeExec(t)
			require.NoError(t, verifyPackageSignature(tt.format, "/tmp/osquery.pkg"))
			assert.Equal(t, [][]string{tt.expected}, *recorded)
		})
	}
}

// deb has no standalone signature to check, which is exactly why the SHA-256
// gate in Task 5 is the primary control rather than a nicety.
func TestVerifyPackageSignatureSkipsDebAndRPM(t *testing.T) {
	for _, format := range []packageFormat{pkgDeb, pkgRPM} {
		recorded := fakeExec(t)
		require.NoError(t, verifyPackageSignature(format, "/tmp/osquery.deb"))
		assert.Empty(t, *recorded)
	}
}

func TestInstallPackageStopsOnBadSignature(t *testing.T) {
	prev := execCommand
	t.Cleanup(func() { execCommand = prev })
	calls := 0
	execCommand = func(name string, args ...string) *exec.Cmd {
		calls++
		return exec.Command("false")
	}

	err := installPackage(pkgPKG, "/tmp/osquery.pkg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
	assert.Equal(t, 1, calls, "a failed signature check must not reach the installer")
}

func TestDownloadPackageStreamsToFile(t *testing.T) {
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	h := sha256.New()
	const n = 40
	for i := 0; i < n; i++ {
		h.Write(chunk)
	}
	sum := fmt.Sprintf("%x", h.Sum(nil))
	// chunked response: no Content-Length
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < n; i++ {
			_, _ = w.Write(chunk)
			_ = http.NewResponseController(w).Flush()
		}
	}))
	defer server.Close()

	path, err := downloadPackage(server.URL+"/osquery.deb", strings.ToUpper(sum), false, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, int64(n*len(chunk)), fi.Size())
}

func tempPackages(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

func TestDownloadPackageDigestMismatchLeavesNoFile(t *testing.T) {
	dir := tempPackages(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()
	_, err := downloadPackage(server.URL+"/osquery.deb", strings.Repeat("0", 64), false, false)
	require.ErrorIs(t, err, errDigestMismatch)
	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries)
}

func TestDownloadPackageSizeCapRefusesAndLeavesNoFile(t *testing.T) {
	prev := maxPackageSize
	maxPackageSize = 100
	t.Cleanup(func() { maxPackageSize = prev })
	dir := tempPackages(t)
	body := make([]byte, 500)
	t.Run("content-length", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		}))
		defer server.Close()
		_, err := downloadPackage(server.URL+"/o.deb", "", true, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds")
	})
	t.Run("chunked", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body[:250])
			_ = http.NewResponseController(w).Flush()
			_, _ = w.Write(body[250:])
		}))
		defer server.Close()
		_, err := downloadPackage(server.URL+"/o.deb", "", true, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds")
	})
	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries)
}

func TestDownloadPackageUnverifiedStillRefusedWithoutDigest(t *testing.T) {
	_, err := downloadPackage("http://127.0.0.1:1/o.deb", "", false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--allow-unverified")
}

func TestInstallPackageAsRPMDowngradeUsesOldPackage(t *testing.T) {
	recorded := fakeExec(t)
	require.NoError(t, installPackageAs(pkgRPM, "/tmp/o.rpm", true))
	assert.Equal(t, [][]string{{"rpm", "-Uvh", "--oldpackage", "/tmp/o.rpm"}}, *recorded)
}

func TestInstallPackageAsDebAndPkgSameCommandForDowngrade(t *testing.T) {
	for _, f := range []packageFormat{pkgDeb, pkgPKG} {
		a := fakeExec(t)
		require.NoError(t, installPackageAs(f, "/tmp/o", false))
		first := append([][]string(nil), *a...)
		b := fakeExec(t)
		require.NoError(t, installPackageAs(f, "/tmp/o", true))
		assert.Equal(t, first, *b)
	}
}

func TestInstallPackageAsMSIDowngradeRefused(t *testing.T) {
	recorded := fakeExec(t)
	err := installPackageAs(pkgMSI, "/tmp/o.msi", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "downgrade is not supported for msi packages")
	assert.Empty(t, *recorded)
}

func TestDownloadPackageUsesOsctrldTempName(t *testing.T) {
	dir := tempPackages(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()
	path, err := downloadPackage(server.URL+"/osquery.deb", fmt.Sprintf("%x", sha256.Sum256([]byte("payload"))), false, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })
	assert.Equal(t, dir, filepath.Dir(path))
	assert.True(t, strings.HasPrefix(filepath.Base(path), "osctrld-pkg-"), path)
	assert.Equal(t, ".deb", filepath.Ext(path))
}

func TestSweepStaleDownloads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows test runner's temp files are not owned by Administrators or SYSTEM, nothing is swept")
	}
	assert.Equal(t, time.Hour, staleDownloadAge)
	dir := tempPackages(t)
	prevCfg := appConfig
	t.Cleanup(func() { appConfig = prevCfg })
	// The stash directory lives in TMPDIR and matches the pattern itself
	appConfig = Configuration{OsqueryFlagFile: filepath.Join(dir, "osctrld-pkg-flags")}
	stashDir, err := ensureUpgradeDir()
	require.NoError(t, err)

	old := time.Now().Add(-2 * time.Hour)
	mk := func(p string) string {
		require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
		require.NoError(t, os.Chtimes(p, old, old))
		return p
	}
	stale := mk(filepath.Join(dir, "osctrld-pkg-123.deb"))
	other := mk(filepath.Join(dir, "osquery-package-123.deb"))
	target := mk(filepath.Join(dir, "target"))
	stashed := mk(filepath.Join(stashDir, "osctrld-pkg-456.rpm"))
	require.NoError(t, os.Chtimes(stashDir, old, old))
	sub := filepath.Join(dir, "osctrld-pkg-dir")
	require.NoError(t, os.Mkdir(sub, 0700))
	inSub := mk(filepath.Join(sub, "osctrld-pkg-789.deb"))
	require.NoError(t, os.Chtimes(sub, old, old))
	link := filepath.Join(dir, "osctrld-pkg-link.deb")
	require.NoError(t, os.Symlink(target, link))
	fresh := filepath.Join(dir, "osctrld-pkg-fresh.deb")
	require.NoError(t, os.WriteFile(fresh, []byte("x"), 0600))

	sweepStaleDownloads(staleDownloadAge)
	assert.NoFileExists(t, stale)
	assert.FileExists(t, fresh, "a download in progress is left alone")

	// With no age limit only the fresh match goes: never links, directories,
	// other names or the stash
	sweepStaleDownloads(0)
	assert.NoFileExists(t, fresh)
	for _, p := range []string{other, target, stashed, inSub} {
		assert.FileExists(t, p)
	}
	_, err = os.Lstat(link)
	assert.NoError(t, err, "symlink left alone")
	assert.DirExists(t, sub)
	assert.DirExists(t, stashDir)
}

func TestRunMSIExitCodes(t *testing.T) {
	// Real exit codes above 255 cannot come from a POSIX child, so the mapping
	// is checked on its own and runMSI end to end with codes a shell can return
	for _, tc := range []struct {
		code    int
		pending bool
		ok      bool
	}{
		{0, false, true},
		{3010, true, true},
		{1641, true, true},
		{1603, false, false},
		{1618, false, false},
		{1638, false, false},
	} {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			pending, err := msiExitResult(tc.code, "out")
			assert.Equal(t, tc.pending, pending)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), fmt.Sprintf("exit code %d", tc.code))
			}
		})
	}
	t.Run("runMSI", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("uses sh")
		}
		prev := execCommand
		t.Cleanup(func() { execCommand = prev })
		var got []string
		code := "0"
		execCommand = func(name string, args ...string) *exec.Cmd {
			got = append([]string{name}, args...)
			return exec.Command("sh", "-c", "echo busy; exit "+code)
		}
		pending, err := runMSI(context.Background(), "/tmp/o.msi")
		require.NoError(t, err)
		assert.False(t, pending)
		assert.Equal(t, []string{"msiexec", "/i", "/tmp/o.msi", "/passive", "/norestart", "/qn"}, got)
		code = "77"
		_, err = runMSI(context.Background(), "/tmp/o.msi")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit code 77")
		assert.Contains(t, err.Error(), "busy")
	})
}

func TestRunMSITimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sleep")
	}
	prev, prevTimeout, prevDelay := execCommand, msiexecTimeout, msiexecWaitDelay
	t.Cleanup(func() { execCommand, msiexecTimeout, msiexecWaitDelay = prev, prevTimeout, prevDelay })
	msiexecTimeout, msiexecWaitDelay = 50*time.Millisecond, 100*time.Millisecond
	var cmd *exec.Cmd
	execCommand = func(string, ...string) *exec.Cmd {
		// The grandchild keeps the output pipe open after msiexec is killed
		cmd = exec.Command("sh", "-c", "sleep 8 & sleep 8")
		return cmd
	}
	start := time.Now()
	pending, err := runMSI(context.Background(), "/tmp/o.msi")
	require.Error(t, err)
	assert.False(t, pending)
	assert.Contains(t, err.Error(), "timed out")
	assert.ErrorIs(t, err, errMSITimeout, "a timeout is told apart from a failed install")
	assert.Less(t, time.Since(start), 4*time.Second, "a child holding the pipe does not block the wait")
	require.NotNil(t, cmd.ProcessState, "the stalled msiexec was reaped")
	assert.False(t, cmd.ProcessState.Success(), "the stalled msiexec was killed")
}

// A child that keeps msiexec's output open past the wait delay does not
// change the result of the exit code
func TestRunMSILingeringChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh")
	}
	prev, prevDelay := execCommand, msiexecWaitDelay
	t.Cleanup(func() { execCommand, msiexecWaitDelay = prev, prevDelay })
	msiexecWaitDelay = 100 * time.Millisecond
	code := "0"
	execCommand = func(string, ...string) *exec.Cmd { return exec.Command("sh", "-c", "sleep 3 & exit "+code) }
	pending, err := runMSI(context.Background(), "/tmp/o.msi")
	require.NoError(t, err, "a clean exit is a success")
	assert.False(t, pending)
	code = "77"
	_, err = runMSI(context.Background(), "/tmp/o.msi")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit code 77")
	assert.NotErrorIs(t, err, errMSITimeout)
}

func TestPollInstallerIdle(t *testing.T) {
	boom := errors.New("access denied")
	for _, tc := range []struct {
		name  string
		busy  []bool // answers in order, the last one repeats
		err   error
		idle  bool
		calls int // minimum
	}{
		{"idle immediately", []bool{false}, nil, true, 1},
		{"busy then idle", []bool{true, true, false}, nil, true, 3},
		{"busy forever", []bool{true}, nil, false, 2},
		{"error", nil, boom, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			exists := func() (bool, error) {
				calls++
				if tc.err != nil {
					return false, tc.err
				}
				return tc.busy[min(calls, len(tc.busy))-1], nil
			}
			idle, err := pollInstallerIdle(context.Background(), 50*time.Millisecond, time.Millisecond, exists)
			assert.Equal(t, tc.idle, idle)
			assert.ErrorIs(t, err, tc.err)
			if tc.err == nil {
				assert.NoError(t, err)
			}
			assert.GreaterOrEqual(t, calls, tc.calls)
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		idle, err := pollInstallerIdle(ctx, time.Minute, time.Minute, func() (bool, error) { return true, nil })
		assert.False(t, idle)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// The package path reaches PowerShell through the environment, never inside
// the command, so no character in it can change the script
func TestAuthenticodeCommandKeepsPathOutOfScript(t *testing.T) {
	recorded := fakeExec(t)
	for _, path := range []string{
		`C:\Windows\Temp\osquery.msi`,
		`C:\Users\o'brien\osquery.msi`,
		`C:\a b\x'; Remove-Item -Recurse C:\ ; '.msi`,
		"C:\\tmp\\`$(calc)`.msi",
		`C:\tmp\$env:SECRET;$x.msi`,
		`C:\tmp\[abc]*.msi`,
	} {
		*recorded = nil
		cmd := authenticodeCommand(path)
		require.Len(t, *recorded, 1)
		for _, a := range (*recorded)[0] {
			assert.NotContains(t, a, path)
		}
		assert.Equal(t, []string{"powershell", "-NoProfile", "-NonInteractive", "-Command", authenticodeScript}, (*recorded)[0])
		assert.Contains(t, cmd.Env, packagePathEnv+"="+path)
	}
	assert.Contains(t, authenticodeScript, "-LiteralPath $env:"+packagePathEnv, "no wildcard expansion of the path")
}
