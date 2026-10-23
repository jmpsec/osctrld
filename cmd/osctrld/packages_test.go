package main

import (
	"crypto/sha256"
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
			"powershell", "-NoProfile", "-NonInteractive", "-Command",
			"if ((Get-AuthenticodeSignature '/tmp/osquery.pkg').Status -ne 'Valid') { exit 1 }",
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
		t.Skip("ownership is not checked on Windows, nothing is swept")
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
