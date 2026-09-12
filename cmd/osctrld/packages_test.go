package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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
