//go:build !windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsqueryInstallDecision(t *testing.T) {
	cases := []struct {
		name      string
		installed string
		required  string
		expected  bool
	}{
		{"not installed", "", "5.12.1", true},
		{"older must install", "5.11.0", "5.12.1", true},
		{"much older must install", "4.9.0", "5.0.0", true},
		{"equal is skipped", "5.12.1", "5.12.1", false},
		{"newer is left alone", "5.13.0", "5.12.1", false},
		{"newer major is left alone", "6.0.0", "5.12.1", false},
		{"unparseable installed is reinstalled", "5.12.x", "5.12.1", true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, osqueryInstallDecision(tt.installed, tt.required))
		})
	}
}

func TestInstallNodeRequiresPrivileges(t *testing.T) {
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int { return 501 }

	err := installNode(context.Background(), newTestCLICommand())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestEnsureOsquerySkipsWhenCurrent(t *testing.T) {
	recorded := fakeExec(t)

	prevVersion := osqueryVersionReader
	t.Cleanup(func() { osqueryVersionReader = prevVersion })
	osqueryVersionReader = func() string { return "5.12.1" }

	require.NoError(t, ensureOsquery(VerifyResponse{OsqueryVersion: "5.12.1"}))
	assert.Empty(t, *recorded, "nothing should be installed when the version already matches")
}

func TestRemoveIfExists(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(present, []byte("s3cr3t"), 0600))

	require.NoError(t, removeIfExists(present, "secret"))
	assert.NoFileExists(t, present)

	// An absent file is reported, not an error: uninstall must be idempotent
	require.NoError(t, removeIfExists(filepath.Join(dir, "never-existed"), "secret"))
}

func TestUninstallNodeRequiresPrivileges(t *testing.T) {
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int { return 501 }

	err := uninstallNode(context.Background(), newTestCLICommand())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestUninstallNodeRemovesTheThreeFiles(t *testing.T) {
	prevUID := geteuid
	t.Cleanup(func() { geteuid = prevUID })
	geteuid = func() int { return 0 }
	fakeExec(t)
	fakeLookPath(t, "systemctl")

	dir := t.TempDir()
	prevConfig := appConfig
	t.Cleanup(func() { appConfig = prevConfig })
	appConfig = Configuration{
		OsquerySecretFile: filepath.Join(dir, "osquery.secret"),
		OsqueryFlagFile:   filepath.Join(dir, "osquery.flags"),
		OsqueryCertFile:   filepath.Join(dir, "osctrl.crt"),
	}
	for _, p := range []string{appConfig.OsquerySecretFile, appConfig.OsqueryFlagFile, appConfig.OsqueryCertFile} {
		require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
	}

	require.NoError(t, uninstallNode(context.Background(), newTestCLICommand()))

	assert.NoFileExists(t, appConfig.OsquerySecretFile)
	assert.NoFileExists(t, appConfig.OsqueryFlagFile)
	assert.NoFileExists(t, appConfig.OsqueryCertFile)
}

// saveInstallGlobals restores every package global these install tests mutate
func saveInstallGlobals(t *testing.T) {
	t.Helper()
	prevConfig, prevURLs, prevUID, prevReader := appConfig, osctrlURLs, geteuid, osqueryVersionReader
	t.Cleanup(func() {
		appConfig, osctrlURLs, geteuid, osqueryVersionReader = prevConfig, prevURLs, prevUID, prevReader
	})
}

// osctrl's verify response carries one server-wide osquery_sha256, and osquery
// ships a different package per format and architecture, so a mismatch has to
// say where the expected digest came from or the operator cannot tell a wrong
// server digest from a wrong --osquery-sha256.
func TestEnsureOsquerySaysWhereTheExpectedDigestCameFrom(t *testing.T) {
	payload := []byte("pretend osquery package")
	good := fmt.Sprintf("%x", sha256.Sum256(payload))
	wrong := "00" + good[2:]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	cases := []struct {
		name         string
		serverDigest string
		configDigest string
		source       string
	}{
		{"server digest overrides the node's own", wrong, good, "osctrl server"},
		{"node digest when the server sends none", "", wrong, "--osquery-sha256"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			saveInstallGlobals(t)
			recorded := fakeExec(t)
			osqueryVersionReader = func() string { return "" }
			appConfig.OsqueryPackage = server.URL + "/osquery-5.23.1.pkg"
			appConfig.OsquerySHA256 = tt.configDigest

			err := ensureOsquery(VerifyResponse{OsqueryVersion: "5.23.1", OsquerySHA256: tt.serverDigest})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "mismatch")
			assert.Contains(t, err.Error(), tt.source)
			assert.Empty(t, *recorded, "a mismatched package must never reach the installer")
		})
	}
}

// osctrl serves the operator-edited environment flags, which end in a newline.
// install must write them exactly as the flags and cert commands do (trimmed),
// so all three writers leave byte-identical files.
func TestInstallNodeWritesTrimmedFlagsAndCert(t *testing.T) {
	saveInstallGlobals(t)
	fakeExec(t)
	fakeLookPath(t, "systemctl")
	geteuid = func() int { return 0 }
	osqueryVersionReader = func() string { return "5.23.1" }

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Flags:          "--host_identifier=uuid\n--tls_hostname=osctrl.example\n",
			Certificate:    "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n",
			OsqueryVersion: "5.23.1",
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	appConfig = Configuration{
		OsctrlSecret:      "test-secret",
		OsquerySecretFile: filepath.Join(dir, "osquery.secret"),
		OsqueryFlagFile:   filepath.Join(dir, "osquery.flags"),
		OsqueryCertFile:   filepath.Join(dir, "certs", "osctrl.crt"),
	}
	osctrlURLs.Verify = server.URL

	require.NoError(t, installNode(context.Background(), newTestCLICommand()))

	flags, err := os.ReadFile(appConfig.OsqueryFlagFile)
	require.NoError(t, err)
	assert.Equal(t, "--host_identifier=uuid\n--tls_hostname=osctrl.example", string(flags))
	cert, err := os.ReadFile(appConfig.OsqueryCertFile)
	require.NoError(t, err)
	assert.Equal(t, "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----", string(cert))
}

// --insecure is for osctrl and a self-hosted mirror; the official package
// server has a public certificate, so its download always verifies it
func TestInstallNodeInsecureOnlyForOsctrlAndMirrors(t *testing.T) {
	payload := []byte("pretend osquery package")
	for _, tt := range []struct {
		name     string
		override bool
	}{
		{"official URL verifies the certificate", false},
		{"override URL honours --insecure", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			saveInstallGlobals(t)
			tempPackages(t)
			recorded := fakeExec(t)
			fakeLookPath(t, "systemctl")
			geteuid = func() int { return 0 }
			osqueryVersionReader = func() string { return "" }
			var mu sync.Mutex
			verifies, pkgs := 0, 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/verify" {
					verifies++
					_ = json.NewEncoder(w).Encode(VerifyResponse{Flags: "--x", Certificate: "C", OsqueryVersion: "5.23.1",
						OsquerySHA256: fmt.Sprintf("%x", sha256.Sum256(payload))})
					return
				}
				pkgs++
				_, _ = w.Write(payload)
			}))
			server.Config.ErrorLog = stdlog.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			prevURL := installPackageURL
			t.Cleanup(func() { installPackageURL = prevURL })
			installPackageURL = func(packageFormat, string, string) (string, error) { return server.URL + "/osquery.pkg", nil }

			dir := t.TempDir()
			appConfig = Configuration{
				OsctrlSecret:      "test-secret",
				OsquerySecretFile: filepath.Join(dir, "osquery.secret"),
				OsqueryFlagFile:   filepath.Join(dir, "osquery.flags"),
				OsqueryCertFile:   filepath.Join(dir, "osctrl.crt"),
				OsqueryPackage:    defEmptyValue,
				Insecure:          true,
			}
			if tt.override {
				appConfig.OsqueryPackage = server.URL + "/mirror/osquery.pkg"
			}
			osctrlURLs.Verify = server.URL + "/verify"

			err := installNode(context.Background(), newTestCLICommand())
			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, 1, verifies, "osctrl is still reached with --insecure")
			if tt.override {
				require.NoError(t, err)
				assert.Equal(t, 1, pkgs)
				assert.NotEmpty(t, *recorded)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), "certificate")
			assert.Zero(t, pkgs, "a self-signed certificate is refused despite --insecure")
			assert.Empty(t, *recorded, "nothing installed")
		})
	}
}
