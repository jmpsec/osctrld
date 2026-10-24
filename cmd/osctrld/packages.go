package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// packageFormat is the kind of osquery package a platform installs
type packageFormat string

const (
	pkgDeb packageFormat = "deb"
	pkgRPM packageFormat = "rpm"
	pkgPKG packageFormat = "pkg"
	pkgMSI packageFormat = "msi"
)

// osqueryPackagesBase is the distribution point the osctrl quick-add scripts use
const osqueryPackagesBase = "https://osquery-packages.s3.amazonaws.com"

// Go architecture names mapped onto each packaging convention. An architecture
// that is absent is an error rather than a guess, because a wrong URL would
// download a package for the wrong machine.
var (
	debArch = map[string]string{"amd64": "amd64", "arm64": "arm64"}
	rpmArch = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}
)

// osqueryPackageURL builds the download URL for one osquery version
func osqueryPackageURL(format packageFormat, version, goarch string) (string, error) {
	switch format {
	case pkgDeb:
		a, ok := debArch[goarch]
		if !ok {
			return "", fmt.Errorf("no deb package for architecture %s", goarch)
		}
		return fmt.Sprintf("%s/deb/osquery_%s-1.linux_%s.deb", osqueryPackagesBase, version, a), nil
	case pkgRPM:
		a, ok := rpmArch[goarch]
		if !ok {
			return "", fmt.Errorf("no rpm package for architecture %s", goarch)
		}
		return fmt.Sprintf("%s/rpm/osquery-%s-1.linux.%s.rpm", osqueryPackagesBase, version, a), nil
	case pkgPKG:
		return fmt.Sprintf("%s/darwin/osquery-%s.pkg", osqueryPackagesBase, version), nil
	case pkgMSI:
		return fmt.Sprintf("%s/windows/osquery-%s.msi", osqueryPackagesBase, version), nil
	}
	return "", fmt.Errorf("unknown package format %s", format)
}

// linuxPackageFormat picks deb or rpm by probing for RPM markers, replacing the
// script's "rpm -q -f /usr/bin/rpm" exit-code trick. Markers use absolute paths so
// they resolve correctly when root is "" (production); filepath.Join("", "/path")
// yields "/path", and filepath.Join("/tmp/xyz", "/path") yields "/tmp/xyz/path"
// for test directory scoping.
func linuxPackageFormat(root string) packageFormat {
	for _, marker := range []string{"/usr/bin/rpm", "/etc/redhat-release"} {
		if checkFileExist(filepath.Join(root, marker)) {
			return pkgRPM
		}
	}
	return pkgDeb
}

// packageFormatFor resolves the package format for a platform
func packageFormatFor(goos, root string) (packageFormat, error) {
	switch goos {
	case DarwinOS:
		return pkgPKG, nil
	case WindowsOS:
		return pkgMSI, nil
	case LinuxOS:
		return linuxPackageFormat(root), nil
	}
	return "", fmt.Errorf("installing osquery is not supported on %s", goos)
}

// maxPackageSize caps a package download; a var so tests can lower it
var maxPackageSize int64 = 512 << 20

// errDigestMismatch marks a downloaded package whose SHA-256 is not the expected one
var errDigestMismatch = errors.New("package digest mismatch")

// resolveDigest picks the expected package digest. The server's value wins so a
// future osctrl release can turn verification on for every node at once; the
// configured value is the fallback until then. An empty result means there is
// nothing to verify against.
func resolveDigest(serverDigest, configDigest string) string {
	if serverDigest != "" {
		return serverDigest
	}
	return configDigest
}

// packageURLExt returns the file extension for a package URL, using the URL's
// path rather than its raw text so a query string (e.g. a mirror's
// "?token=...") is not mistaken for part of the extension. A URL that fails to
// parse falls back to the raw-text extension rather than erroring, since a
// weird URL should not block an otherwise-working install.
func packageURLExt(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return filepath.Ext(rawURL)
	}
	return filepath.Ext(u.Path)
}

// downloadPackage fetches url and verifies its SHA-256 against digest, returning
// the path of a temporary file the caller must remove. An empty digest is
// refused unless allowUnverified is set, in which case the computed digest is
// logged so an operator can record it.
func downloadPackage(url, digest string, allowUnverified, insecure bool) (string, error) {
	if digest == "" && !allowUnverified {
		return "", fmt.Errorf("no SHA-256 available to verify %s - set --osquery-sha256, or pass --allow-unverified to install without verification", url)
	}
	resp, err := SendRequestStream(http.MethodGet, url, nil, map[string]string{}, insecure)
	if err != nil {
		return "", fmt.Errorf("error downloading %s - %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, url)
	}
	if resp.ContentLength > maxPackageSize {
		return "", fmt.Errorf("package %s exceeds the %d byte limit", url, maxPackageSize)
	}
	f, err := os.CreateTemp("", downloadTempPrefix+"*"+packageURLExt(url))
	if err != nil {
		return "", fmt.Errorf("error creating temporary file - %v", err)
	}
	fail := func(err error) (string, error) {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", err
	}
	hasher := sha256.New()
	n, err := io.Copy(f, io.TeeReader(io.LimitReader(resp.Body, maxPackageSize+1), hasher))
	if err != nil {
		return fail(fmt.Errorf("error writing package to %s - %v", f.Name(), err))
	}
	if n > maxPackageSize {
		return fail(fmt.Errorf("package %s exceeds the %d byte limit", url, maxPackageSize))
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	if digest == "" {
		log.Warn().Str("url", url).Str("sha256", sum).Msg("installing an unverified osquery package")
	} else if !strings.EqualFold(sum, digest) {
		return fail(fmt.Errorf("%w for %s - expected %s, got %s", errDigestMismatch, url, digest, sum))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("error writing package to %s - %v", f.Name(), err)
	}
	log.Debug().Str("path", f.Name()).Int64("bytes", n).Msg("osquery package downloaded")
	return f.Name(), nil
}

// downloadTempPrefix names osctrld's package downloads in os.TempDir, so a
// download a SIGTERM interrupted can be found and swept later
const downloadTempPrefix = "osctrld-pkg-"

// staleDownloadAge is how old a leftover download must be before it is swept;
// a download in progress keeps its mtime fresh
var staleDownloadAge = time.Hour

// sweepStaleDownloads removes leftover downloads older than maxAge from
// os.TempDir: only regular files of this user with osctrld's name, never
// following a symlink nor entering a directory
func sweepStaleDownloads(maxAge time.Duration) {
	dir := os.TempDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Debug().Err(err).Str("dir", dir).Msg("cannot list the temporary directory")
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), downloadTempPrefix) {
			continue
		}
		full := filepath.Join(dir, e.Name())
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() || !ownedByCurrentUser(full, info) || time.Since(info.ModTime()) < maxAge {
			continue
		}
		if err := removeManagedFile(dir, e.Name()); err != nil {
			log.Debug().Err(err).Str("file", e.Name()).Msg("cannot remove stale package download")
			continue
		}
		log.Debug().Str("file", e.Name()).Msg("removed stale package download")
	}
}

// verifyPackageSignature runs the platform's own signature check as defence in
// depth, after the SHA-256 gate and never instead of it. deb and rpm have no
// standalone signature to verify against without importing a keyring, which is
// precisely why the digest gate is the primary control.
func verifyPackageSignature(format packageFormat, path string) error {
	switch format {
	case pkgPKG:
		if err := runCommand("pkgutil", "--check-signature", path); err != nil {
			return fmt.Errorf("package signature check failed for %s - %v", path, err)
		}
	case pkgMSI:
		script := fmt.Sprintf("if ((Get-AuthenticodeSignature '%s').Status -ne 'Valid') { exit 1 }", path)
		if err := runCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", script); err != nil {
			return fmt.Errorf("authenticode signature check failed for %s - %v", path, err)
		}
	}
	return nil
}

// installPackage verifies the package signature where the platform offers one,
// then runs the platform's installer against the downloaded file.
func installPackage(format packageFormat, path string) error {
	return installPackageAs(format, path, false)
}

// installPackageAs is installPackage that can also install an older version
// than the one present. Only rpm needs a flag for that.
func installPackageAs(format packageFormat, path string, downgrade bool) error {
	if downgrade && format == pkgMSI {
		return errors.New("downgrade is not supported for msi packages")
	}
	if err := verifyPackageSignature(format, path); err != nil {
		return err
	}
	switch format {
	case pkgDeb:
		return runCommand("dpkg", "-i", path)
	case pkgRPM:
		if downgrade {
			return runCommand("rpm", "-Uvh", "--oldpackage", path)
		}
		return runCommand("rpm", "-Uvh", path)
	case pkgPKG:
		return runCommand("installer", "-pkg", path, "-target", "/")
	case pkgMSI:
		pending, err := msiInstaller(context.Background(), path)
		if pending {
			// Only a note: the version check that follows decides the outcome
			log.Info().Str("package", path).Msg("msiexec reports a reboot is pending to finish the osquery install")
		}
		return err
	}
	return fmt.Errorf("unknown package format %s", format)
}

var (
	// msiexecTimeout bounds one msiexec run so a stuck installer cannot hang
	// the sync loop; a var for tests
	msiexecTimeout = 10 * time.Minute
	// msiInstaller runs msiexec; a seam for tests
	msiInstaller = runMSI
	// msiexecWaitDelay bounds the wait for msiexec's output pipes after it
	// exits or is killed, in case a child process still holds them
	msiexecWaitDelay = 5 * time.Second
)

// msiExitResult maps an msiexec exit code: 3010 and 1641 mean installed with
// a reboot pending, any other non-zero code is a failure
func msiExitResult(code int, out string) (rebootPending bool, err error) {
	switch code {
	case 0:
		return false, nil
	case 3010, 1641:
		return true, nil
	}
	return false, fmt.Errorf("msiexec failed with exit code %d (output: %s)", code, out)
}

// runMSI installs an MSI quietly without rebooting, killing msiexec after
// msiexecTimeout
func runMSI(ctx context.Context, path string) (rebootPending bool, err error) {
	args := []string{"/i", path, "/passive", "/norestart", "/qn"}
	log.Info().Str("command", "msiexec").Strs("args", args).Msg("running command")
	ctx, cancel := context.WithTimeout(ctx, msiexecTimeout)
	defer cancel()
	cmd := execCommand("msiexec", args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = msiexecWaitDelay
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("error running msiexec - %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return false, fmt.Errorf("msiexec timed out after %s - %v", msiexecTimeout, ctx.Err())
	}
	// A child still holding the output after a clean exit is not a failure
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return msiExitResult(exitErr.ExitCode(), out.String())
	}
	if err != nil {
		return false, fmt.Errorf("error running msiexec - %v", err)
	}
	return false, nil
}
