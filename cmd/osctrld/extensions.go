package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/rs/zerolog/log"
)

// maxExtensionSize caps any single extension download
const maxExtensionSize = 64 << 20

var (
	extensionNameRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	extensionSHA256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// setOwner hands a file or directory to the administrator before osquery may
// load it. It is a seam so tests run without root.
var setOwner = setOwnerRoot

// extensionFileSafe reports whether an existing extension file is owned and
// protected so only an administrator can have written it. A seam for tests.
var extensionFileSafe = adminOwnedFile

func retrieveExtensionManifest(req ExtensionsRequest, url string, insecure bool) ([]ExtensionEntry, error) {
	body, err := genericRetrieve(url, insecure, req)
	// An osctrl without extensions support answers 404. Treat it as an empty
	// manifest so the daemon does not log a failure every cycle; a wrong URL or
	// environment still fails loudly earlier in the cycle, on flags and cert.
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.code == http.StatusNotFound {
		log.Debug().Msg("osctrl server does not serve extensions, skipping")
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error retrieving extension manifest - %w", err)
	}
	var entries []ExtensionEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("error parsing extension manifest - %v", err)
	}
	return entries, nil
}

// extensionFileName turns an extension name osctrl serves into the file osquery
// autoloads. The name comes from the network and the file is written as root, so only a short
// plain name is accepted, never a path.
func extensionFileName(name, goos string) (string, error) {
	if !extensionNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid extension name %q", name)
	}
	if goos == WindowsOS {
		return name + ".exe", nil
	}
	return name + ".ext", nil
}

// fileSHA256 hashes a regular file on disk; anything else (a FIFO would block
// the open) is refused
func fileSHA256(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// installExtension places one extension in dir, returning its path and whether
// it was written. The download URL is built from the configured osctrl base and
// environment (osctrlURLs.URL); e.URL is never used, so a manifest cannot send
// osctrld, or its secret, to another host. The file is streamed into a temp file
// in dir, verified against e.Size and e.SHA256, owned by the administrator and
// only then renamed over the target.
func installExtension(dir string, e ExtensionEntry, goos string, secret string, insecure bool) (path string, changed bool, err error) {
	fileName, err := extensionFileName(e.Name, goos)
	if err != nil {
		return "", false, err
	}
	if !extensionSHA256Re.MatchString(e.SHA256) {
		return "", false, fmt.Errorf("extension %s: invalid sha256 %q", e.Name, e.SHA256)
	}
	if e.Size <= 0 || e.Size > maxExtensionSize {
		return "", false, fmt.Errorf("extension %s: size %d outside 1..%d", e.Name, e.Size, maxExtensionSize)
	}
	path = filepath.Join(dir, fileName)
	info, err := os.Lstat(path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return "", false, fmt.Errorf("extension %s: %s is not a regular file, refusing to replace it", e.Name, path)
	case err == nil:
		// The hash is public, so matching bytes alone prove nothing about who
		// can rewrite the file; anything not safely owned is replaced below
		if sum, err := fileSHA256(path); err == nil && sum == e.SHA256 && extensionFileSafe(path) {
			return path, false, nil
		}
	case !os.IsNotExist(err):
		return "", false, fmt.Errorf("extension %s: %v", e.Name, err)
	}

	reqBody, err := json.Marshal(ExtensionDownloadRequest{OsctrlSecret: secret, SHA256: e.SHA256})
	if err != nil {
		return "", false, err
	}
	url := fmt.Sprintf(OsctrlURLExtension, osctrlURLs.URL)
	resp, err := SendRequestStream(http.MethodPost, url, bytes.NewReader(reqBody), map[string]string{}, insecure)
	if err != nil {
		return "", false, fmt.Errorf("extension %s: error downloading - %v", e.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("extension %s: HTTP %d downloading", e.Name, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dir, "."+fileName+".tmp-*")
	if err != nil {
		return "", false, fmt.Errorf("extension %s: %v", e.Name, err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	// One byte past the size is enough to tell an oversized body
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, e.Size+1))
	if err != nil {
		return "", false, fmt.Errorf("extension %s: error downloading - %v", e.Name, err)
	}
	if n != e.Size {
		return "", false, fmt.Errorf("extension %s: size mismatch - expected %d, got %d or more", e.Name, e.Size, n)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); sum != e.SHA256 {
		return "", false, fmt.Errorf("extension %s: sha256 mismatch - expected %s, got %s", e.Name, e.SHA256, sum)
	}
	if err = tmp.Sync(); err != nil {
		return "", false, fmt.Errorf("extension %s: %v", e.Name, err)
	}
	if err = tmp.Close(); err != nil {
		return "", false, fmt.Errorf("extension %s: %v", e.Name, err)
	}
	if err = setOwner(tmp.Name()); err != nil {
		return "", false, fmt.Errorf("extension %s: error setting owner - %v", e.Name, err)
	}
	if err = os.Chmod(tmp.Name(), 0755); err != nil {
		return "", false, fmt.Errorf("extension %s: %v", e.Name, err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return "", false, fmt.Errorf("extension %s: %v", e.Name, err)
	}
	syncDir(dir)
	return path, true, nil
}

// ensureExtensionsDir makes dir an administrator-owned 0755 directory. A
// symlink is refused, since osctrld writes into it as root.
func ensureExtensionsDir(dir string) error {
	// Clean drops a trailing slash, which would make Lstat follow a symlink
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("error creating extensions directory - %v", err)
		}
		info, err = os.Lstat(dir)
	}
	if err != nil {
		return fmt.Errorf("error checking extensions directory - %v", err)
	}
	// Not IsDir: a Windows junction reports ModeDir with ModeIrregular
	if info.Mode().Type() != fs.ModeDir {
		return fmt.Errorf("extensions directory %s is not a directory, refusing to use it", dir)
	}
	if err := setOwner(dir); err != nil {
		return fmt.Errorf("error setting owner of %s - %v", dir, err)
	}
	// Repairs group/world-writable modes; MkdirAll's mode is also subject to umask
	if err := os.Chmod(dir, 0755); err != nil {
		return fmt.Errorf("error setting mode on %s - %v", dir, err)
	}
	return nil
}

// removeManagedFile removes one file osctrld placed in dir. Anything that is
// not a regular file directly in dir is refused; an absent file is not an error.
func removeManagedFile(dir, fileName string) error {
	dir = filepath.Clean(dir)
	path := filepath.Join(dir, fileName)
	if filepath.Dir(path) != dir {
		return fmt.Errorf("refusing to remove %q, it is not a file in %s", fileName, dir)
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove %s, it is not a regular file", path)
	}
	return os.Remove(path)
}
