//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtensionFileSafePOSIX(t *testing.T) {
	dir := t.TempDir()
	file := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("x"), 0600))
		require.NoError(t, os.Chmod(p, mode))
		return p
	}
	asRoot := os.Geteuid() == 0

	assert.False(t, adminOwnedFile(file("writable", 0777)), "group/world-writable is never safe")
	assert.False(t, adminOwnedFile(file("setuid", 0755|os.ModeSetuid)), "special bits are not 0755")
	assert.Equal(t, asRoot, adminOwnedFile(file("good", 0755)), "0755 is safe only when owned by root")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(filepath.Join(dir, "good"), link))
	assert.False(t, adminOwnedFile(link), "a symlink is not followed")
	assert.False(t, adminOwnedFile(filepath.Join(dir, "missing")))
}

func TestAdminOwnedDirPOSIX(t *testing.T) {
	dir := t.TempDir()
	asRoot := os.Geteuid() == 0
	require.NoError(t, os.Chmod(dir, 0755))
	assert.Equal(t, asRoot, adminOwnedDir(dir), "0755 is safe only when owned by root")
	require.NoError(t, os.Chmod(dir, 0775))
	assert.False(t, adminOwnedDir(dir), "group-writable is never safe")
	require.NoError(t, os.Chmod(dir, 0755))
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(dir, link))
	assert.False(t, adminOwnedDir(link), "a symlink is not followed")
	assert.False(t, adminOwnedDir(filepath.Join(dir, "missing")))
}

// A FIFO where an extension goes is refused, never opened (which would block)
func TestSyncExtensionsRefusesFIFO(t *testing.T) {
	e := setupExt(t)
	x := e.extPath(t, "x")
	require.NoError(t, os.MkdirAll(e.dir, 0755))
	require.NoError(t, syscall.Mkfifo(x, 0644))
	e.srv.serve("x", "x-v1")

	done := make(chan error, 1)
	go func() {
		_, err := syncExtensionsStep(context.Background())
		done <- err
	}()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("syncExtensionsStep blocked on the FIFO")
	}
	s := statusFor(readExtState(t), "x")
	require.NotNil(t, s)
	assert.Equal(t, applyRejected, s.Result)
	info, err := os.Lstat(x)
	require.NoError(t, err)
	assert.Equal(t, os.ModeNamedPipe, info.Mode().Type(), "left alone")
}

// runAsRootOwning runs the app as if euid were 0 and files owned by this user
// were owned by root, since tests cannot create root-owned files
func runAsRootOwning(t *testing.T, args ...string) string {
	t.Helper()
	prevEuid, prevRoot := geteuid, rootUID
	t.Cleanup(func() { geteuid, rootUID = prevEuid, prevRoot })
	geteuid, rootUID = func() int { return 0 }, os.Getuid()
	t.Setenv("OSCTRL_CONFIG", "")
	out, err := runWithFreshFlags(t, args...)
	require.NoError(t, err, "unsafe ownership is a warning, never a refusal")
	return out
}

func writeTestConfig(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "osctrld.yaml")
	require.NoError(t, os.WriteFile(path, []byte("osctrld:\n  osctrlSecret: very-secret-value\n  environment: 11111111-1111-4111-8111-111111111111\n  baseurl: https://osctrl.example\n"), 0600))
	require.NoError(t, os.Chmod(path, mode))
	return path
}

func TestConfigOwnershipWarnedAsRoot(t *testing.T) {
	path := writeTestConfig(t, t.TempDir(), 0666)
	out := runAsRootOwning(t, "-c", path, "check-config")
	assert.Equal(t, 1, strings.Count(out, "world-writable"), out)
	assert.Equal(t, 1, strings.Count(out, "group-writable"), out)
	assert.Contains(t, out, "osctrld.yaml")
	assert.NotContains(t, out, "very-secret-value")
}

func TestConfigOwnershipGoodFileNotWarned(t *testing.T) {
	path := writeTestConfig(t, t.TempDir(), 0600)
	out := runAsRootOwning(t, "-c", path, "check-config")
	assert.NotContains(t, out, "WRN", out)
}

func TestConfigOwnershipNotCheckedWhenNotRoot(t *testing.T) {
	path := writeTestConfig(t, t.TempDir(), 0666)
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int { return 501 }
	t.Setenv("OSCTRL_CONFIG", "")
	out, err := runWithFreshFlags(t, "-c", path, "check-config")
	require.NoError(t, err)
	assert.NotContains(t, out, "writable", out)
}

func TestConfigOwnershipOtherOwnerWarned(t *testing.T) {
	path := writeTestConfig(t, t.TempDir(), 0600)
	prevEuid, prevRoot := geteuid, rootUID
	t.Cleanup(func() { geteuid, rootUID = prevEuid, prevRoot })
	geteuid, rootUID = func() int { return 0 }, os.Getuid()+1
	t.Setenv("OSCTRL_CONFIG", "")
	out, err := runWithFreshFlags(t, "-c", path, "check-config")
	require.NoError(t, err)
	// The file and its directory both belong to this (non-"root") user
	assert.Equal(t, 2, strings.Count(out, "not owned by root"), out)
}

func TestConfigOwnershipSymlinkTargetChecked(t *testing.T) {
	target := writeTestConfig(t, t.TempDir(), 0666)
	link := filepath.Join(t.TempDir(), "osctrld.yaml")
	require.NoError(t, os.Symlink(target, link))
	out := runAsRootOwning(t, "-c", link, "check-config")
	assert.Equal(t, 1, strings.Count(out, "world-writable"), out)
}

func TestConfigOwnershipWritableDirectoryWarned(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0777))
	path := writeTestConfig(t, dir, 0600)
	out := runAsRootOwning(t, "-c", path, "check-config")
	assert.Equal(t, 1, strings.Count(out, "world-writable"), out)
	assert.Contains(t, out, "directory")
}

// The mode is exact whatever the umask, for created and replaced files
func TestWriteContentExistsModeIgnoresUmask(t *testing.T) {
	dir := t.TempDir()
	prev := syscall.Umask(0777)
	t.Cleanup(func() { syscall.Umask(prev) })
	for _, mode := range []os.FileMode{0600, 0700} {
		path := filepath.Join(dir, mode.String())
		_, err := writeContentExists(path, "a", "test", true, mode)
		require.NoError(t, err)
		_, err = writeContentExists(path, "b", "test", true, mode)
		require.NoError(t, err)
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, mode, info.Mode().Perm())
	}
	require.NoError(t, writeFileAtomic(filepath.Join(dir, "state"), []byte("{}"), 0600, false))
	info, err := os.Stat(filepath.Join(dir, "state"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
