//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestExtensionDACL(t *testing.T) {
	acl, err := extensionDACL()
	require.NoError(t, err)
	want := []struct {
		sid  windows.WELL_KNOWN_SID_TYPE
		mask windows.ACCESS_MASK
	}{
		{windows.WinBuiltinAdministratorsSid, fileAllAccess},
		{windows.WinLocalSystemSid, fileAllAccess},
		{windows.WinBuiltinUsersSid, windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE},
	}
	require.Equal(t, uint16(len(want)), acl.AceCount, "no entry beyond the three granted")
	got := map[string]windows.ACCESS_MASK{}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(acl, i, &ace))
		assert.Equal(t, uint8(windows.ACCESS_ALLOWED_ACE_TYPE), ace.Header.AceType)
		assert.Zero(t, ace.Header.AceFlags, "no inheritance flags")
		got[(*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()] = ace.Mask
	}
	for _, w := range want {
		sid, err := windows.CreateWellKnownSid(w.sid)
		require.NoError(t, err)
		assert.Equal(t, w.mask, got[sid.String()], sid.String())
	}
}

// A junction reports ModeDir with ModeIrregular: it is not a real directory
func TestEnsureExtensionsDirRefusesJunction(t *testing.T) {
	owned := fakeSetOwner(t)
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "extensions")
	require.NoError(t, exec.Command("cmd", "/c", "mklink", "/J", link, target).Run())
	assert.Error(t, ensureExtensionsDir(link))
	assert.Empty(t, *owned)
}

func TestStashACLAndOwner(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, applyStashACLOS(dir))
	info, err := os.Lstat(dir)
	require.NoError(t, err)
	// owner depends on who runs the test; only the call must not panic
	_ = ownedByCurrentUser(dir, info)
	assert.False(t, ownedByCurrentUser(filepath.Join(dir, "missing"), info))

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	ctrl, _, err := sd.Control()
	require.NoError(t, err)
	assert.NotZero(t, ctrl&windows.SE_DACL_PROTECTED, "inheritance is blocked")
	dacl, _, err := sd.DACL()
	require.NoError(t, err)
	require.Equal(t, uint16(2), dacl.AceCount, "SYSTEM and Administrators only")
	for i := uint32(0); i < 2; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		require.NoError(t, windows.GetAce(dacl, i, &ace))
		assert.True(t, trustedOwnerSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()))
	}
}

// A junction as the stash is refused before the ACL is applied through it
func TestEnsureUpgradeDirRefusesJunction(t *testing.T) {
	setupUpgrade(t)
	prev := applyStashACL
	t.Cleanup(func() { applyStashACL = prev })
	called := false
	applyStashACL = func(string) error { called = true; return nil }
	require.NoError(t, exec.Command("cmd", "/c", "mklink", "/J", upgradeDir(), t.TempDir()).Run())
	_, err := ensureUpgradeDir()
	assert.Error(t, err)
	assert.False(t, called)
}

// assertSecretDACL checks path has a protected DACL of SYSTEM and
// Administrators full control and nothing else
func assertSecretDACL(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	ctrl, _, err := sd.Control()
	require.NoError(t, err)
	assert.NotZero(t, ctrl&windows.SE_DACL_PROTECTED, "inheritance is blocked")
	s, err := readSecurity(path)
	require.NoError(t, err)
	require.Len(t, s.ACEs, 2, "SYSTEM and Administrators only")
	for _, a := range s.ACEs {
		assert.True(t, a.Allow)
		assert.True(t, trustedOwnerSID(a.SID), a.SID)
		assert.Equal(t, uint32(fileAllAccess), a.Mask)
	}
}

// The secret's temp file carries its DACL from creation, and stays writable
// through the handle osctrld holds
func TestCreateTempRestricted(t *testing.T) {
	dir := t.TempDir()
	f, err := createTempOS(dir, ".osquery.secret.tmp-*", true)
	require.NoError(t, err)
	assertSecretDACL(t, f.Name())
	require.NoError(t, f.Chmod(0600))
	_, err = f.WriteString("s3cr3t")
	require.NoError(t, err)
	require.NoError(t, f.Sync())
	require.NoError(t, f.Close())
	assert.True(t, strings.HasPrefix(filepath.Base(f.Name()), ".osquery.secret.tmp-"))

	path := filepath.Join(dir, "osquery.secret")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0600))
	require.NoError(t, os.Rename(f.Name(), path), "rename over an existing file")
	assertSecretDACL(t, path)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", string(b))
}

// A temp dir under the user profile grants the user full control: not admin-only
func TestAdminOwnedDirReadsDACL(t *testing.T) {
	dir := t.TempDir()
	assert.False(t, adminOwnedDir(dir))
	f := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0600))
	assert.False(t, adminOwnedFile(f))
	assert.False(t, adminOwnedDir(f), "a file is not a directory")
	assert.False(t, adminOwnedFile(dir), "a directory is not a file")
}
