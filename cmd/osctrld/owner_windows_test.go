//go:build windows

package main

import (
	"os/exec"
	"path/filepath"
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
