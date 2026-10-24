package main

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustedOwnerSID(t *testing.T) {
	assert.True(t, trustedOwnerSID("S-1-5-18"))
	assert.True(t, trustedOwnerSID("S-1-5-32-544"))
	for _, s := range []string{"S-1-5-32-545", "S-1-5-11", "S-1-5-21-1-2-3-1001", ""} {
		assert.False(t, trustedOwnerSID(s), s)
	}
}

func TestStashDACLHasNoUsers(t *testing.T) {
	assert.Contains(t, stashDACLSDDL, ";;;SY)")
	assert.Contains(t, stashDACLSDDL, ";;;BA)")
	assert.Contains(t, stashDACLSDDL, "D:P", "protected from inheritance")
	for _, s := range []string{";;;BU)", ";;;WD)", ";;;AU)", ";;;IU)"} {
		assert.NotContains(t, stashDACLSDDL, s)
	}
}

func TestEnsureUpgradeDirAppliesACL(t *testing.T) {
	setupUpgrade(t)
	prevACL := applyStashACL
	t.Cleanup(func() { applyStashACL = prevACL })
	var got []string
	applyStashACL = func(p string) error { got = append(got, p); return nil }

	upgradeGOOS = LinuxOS
	_, err := ensureUpgradeDir()
	require.NoError(t, err)
	assert.Empty(t, got, "not applied off Windows")

	upgradeGOOS = WindowsOS
	dir, err := ensureUpgradeDir()
	require.NoError(t, err)
	assert.Equal(t, []string{dir}, got)

	applyStashACL = func(string) error { return errors.New("denied") }
	_, err = ensureUpgradeDir()
	assert.Error(t, err)
}

// A symlink (on Windows, a junction) in place of the stash is refused before
// any ACL is applied through it
func TestEnsureUpgradeDirRefusesLinkBeforeACL(t *testing.T) {
	setupUpgrade(t)
	prevACL := applyStashACL
	t.Cleanup(func() { applyStashACL = prevACL })
	var got []string
	applyStashACL = func(p string) error { got = append(got, p); return nil }
	upgradeGOOS = WindowsOS
	require.NoError(t, os.Symlink(t.TempDir(), upgradeDir()))
	_, err := ensureUpgradeDir()
	assert.Error(t, err)
	assert.Empty(t, got)
}

// A stash left by an earlier run is re-restricted when read back
func TestLoadSnapshotReappliesACL(t *testing.T) {
	setupUpgrade(t)
	prevACL := applyStashACL
	t.Cleanup(func() { applyStashACL = prevACL })
	var got []string
	applyStashACL = func(p string) error { got = append(got, p); return nil }
	upgradeGOOS = LinuxOS
	dir, err := ensureUpgradeDir()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(snapshotPath(), []byte("{}"), 0600))
	upgradeGOOS = WindowsOS
	_, err = loadSnapshot()
	require.NoError(t, err)
	assert.Equal(t, []string{dir}, got)
}
