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

func TestFileACLFor(t *testing.T) {
	cases := []struct {
		name, path, secret, goos string
		want                     fileACL
	}{
		{"secret", "/etc/osquery/osquery.secret", "/etc/osquery/osquery.secret", LinuxOS, aclSecret},
		{"secret uncleaned", "/etc/osquery/./osquery.secret", "/etc/osquery/osquery.secret", LinuxOS, aclSecret},
		{"flagfile", "/etc/osquery/osquery.flags", "/etc/osquery/osquery.secret", LinuxOS, aclDefault},
		{"certificate", "/etc/osquery/certs/osctrl.crt", "/etc/osquery/osquery.secret", LinuxOS, aclDefault},
		{"autoload", "/etc/osquery/extensions.load", "/etc/osquery/osquery.secret", LinuxOS, aclDefault},
		{"no secret configured", "/etc/osquery/osquery.secret", "", LinuxOS, aclDefault},
		{"posix is case sensitive", "/etc/osquery/OSQUERY.secret", "/etc/osquery/osquery.secret", LinuxOS, aclDefault},
		{"windows secret", `C:\Program Files\osquery\osquery.secret`, `C:\Program Files\osquery\osquery.secret`, WindowsOS, aclSecret},
		{"windows is case insensitive", `c:\program files\osquery\OSQUERY.SECRET`, `C:\Program Files\osquery\osquery.secret`, WindowsOS, aclSecret},
		{"windows flagfile", `C:\Program Files\osquery\osquery.flags`, `C:\Program Files\osquery\osquery.secret`, WindowsOS, aclDefault},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fileACLFor(tt.path, tt.secret, tt.goos))
		})
	}
}

func TestSecretDACLHasNoUsers(t *testing.T) {
	assert.Equal(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)", secretDACLSDDL, "protected, not inherited, nothing inheritable")
}

// Masks as icacls shows them on a default install
const (
	maskFull        uint32 = 0x1F01FF // F
	maskModify      uint32 = 0x1301BF // M
	maskRX          uint32 = 0x1200A9 // RX
	genericAll      uint32 = 0x10000000
	genericRE       uint32 = 0xA0000000 // GR, GE
	sidUsers               = "S-1-5-32-545"
	sidSystem              = "S-1-5-18"
	sidAdmins              = "S-1-5-32-544"
	sidCreatorOwner        = "S-1-3-0"
	sidAppPackages         = "S-1-15-2-1"
)

func TestAdminOnlyWrite(t *testing.T) {
	allow := func(sid string, mask uint32) aceInfo { return aceInfo{SID: sid, Mask: mask, Allow: true} }
	// C:\Program Files\osquery as the MSI leaves it, inherited from Program Files
	programFiles := []aceInfo{
		allow(sidTrustedInstaller, maskFull), allow(sidTrustedInstaller, genericAll),
		allow(sidSystem, maskModify), allow(sidSystem, genericAll),
		allow(sidAdmins, maskModify), allow(sidAdmins, genericAll),
		allow(sidUsers, maskRX), allow(sidUsers, genericRE),
		allow(sidCreatorOwner, genericAll),
		allow(sidAppPackages, maskRX), allow(sidAppPackages, genericRE),
	}
	// osquery's Set-SafePermissions and osctrld's extensionDACL
	hardened := []aceInfo{allow(sidAdmins, maskFull), allow(sidSystem, maskFull), allow(sidUsers, maskRX)}
	with := func(base []aceInfo, extra ...aceInfo) []aceInfo {
		return append(append([]aceInfo{}, base...), extra...)
	}
	cases := []struct {
		name string
		sec  securityInfo
		safe bool
	}{
		{"program files default", securityInfo{Owner: sidAdmins, ACEs: programFiles}, true},
		{"owned by SYSTEM", securityInfo{Owner: sidSystem, ACEs: programFiles}, true},
		{"owned by TrustedInstaller", securityInfo{Owner: sidTrustedInstaller, ACEs: programFiles}, true},
		{"hardened", securityInfo{Owner: sidAdmins, ACEs: hardened}, true},
		{"deny entries never make it unsafe", securityInfo{Owner: sidAdmins, ACEs: with(hardened, aceInfo{SID: sidUsers, Mask: maskFull})}, true},
		{"owned by Users", securityInfo{Owner: sidUsers, ACEs: hardened}, false},
		{"owned by a user", securityInfo{Owner: "S-1-5-21-1-2-3-1001", ACEs: hardened}, false},
		{"no owner", securityInfo{ACEs: hardened}, false},
		{"null DACL", securityInfo{Owner: sidAdmins, NoDACL: true}, false},
		{"Users add file", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow(sidUsers, 0x2))}, false},
		{"Users add subdirectory", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow(sidUsers, 0x4))}, false},
		{"Users delete child", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow(sidUsers, 0x40))}, false},
		{"Users delete", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow(sidUsers, 0x10000))}, false},
		{"Users write DAC", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow(sidUsers, 0x40000))}, false},
		{"Users write owner", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow(sidUsers, 0x80000))}, false},
		{"Everyone generic write", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow("S-1-1-0", 0x40000000))}, false},
		{"Authenticated Users modify", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow("S-1-5-11", maskModify))}, false},
		{"a user generic all", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow("S-1-5-21-1-2-3-1001", genericAll))}, false},
		{"OWNER RIGHTS write", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow("S-1-3-4", 0x2))}, false},
		{"CREATOR GROUP generic all", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow("S-1-3-1", genericAll))}, false},
		// ProgramData lets Users create files and folders; inheritable entries
		// count too, since files osctrld creates there would get them
		{"ProgramData Users create", securityInfo{Owner: sidSystem, ACEs: with(hardened, allow(sidUsers, 0x2|0x4|0x10|0x100))}, false},
		{"unreadable entry", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow("", maskRX|0x2))}, false},
		{"Users read only", securityInfo{Owner: sidAdmins, ACEs: with(hardened, allow(sidUsers, maskRX|0x10|0x100))}, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.safe, adminOnlyWrite(tt.sec))
		})
	}
}
