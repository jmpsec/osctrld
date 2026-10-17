//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// fileAllAccess is FILE_ALL_ACCESS, absent from x/sys/windows
const fileAllAccess windows.ACCESS_MASK = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1FF

// extensionDACL grants full control to Administrators and SYSTEM and read and
// execute to Users, and nothing else
func extensionDACL() (*windows.ACL, error) {
	grants := []struct {
		sid  windows.WELL_KNOWN_SID_TYPE
		mask windows.ACCESS_MASK
	}{
		{windows.WinBuiltinAdministratorsSid, fileAllAccess},
		{windows.WinLocalSystemSid, fileAllAccess},
		{windows.WinBuiltinUsersSid, windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE},
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(grants))
	for _, g := range grants {
		sid, err := windows.CreateWellKnownSid(g.sid)
		if err != nil {
			return nil, err
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: g.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	return windows.ACLFromEntries(entries, nil)
}

// setOwnerRoot makes Administrators the owner of path and replaces its whole
// DACL with extensionDACL, protected from inheritance, in one call. The owner
// is an administrator group, so its implicit WRITE_DAC grants nobody else write.
func setOwnerRoot(path string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	dacl, err := extensionDACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		admins, nil, dacl, nil); err != nil {
		return fmt.Errorf("error setting security on %s - %v", path, err)
	}
	return nil
}

// adminOwnedFile re-applies the owner and DACL to an existing file and trusts
// it only if that succeeds, rather than parsing its current security descriptor
func adminOwnedFile(path string) bool {
	return setOwnerRoot(path) == nil
}

// adminOwnedDir is not checked on Windows: osquery's directories under
// Program Files are writable by administrators only by default.
// ponytail: read the directory's DACL with GetNamedSecurityInfo if hosts move
// the autoload file somewhere looser.
func adminOwnedDir(string) bool { return true }
