//go:build windows

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

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
	dacl, err := extensionDACL()
	if err != nil {
		return err
	}
	return setAdminOwnerAndDACL(path, dacl)
}

// applySecretACLOS makes Administrators the owner of path and replaces its
// DACL with secretDACLSDDL, protected from inheritance
func applySecretACLOS(path string) error {
	dacl, err := daclFromSDDL(secretDACLSDDL)
	if err != nil {
		return err
	}
	return setAdminOwnerAndDACL(path, dacl)
}

func setAdminOwnerAndDACL(path string, dacl *windows.ACL) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
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

func daclFromSDDL(sddl string) (*windows.ACL, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	return dacl, err
}

// createTempOS is os.CreateTemp, except that a restricted file is created with
// secretDACLSDDL in the same CreateFile call: no other account ever holds a
// handle to it, as one opened during a window with the inherited ACL could
// read what is written afterwards
func createTempOS(dir, pattern string, restricted bool) (*os.File, error) {
	if !restricted {
		return os.CreateTemp(dir, pattern)
	}
	sd, err := windows.SecurityDescriptorFromString(secretDACLSDDL)
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	prefix, suffix, _ := strings.Cut(pattern, "*")
	for range 100 {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(b)+suffix)
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, &fs.PathError{Op: "createtemp", Path: name, Err: err}
		}
		return os.NewFile(uintptr(h), name), nil
	}
	return nil, &fs.PathError{Op: "createtemp", Path: filepath.Join(dir, pattern), Err: fs.ErrExist}
}

// readSecurity fills securityInfo from path's owner and DACL. An entry whose
// type has the SID elsewhere (object entries) is kept with an empty SID,
// which adminOnlyWrite never trusts.
func readSecurity(path string) (securityInfo, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return securityInfo{}, err
	}
	var s securityInfo
	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		s.Owner = owner.String()
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		// Not present or NULL: everyone has full access
		s.NoDACL = true
		return s, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return securityInfo{}, err
		}
		e := aceInfo{Mask: uint32(ace.Mask), Allow: ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			e.SID = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		s.ACEs = append(s.ACEs, e)
	}
	return s, nil
}

// adminOwnedFile reports whether path is a regular file only SYSTEM,
// Administrators or TrustedInstaller can change. It only reads: a file that
// fails is replaced by the caller, never adopted by re-applying an ACL.
func adminOwnedFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	s, err := readSecurity(path)
	return err == nil && adminOnlyWrite(s)
}

// adminOwnedDir reports whether path is a real directory (not a junction or
// symlink) only SYSTEM, Administrators or TrustedInstaller can write in
func adminOwnedDir(path string) bool {
	info, err := os.Lstat(path)
	// Not IsDir: a junction reports ModeDir with ModeIrregular
	if err != nil || info.Mode().Type() != fs.ModeDir {
		return false
	}
	s, err := readSecurity(path)
	return err == nil && adminOnlyWrite(s)
}

// ownedByCurrentUser reports whether path is owned by SYSTEM or Administrators,
// the identities osctrld runs as
func ownedByCurrentUser(path string, _ fs.FileInfo) bool {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := sd.Owner()
	return err == nil && owner != nil && trustedOwnerSID(owner.String())
}

// applyStashACLOS replaces the DACL of path with stashDACLSDDL, protected from
// inheritance
func applyStashACLOS(path string) error {
	dacl, err := daclFromSDDL(stashDACLSDDL)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// fileOwner is unknown on Windows: restore hands files to Administrators
func fileOwner(fs.FileInfo) (*fileOwnerIDs, bool) { return nil, false }

// warnUnsafeConfigFile is POSIX-only: Windows file security is ACL based
func warnUnsafeConfigFile(string) {}
