package main

import (
	"path/filepath"
	"strings"
)

// stashDACLSDDL is a protected DACL (no inherited entries) that gives SYSTEM
// and Administrators full control, inherited by everything in the stash, and
// nobody else any access
const stashDACLSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// secretDACLSDDL is the protected DACL of the enrollment secret: full control
// for SYSTEM and Administrators, nothing for anyone else, nothing inheritable.
// osqueryd runs as SYSTEM and reads the secret through --enroll_secret_path.
const secretDACLSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

const (
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	// creatorOwnerSID only appears in inheritable entries, where it stands for
	// whoever creates the child: osctrld itself, as SYSTEM or Administrators
	creatorOwnerSID = "S-1-3-0"
)

var (
	// createTemp creates the temp file writeFileAtomic fills. restricted makes
	// Windows create it with secretDACLSDDL, so the secret is never written to
	// a file anyone else can open. A seam for tests.
	createTemp = createTempOS
	// applySecretACL hands an existing secret file to Administrators with
	// secretDACLSDDL; a no-op off Windows, a seam for tests
	applySecretACL = applySecretACLOS
)

// fileACL is the Windows access class of a file osctrld writes
type fileACL int

const (
	// aclDefault is what each caller did before: the flagfile and certificate
	// keep the directory's inherited ACL when written, and restore hands them
	// and the autoload file extensionDACL (Users read and execute)
	aclDefault fileACL = iota
	// aclSecret is secretDACLSDDL
	aclSecret
)

// fileACLFor picks the access class of path: only the enrollment secret is
// restricted. Windows paths compare case-insensitively.
func fileACLFor(path, secretFile, goos string) fileACL {
	if secretFile == "" {
		return aclDefault
	}
	p, s := filepath.Clean(path), filepath.Clean(secretFile)
	if p == s || (goos == WindowsOS && strings.EqualFold(p, s)) {
		return aclSecret
	}
	return aclDefault
}

// writeRights is every access right that lets a principal change what a
// directory holds or a file contains, or who may: FILE_ADD_FILE/WRITE_DATA,
// FILE_ADD_SUBDIRECTORY/APPEND_DATA, FILE_DELETE_CHILD, DELETE, WRITE_DAC,
// WRITE_OWNER, GENERIC_ALL and GENERIC_WRITE
const writeRights uint32 = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

// aceInfo is one DACL entry; SID is empty when it could not be read
type aceInfo struct {
	SID   string
	Mask  uint32
	Allow bool
}

// securityInfo is the part of a Windows security descriptor that decides who
// can write: the owner (who can always rewrite the DACL) and the DACL
type securityInfo struct {
	Owner string
	// NoDACL is a missing or NULL DACL, which grants everyone everything
	NoDACL bool
	ACEs   []aceInfo
}

// trustedWriterSID is an identity allowed to write where osctrld trusts content
func trustedWriterSID(sid string) bool {
	return trustedOwnerSID(sid) || sid == sidTrustedInstaller
}

// adminOnlyWrite reports whether only SYSTEM, Administrators or TrustedInstaller
// can change a file or directory with security s. Deny entries are ignored and
// inheritable entries count as if they applied, so the answer only errs towards
// unsafe: an inheritable grant reaches the temp files osctrld creates inside.
func adminOnlyWrite(s securityInfo) bool {
	if !trustedWriterSID(s.Owner) || s.NoDACL {
		return false
	}
	for _, a := range s.ACEs {
		if a.Allow && a.Mask&writeRights != 0 && !trustedWriterSID(a.SID) && a.SID != creatorOwnerSID {
			return false
		}
	}
	return true
}

// trustedOwnerSID reports whether sid is SYSTEM or the Administrators group,
// the only owners that make an upgrade directory trustworthy on Windows
func trustedOwnerSID(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544"
}
