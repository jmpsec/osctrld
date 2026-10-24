package main

// stashDACLSDDL is a protected DACL (no inherited entries) that gives SYSTEM
// and Administrators full control, inherited by everything in the stash, and
// nobody else any access
const stashDACLSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// trustedOwnerSID reports whether sid is SYSTEM or the Administrators group,
// the only owners that make an upgrade directory trustworthy on Windows
func trustedOwnerSID(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544"
}
