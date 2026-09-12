//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// isAdmin is a seam mirroring geteuid on unix
var isAdmin = currentProcessIsAdmin

// currentProcessIsAdmin reports whether the effective token is a member of the
// built-in Administrators group. The zero Token asks about the current thread.
func currentProcessIsAdmin() bool {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := windows.Token(0).IsMember(sid)
	return err == nil && member
}

// requirePrivileges fails unless this process holds an elevated token.
func requirePrivileges() error {
	if !isAdmin() {
		return fmt.Errorf("this command needs Administrator privileges, re-run it from an elevated prompt")
	}
	return nil
}
