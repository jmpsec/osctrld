//go:build !windows

package main

import (
	"fmt"
	"os"
)

// geteuid is a seam so the privilege gate can be exercised without running tests as root
var geteuid = os.Geteuid

// requirePrivileges fails unless this process can write system paths and manage
// services. osctrld never escalates on its own: the operator runs it under sudo.
func requirePrivileges() error {
	if geteuid() != 0 {
		return fmt.Errorf("this command needs root privileges, re-run it with sudo")
	}
	return nil
}
