//go:build !windows

package main

import (
	"context"
	"fmt"
	"time"
)

// These exist only so the GOOS dispatch in osquery.go compiles off Windows.
// The dispatch never reaches them, because it selects them by runtime.GOOS.

func windowsServiceStop() error   { return fmt.Errorf("windows service control unavailable") }
func windowsServiceStart() error  { return fmt.Errorf("windows service control unavailable") }
func windowsServiceEnable() error { return fmt.Errorf("windows service control unavailable") }
func windowsServiceRestart() error {
	return fmt.Errorf("windows service control unavailable")
}

// ensureServiceSettings only matters for the Windows service manager
func ensureServiceSettings(string) (bool, error) { return false, nil }

// waitInstallerIdle: there is no Windows Installer to wait for
func waitInstallerIdle(context.Context, time.Duration) (bool, error) { return true, nil }
