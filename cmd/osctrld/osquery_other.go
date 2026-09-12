//go:build !windows

package main

import "fmt"

// These exist only so the GOOS dispatch in osquery.go compiles off Windows.
// The dispatch never reaches them, because it selects them by runtime.GOOS.

func windowsServiceStop() error   { return fmt.Errorf("windows service control unavailable") }
func windowsServiceStart() error  { return fmt.Errorf("windows service control unavailable") }
func windowsServiceEnable() error { return fmt.Errorf("windows service control unavailable") }
