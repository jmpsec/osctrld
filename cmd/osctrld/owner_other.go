//go:build !windows

package main

import "os"

func applyStashACLOS(string) error { return nil }

func applySecretACLOS(string) error { return nil }

// createTempOS is os.CreateTemp: 0600 from creation, owned by this process
func createTempOS(dir, pattern string, _ bool) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}
