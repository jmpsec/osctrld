//go:build !windows

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirePrivilegesAsRoot(t *testing.T) {
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int { return 0 }

	require.NoError(t, requirePrivileges())
}

func TestRequirePrivilegesUnprivileged(t *testing.T) {
	prev := geteuid
	t.Cleanup(func() { geteuid = prev })
	geteuid = func() int { return 501 }

	err := requirePrivileges()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
	assert.Contains(t, err.Error(), "sudo", "the error must tell the operator how to proceed")
}
