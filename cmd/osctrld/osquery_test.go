package main

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOsqueryRestartCommand(t *testing.T) {
	cmd, args := osqueryRestartCommand()
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, "systemctl", cmd)
		assert.Equal(t, []string{"restart", "osqueryd"}, args)
	case "darwin":
		assert.Equal(t, "launchctl", cmd)
		assert.Equal(t, []string{"kickstart", "-k", "system/io.osquery.agent"}, args)
	default:
		assert.Empty(t, cmd, "unsupported OS should return empty command")
		assert.Nil(t, args)
	}
}
