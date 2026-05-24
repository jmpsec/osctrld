package main

import (
	"fmt"
	"os/exec"
	"runtime"

	"github.com/rs/zerolog/log"
)

func osqueryRestartCommand() (string, []string) {
	switch runtime.GOOS {
	case LinuxOS:
		return "systemctl", []string{"restart", "osqueryd"}
	case DarwinOS:
		return "launchctl", []string{"kickstart", "-k", "system/io.osquery.agent"}
	default:
		return "", nil
	}
}

func restartOsquery() error {
	cmd, args := osqueryRestartCommand()
	if cmd == "" {
		return fmt.Errorf("osquery restart not supported on %s", runtime.GOOS)
	}
	log.Info().Str("command", cmd).Strs("args", args).Msg("restarting osquery")
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart osquery: %v (output: %s)", err, string(out))
	}
	log.Info().Msg("osquery restarted successfully")
	return nil
}
