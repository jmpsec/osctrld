package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
)

// Seams so tests can observe privileged commands without running them
var (
	execCommand = exec.Command
	lookPath    = exec.LookPath
)

// runCommand runs one command and folds its output into any error
func runCommand(name string, args ...string) error {
	log.Info().Str("command", name).Strs("args", args).Msg("running command")
	out, err := execCommand(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s failed: %v (output: %s)", name, strings.Join(args, " "), err, string(out))
	}
	return nil
}

// runFirstAvailable runs the first candidate whose binary is present, mirroring
// the script's systemctl -> service -> init.d fallback chain. An absolute path
// is probed on disk rather than on PATH.
func runFirstAvailable(candidates [][]string) error {
	for _, c := range candidates {
		if strings.HasPrefix(c[0], "/") {
			if !checkFileExist(c[0]) {
				continue
			}
		} else if _, err := lookPath(c[0]); err != nil {
			continue
		}
		return runCommand(c[0], c[1:]...)
	}
	return fmt.Errorf("no service manager found for osquery")
}

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
	if err := runCommand(cmd, args...); err != nil {
		return fmt.Errorf("failed to restart osquery: %v", err)
	}
	log.Info().Msg("osquery restarted successfully")
	return nil
}

const (
	// darwinLaunchDaemon is where the osquery plist must live to load at boot
	darwinLaunchDaemon = "/Library/LaunchDaemons/io.osquery.agent.plist"
	// darwinSourcePlist is the plist the osquery package ships
	darwinSourcePlist = "/private/var/osquery/io.osquery.agent.plist"
	// osqueryService is the service name on Linux and Windows
	osqueryService = "osqueryd"
)

// stopOsquery stops the osquery service. On macOS an unload that fails because
// the daemon was not loaded is not an error: stopped is the desired state either way.
func stopOsquery() error {
	switch runtime.GOOS {
	case LinuxOS:
		return runFirstAvailable([][]string{
			{"systemctl", "stop", osqueryService},
			{"service", osqueryService, "stop"},
			{"/etc/init.d/" + osqueryService, "stop"},
		})
	case DarwinOS:
		if err := runCommand("launchctl", "unload", darwinLaunchDaemon); err != nil {
			log.Debug().Err(err).Msg("launchctl unload failed, assuming osquery was not loaded")
		}
		return nil
	case WindowsOS:
		return windowsServiceStop()
	}
	return fmt.Errorf("stopping osquery is not supported on %s", runtime.GOOS)
}

// startOsquery starts the osquery service, installing the launch daemon on macOS
func startOsquery() error {
	switch runtime.GOOS {
	case LinuxOS:
		return runFirstAvailable([][]string{
			{"systemctl", "start", osqueryService},
			{"service", osqueryService, "start"},
			{"/etc/init.d/" + osqueryService, "start"},
		})
	case DarwinOS:
		if err := runCommand("cp", darwinSourcePlist, darwinLaunchDaemon); err != nil {
			return err
		}
		return runCommand("launchctl", "load", darwinLaunchDaemon)
	case WindowsOS:
		return windowsServiceStart()
	}
	return fmt.Errorf("starting osquery is not supported on %s", runtime.GOOS)
}

// enableOsquery makes osquery start at boot. macOS needs no separate step: a
// LaunchDaemon plist in /Library/LaunchDaemons is loaded at boot by launchd.
func enableOsquery() error {
	switch runtime.GOOS {
	case LinuxOS:
		return runFirstAvailable([][]string{
			{"systemctl", "enable", osqueryService},
			{"update-rc.d", osqueryService, "defaults"},
		})
	case DarwinOS:
		return nil
	case WindowsOS:
		return windowsServiceEnable()
	}
	return fmt.Errorf("enabling osquery is not supported on %s", runtime.GOOS)
}
