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

// osqueryRestartCandidates is the restart fallback chain for goos. Windows
// restarts through the service manager instead, so it has none.
func osqueryRestartCandidates(goos string) [][]string {
	switch goos {
	case LinuxOS:
		return [][]string{
			{"systemctl", "restart", osqueryService},
			{"service", osqueryService, "restart"},
			{"/etc/init.d/" + osqueryService, "restart"},
		}
	case DarwinOS:
		return [][]string{{"launchctl", "kickstart", "-k", "system/io.osquery.agent"}}
	}
	return nil
}

func restartOsquery() error {
	var err error
	if runtime.GOOS == WindowsOS {
		err = windowsServiceRestart()
	} else if candidates := osqueryRestartCandidates(runtime.GOOS); candidates != nil {
		err = runFirstAvailable(candidates)
	} else {
		return fmt.Errorf("osquery restart not supported on %s", runtime.GOOS)
	}
	if err != nil {
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

// splitCommandLine splits a Windows service command line on spaces outside
// double quotes, keeping each token's quotes. Paths cannot contain quotes, so
// no escapes are handled.
func splitCommandLine(s string) []string {
	var tokens []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			cur.WriteRune(r)
		case (r == ' ' || r == '\t') && !quoted:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

// serviceCommandLine returns the osqueryd service command line with exactly
// one --flagfile argument naming flagFile, keeping the executable and the
// other arguments, and whether that differs from existing. The flag name is
// case-sensitive like gflags, the path compares case-insensitively and quotes
// are ignored; an empty line is left alone. A flag file path that cannot be
// quoted safely (a quote, or a trailing backslash that would escape the
// closing quote) is refused.
func serviceCommandLine(existing, flagFile string) (string, bool, error) {
	if strings.Contains(flagFile, `"`) || strings.HasSuffix(flagFile, `\`) {
		return existing, false, fmt.Errorf("flag file path %q cannot be put on the service command line", flagFile)
	}
	tokens := splitCommandLine(existing)
	if len(tokens) == 0 {
		return existing, false, nil
	}
	unquote := func(t string) string { return strings.ReplaceAll(t, `"`, "") }
	others := []string{tokens[0]}
	correct, wrong := 0, false
	for i := 1; i < len(tokens); i++ {
		arg := unquote(tokens[i])
		name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if !strings.HasPrefix(arg, "-") || name != "flagfile" {
			others = append(others, tokens[i])
			continue
		}
		if !hasValue && i+1 < len(tokens) {
			// --flagfile <path>
			i++
			value = unquote(tokens[i])
		}
		if strings.EqualFold(value, flagFile) {
			correct++
		} else {
			wrong = true
		}
	}
	if correct == 1 && !wrong {
		return existing, false, nil
	}
	return strings.Join(append(others, `--flagfile="`+flagFile+`"`), " "), true, nil
}

// fixServiceConfig decides the osqueryd service update: the command line to
// set and whether anything (it, or a start type other than automatic) changes.
// A refused command line is returned unchanged with the error, so the start
// type is still fixed.
func fixServiceConfig(automatic bool, binaryPath, flagFile string) (string, bool, error) {
	bin, changed, err := serviceCommandLine(binaryPath, flagFile)
	return bin, changed || !automatic, err
}
