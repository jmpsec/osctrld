package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/urfave/cli/v2"
)

var (
	// OsqueryDarwin default installation
	OsqueryDarwin = []string{
		"/private/var/osquery/io.osquery.agent.plist",
		"/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd",
	}
	// OsqueryLinux default installation
	OsqueryLinux = []string{
		"/usr/lib/systemd/system/osqueryd.service",
		"/opt/osquery/bin/osqueryd",
	}
	// OsqueryWindows default installation
	OsqueryWindows = []string{
		"C:\\Program Files\\osquery\\manage-osqueryd.ps1",
		"C:\\Program Files\\osquery\\osqueryd\\osqueryd.exe",
	}
	// FlagTLSServerCerts for TLS server certificates
	FlagTLSServerCerts = "--tls_server_certs"
	// FlagOsqueryVersion to get osquery version
	FlagOsqueryVersion = "-version"
)

// FlagsRequest to retrieve flags
type FlagsRequest struct {
	Secret     string `json:"secret"`
	SecretFile string `json:"secretFile"`
	CertFile   string `json:"certFile"`
}

// CertRequest to retrieve certificate
type CertRequest struct {
	Secret string `json:"secret"`
}

// ScriptRequest to retrieve script
type ScriptRequest CertRequest

// VerifyRequest to verify node
type VerifyRequest FlagsRequest

// VerifyResponse for verify requests from osctrld
type VerifyResponse struct {
	Flags          string `json:"flags"`
	Certificate    string `json:"certificate"`
	OsqueryVersion string `json:"osquery_version"`
}

// ExtensionEntry represents a single extension from the manifest
type ExtensionEntry struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// ExtensionsRequest to retrieve extension manifest
type ExtensionsRequest struct {
	Secret string `json:"secret"`
}

// Function to action on enroll command
func enrollNode(c *cli.Context) error {
	log.Debug().Str("url", osctrlURLs.Enroll).Msg("enrolling node")
	script, err := retrieveScript(appConfig.Secret, osctrlURLs.Enroll, appConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error retrieving enroll - %v", err)
	}
	fmt.Printf("%s", script)
	return nil
}

// Function to action on flags command
func getFlags(c *cli.Context) (bool, error) {
	log.Debug().Str("url", osctrlURLs.Flags).Msg("getting flags")
	flags, err := retrieveFlags(appConfig.Secret, appConfig.SecretFile, appConfig.CertFile)
	if err != nil {
		return false, fmt.Errorf("error retrieving flags - %v", err)
	}
	log.Debug().Str("flags", flags).Msg("flags content")
	changed, err := writeContentExists(appConfig.FlagFile, flags, "flags", appConfig.Force)
	if err != nil {
		return false, err
	}
	log.Info().Str("path", appConfig.FlagFile).Msg("flags ready")
	return changed, nil
}

// Function to action on cert command
func getCert(c *cli.Context) (bool, error) {
	log.Debug().Str("url", osctrlURLs.Cert).Msg("getting cert")
	cert, err := retrieveCert(appConfig.Secret, osctrlURLs.Cert, appConfig.Insecure)
	if err != nil {
		return false, fmt.Errorf("error retrieving cert - %v", err)
	}
	log.Debug().Str("cert", cert).Msg("cert content")
	changed, err := writeContentExists(appConfig.CertFile, cert, "cert", appConfig.Force)
	if err != nil {
		return false, err
	}
	log.Info().Str("path", appConfig.CertFile).Msg("cert ready")
	return changed, nil
}

// Function to action on remove command. It retrieves the script to run the removal from osctrl
func removeNode(c *cli.Context) error {
	log.Debug().Str("url", osctrlURLs.Remove).Msg("removing node")
	script, err := retrieveScript(appConfig.Secret, osctrlURLs.Remove, appConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error retrieving remove - %v", err)
	}

	fmt.Printf("%s", script)
	return nil
}

// Function to action on verify command. It verifies flags, cert and secret for and enrolled node in osctrl
func verifyNode(c *cli.Context) error {
	// Compare secret with local
	log.Debug().Str("path", appConfig.SecretFile).Msg("comparing secret")
	if checkFileContent(appConfig.SecretFile, appConfig.Secret) {
		log.Info().Msg("osquery secret is valid")
	} else {
		log.Warn().Msg("osquery secret mismatch")
	}
	// Retrieve verification
	log.Debug().Str("url", osctrlURLs.Verify).Msg("retrieving verification")
	verification, err := retrieveVerify(appConfig.Secret, appConfig.SecretFile, appConfig.CertFile, osctrlURLs.Verify, appConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error retrieving verification - %v", err)
	}
	// Compare flags with local
	log.Debug().Str("path", appConfig.FlagFile).Msg("comparing flags")
	if checkFileContent(appConfig.FlagFile, strings.TrimSpace(verification.Flags)) {
		log.Info().Msg("flags are valid")
	} else {
		log.Warn().Msg("flags mismatch")
	}
	// Retrieve certificate if flag is present
	if strings.Contains(verification.Flags, FlagTLSServerCerts) {
		// Compare certificate with local
		log.Debug().Str("path", appConfig.CertFile).Msg("comparing certificate")
		if checkFileContent(appConfig.CertFile, strings.TrimSpace(verification.Certificate)) {
			log.Info().Msg("osquery certificate is valid")
		} else {
			log.Warn().Msg("osquery certificate mismatch")
		}
	}
	// Check local files
	var localFiles []string
	switch runtime.GOOS {
	case DarwinOS:
		localFiles = OsqueryDarwin
	case LinuxOS:
		localFiles = OsqueryLinux
	case WindowsOS:
		localFiles = OsqueryWindows
	}
	validLocal := true
	for _, l := range localFiles {
		log.Debug().Str("path", l).Msg("checking local file")
		if !checkFileExist(l) {
			log.Warn().Str("path", l).Msg("local file missing")
			validLocal = false
		}
	}
	if validLocal {
		log.Info().Msg("osquery local files are present")
		// osquery version check
		log.Debug().Str("version", verification.OsqueryVersion).Msg("expected osquery version")
		existingVersion := getOsqueryVersion()
		log.Debug().Str("version", existingVersion).Msg("existing osquery version")
		if osqueryVersionCompare(existingVersion, verification.OsqueryVersion) > 1 {
			log.Warn().Str("existing", existingVersion).Str("required", verification.OsqueryVersion).Msg("osquery version too low")
		} else {
			log.Info().Str("version", existingVersion).Msg("osquery version is valid")
		}
		// Check if osquery is running
		log.Debug().Msg("checking running process")
		ps, err := process.Processes()
		if err != nil {
			return fmt.Errorf("error getting processes - %s", err)
		}
		osqueryRunning := false
		var osqueryPid int32
		for _, p := range ps {
			pCmd, _ := p.Cmdline()
			if strings.Contains(pCmd, "/osqueryd ") {
				osqueryRunning = true
				osqueryPid = p.Pid
				break
			}
		}
		if osqueryRunning {
			log.Info().Int32("pid", osqueryPid).Msg("osqueryd is running")
		} else {
			log.Warn().Msg("osqueryd is not running")
		}
	} else {
		log.Error().Msg("osquery is not installed")
	}
	return nil
}
