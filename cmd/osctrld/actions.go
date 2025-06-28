package main

import (
	"fmt"
	"log"
	"runtime"
	"strings"

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

// Function to action on enroll command
func enrollNode(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Enrolling node in %s", osctrlURLs.Enroll)
	}
	script, err := retrieveScript(jsonConfig.Secret, osctrlURLs.Enroll, jsonConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error retrieving enroll - %v", err)
	}
	fmt.Printf("%s", script)
	return nil
}

// Function to action on flags command
func getFlags(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Getting flags from %s", osctrlURLs.Flags)
	}
	flags, err := retrieveFlags(jsonConfig.Secret, jsonConfig.SecretFile, jsonConfig.CertFile)
	if err != nil {
		return fmt.Errorf("error retrieving flags - %v", err)
	}
	if jsonConfig.Verbose {
		fmt.Println(flags)
	}
	if err := writeContentExists(jsonConfig.FlagFile, flags, "flags", jsonConfig.Force); err != nil {
		return err
	}
	log.Printf("✅ flags ready in %s", jsonConfig.FlagFile)
	return nil
}

// Function to action on cert command
func getCert(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Getting cert from %s", osctrlURLs.Cert)
	}
	cert, err := retrieveCert(jsonConfig.Secret, osctrlURLs.Cert, jsonConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error retrieving cert - %v", err)
	}
	if jsonConfig.Verbose {
		fmt.Println(cert)
	}
	if err := writeContentExists(jsonConfig.CertFile, cert, "cert", jsonConfig.Force); err != nil {
		return err
	}
	log.Printf("✅ cert ready in %s", jsonConfig.CertFile)
	return nil
}

// Function to action on remove command. It retrieves the script to run the removal from osctrl
func removeNode(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Removing node in %s", osctrlURLs.Remove)
	}
	script, err := retrieveScript(jsonConfig.Secret, osctrlURLs.Remove, jsonConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error retrieving remove - %v", err)
	}

	fmt.Printf("%s", script)
	return nil
}

// Function to action on verify command. It verifies flags, cert and secret for and enrolled node in osctrl
func verifyNode(c *cli.Context) error {
	// Compare secret with local
	if jsonConfig.Verbose {
		log.Printf("Comparing secret with %s", jsonConfig.SecretFile)
	}
	if checkFileContent(jsonConfig.SecretFile, jsonConfig.Secret) {
		log.Println("✅ osquery secret is valid")
	} else {
		log.Printf("❌ osquery secret mismatch")
	}
	fmt.Println()
	// Retrieve verification
	if jsonConfig.Verbose {
		log.Printf("Retrieving verification from %s", osctrlURLs.Verify)
	}
	verification, err := retrieveVerify(jsonConfig.Secret, jsonConfig.SecretFile, jsonConfig.CertFile, osctrlURLs.Verify, jsonConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error retrieving verification - %v", err)
	}
	// Compare flags with local
	if jsonConfig.Verbose {
		log.Printf("Comparing flags with %s", jsonConfig.FlagFile)
	}
	if checkFileContent(jsonConfig.FlagFile, strings.TrimSpace(verification.Flags)) {
		log.Println("✅ flags are valid")
	} else {
		log.Printf("❌ flags mismatch")
	}
	fmt.Println()
	// Retrieve certificate if flag is present
	if strings.Contains(verification.Flags, FlagTLSServerCerts) {
		// Compare certificate with local
		if jsonConfig.Verbose {
			log.Printf("Comparing certificate with %s", jsonConfig.CertFile)
		}
		if checkFileContent(jsonConfig.CertFile, strings.TrimSpace(verification.Certificate)) {
			log.Println("✅ osquery certificate is valid")
		} else {
			log.Printf("❌ osquery certificate mismatch")
		}
		fmt.Println()
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
		if jsonConfig.Verbose {
			log.Printf("Checking %s", l)
		}
		if !checkFileExist(l) {
			log.Printf("❌ %s is missing", l)
			validLocal = false
		}
	}
	if validLocal {
		log.Println("✅ osquery local files are present")
		fmt.Println()
		// osquery version check
		if jsonConfig.Verbose {
			log.Printf("Expecting osquery %s or higher", verification.OsqueryVersion)
		}
		existingVersion := getOsqueryVersion()
		if jsonConfig.Verbose {
			log.Printf("Existing version is %s", existingVersion)
		}
		if osqueryVersionCompare(existingVersion, verification.OsqueryVersion) > 1 {
			log.Printf("❌ osquery version (%s) is lower than required (%s)", existingVersion, verification.OsqueryVersion)
		} else {
			log.Printf("✅ osquery version (%s) is valid", existingVersion)
		}
		fmt.Println()
		// Check if osquery is running
		if jsonConfig.Verbose {
			log.Println("Checking running process")
		}
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
			log.Printf("✅ osqueryd is running (pid %d)", osqueryPid)
		} else {
			log.Printf("❌ osqueryd is NOT running")
		}
	} else {
		log.Printf("❌ please install osquery")
	}
	return nil
}
