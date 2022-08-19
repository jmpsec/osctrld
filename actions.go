package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
	"github.com/urfave/cli/v2"
)

var (
	// OsqueryDarwin default installation
	OsqueryDarwin = []string{
		"/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd",
		"/private/var/osquery/io.osquery.agent.plist",
	}
	// OsqueryLinux default installation
	OsqueryLinux = []string{
		"/usr/lib/systemd/system/osqueryd.service",
		"/opt/osquery/bin/osqueryd",
	}
	// OsqueryWindows default installation
	OsqueryWindows = []string{
		"C:\\Program Files\\osquery\\osqueryd\\osqueryd.exe",
		"C:\\Program Files\\osquery\\manage-osqueryd.ps1",
	}
)

const (
	// FlagTLSServerCerts
	FlagTLSServerCerts = "--tls_server_certs"
)

// FlagsRequest to retrieve flags
type FlagsRequest struct {
	Secret      string `json:"secret"`
	SecrefFile  string `json:"secretFile"`
	Certificate string `json:"certificate"`
}

// CertRequest to retrieve certificate
type CertRequest struct {
	Secret string `json:"secret"`
}

// Function to action on enroll command
func enrollNode(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Enrolling node in %s", osctrlURLs.Enroll)
	}
	return nil
}

// Function to action on flags command
func getFlags(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Getting flags from %s", osctrlURLs.Flags)
	}
	flags, err := retrieveFlags(jsonConfig.Secret, jsonConfig.SecretFile, jsonConfig.Certificate)
	if err != nil {
		return fmt.Errorf("error retrieving flags - %v", err)
	}
	fmt.Printf("%s", flags)
	return nil
}

// Function to action on cert command
func getCert(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Getting cert from %s", osctrlURLs.Cert)
	}
	cert, err := retrieveCert(jsonConfig.Secret)
	if err != nil {
		return fmt.Errorf("error retrieving cert - %v", err)
	}
	fmt.Printf("%s", cert)
	return nil
}

// Function to action on remove command
func removeNode(c *cli.Context) error {
	if jsonConfig.Verbose {
		log.Printf("Removing node in %s", osctrlURLs.Remove)
	}
	return nil
}

// Function to action on verify command
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
	// Retrieve flags
	if jsonConfig.Verbose {
		log.Printf("Retrieving flags from %s", osctrlURLs.Flags)
	}
	flags, err := retrieveFlags(jsonConfig.Secret, jsonConfig.SecretFile, jsonConfig.Certificate)
	if err != nil {
		return fmt.Errorf("error retrieving flags - %v", err)
	}
	// Compare flags with local
	if jsonConfig.Verbose {
		log.Printf("Comparing flags with %s", jsonConfig.FlagFile)
	}
	if checkFileContent(jsonConfig.FlagFile, flags) {
		log.Println("✅ flags are valid")
	} else {
		log.Printf("❌ flags mismatch")
	}
	fmt.Println()
	// Retrieve certificate if flag is present
	if strings.Contains(FlagTLSServerCerts, flags) {
		if jsonConfig.Verbose {
			log.Printf("Retrieving cert from %s", osctrlURLs.Cert)
		}
		cert, err := retrieveCert(jsonConfig.Secret)
		if err != nil {
			return fmt.Errorf("error retrieving cert - %v", err)
		}
		// Compare certificate with local
		if jsonConfig.Verbose {
			log.Printf("Comparing certificate with %s", jsonConfig.Certificate)
		}
		if checkFileContent(jsonConfig.Certificate, cert) {
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
	return nil
}

// Helper function to retrieve flags
func retrieveFlags(secret, secretFile, cert string) (string, error) {
	flagsData := FlagsRequest{
		Secret:      secret,
		SecrefFile:  secretFile,
		Certificate: cert,
	}
	jsonReq, err := json.Marshal(flagsData)
	if err != nil {
		return "", fmt.Errorf("error parsing data - %s", err)
	}
	jsonParam := strings.NewReader(string(jsonReq))
	code, body, err := SendRequest(http.MethodPost, osctrlURLs.Flags, jsonParam, map[string]string{}, jsonConfig.Insecure)
	if err != nil {
		return "", fmt.Errorf("error sending request - %v", err)
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("HTTP %d - Response: %s", code, string(body))
	}
	return fmt.Sprintf("%s", strings.TrimSpace(string(body))), nil
}

// Helper function to retrieve cert
func retrieveCert(secret string) (string, error) {
	certData := CertRequest{
		Secret: secret,
	}
	jsonReq, err := json.Marshal(certData)
	if err != nil {
		return "", fmt.Errorf("error parsing data - %s", err)
	}
	jsonParam := strings.NewReader(string(jsonReq))
	code, body, err := SendRequest(http.MethodPost, osctrlURLs.Cert, jsonParam, map[string]string{}, jsonConfig.Insecure)
	if err != nil {
		return "", fmt.Errorf("error sending request - %v", err)
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("HTTP %d - Response: %s", code, string(body))
	}
	return fmt.Sprintf("%s", strings.TrimSpace(string(body))), nil
}

// Helper function to check file existance
func checkFileExist(path string) bool {
	_, err := os.Stat(path)
	return (err == nil)
}

// Helper function to check if file content is the same
func checkFileContent(path, content string) bool {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("error opening %s - %v", path, err)
		return false
	}
	defer f.Close()
	fContent, _ := ioutil.ReadAll(f)
	return (strings.TrimSpace(string(fContent)) == content)
}
