package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Helper function to retrieve flags
func retrieveFlags(secret, secretFile, certFile string) (string, error) {
	flagsData := FlagsRequest{
		Secret:     secret,
		SecretFile: secretFile,
		CertFile:   certFile,
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

// Helper function to retrieve from server
func genericRetrieve(url string, insecure bool, data any) ([]byte, error) {
	jsonReq, err := json.Marshal(data)
	if err != nil {
		return []byte{}, fmt.Errorf("error parsing data - %s", err)
	}
	jsonParam := strings.NewReader(string(jsonReq))
	code, body, err := SendRequest(http.MethodPost, url, jsonParam, map[string]string{}, insecure)
	if err != nil {
		return []byte{}, fmt.Errorf("error sending request - %v", err)
	}
	if code != http.StatusOK {
		return []byte{}, fmt.Errorf("HTTP %d - Response: %s", code, string(body))
	}
	return body, nil
}

// Helper function to retrieve script
func retrieveScript(secret, url string, insecure bool) (string, error) {
	scriptData := ScriptRequest{
		Secret: secret,
	}
	resp, err := genericRetrieve(url, insecure, scriptData)
	return strings.TrimSpace(string(resp)), err
}

// Helper function to retrieve cert
func retrieveCert(secret, url string, insecure bool) (string, error) {
	certData := CertRequest{
		Secret: secret,
	}
	resp, err := genericRetrieve(url, insecure, certData)
	return strings.TrimSpace(string(resp)), err
}

// Helper function to retrieve verify
func retrieveVerify(secret, secretFile, certFile, url string, insecure bool) (VerifyResponse, error) {
	verifyData := VerifyRequest{
		Secret:     secret,
		SecretFile: secretFile,
		CertFile:   certFile,
	}
	var vData VerifyResponse
	resp, err := genericRetrieve(url, insecure, verifyData)
	if err != nil {
		return VerifyResponse{}, err
	}
	if err := json.Unmarshal(resp, &vData); err != nil {
		return VerifyResponse{}, fmt.Errorf("error parsing - %v", err)
	}
	return vData, nil
}

// Helper function to check file existance - true if file exists and it opens
func checkFileExist(path string) bool {
	_, err := os.Stat(path)
	return (err == nil)
}

// Helper function to check if file content is the same - true if content is the same than file
func checkFileContent(path, content string) bool {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("error opening %s - %v", path, err)
		return false
	}
	defer f.Close()
	fContent, _ := io.ReadAll(f)
	return (strings.TrimSpace(string(fContent)) == content)
}

// Helper function to write content to a file if not different from existing
func writeContentExists(path, content, name string, force bool) error {
	if checkFileExist(path) {
		if !checkFileContent(path, content) {
			if force {
				if err := os.WriteFile(path, []byte(content), 0700); err != nil {
					return fmt.Errorf("error overwriting %s to %s - %v", name, path, err)
				}
			} else {
				return fmt.Errorf("%s exists, please use --force to overwrite", path)
			}
		}
	} else {
		if err := os.WriteFile(path, []byte(content), 0700); err != nil {
			return fmt.Errorf("error writing %s to %s - %v", name, path, err)
		}
	}
	return nil
}

// Helper function to execute the "osqueryd -version" command and return output
func getOsqueryVersion() string {
	var osquerydBin string
	switch runtime.GOOS {
	case DarwinOS:
		osquerydBin = OsqueryDarwin[1]
	case LinuxOS:
		osquerydBin = OsqueryLinux[1]
	case WindowsOS:
		osquerydBin = OsqueryWindows[1]
	}
	cmd := exec.Command(osquerydBin, FlagOsqueryVersion)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("error running osqueryd - %v - %s", err, string(out))
		return ""
	}
	splitted := strings.Split(strings.TrimSpace(string(out)), " ")
	if len(splitted) < 2 {
		return ""
	}
	return splitted[2]
}

// Helper function to run the retrieved script from osctrl
func runScript(directory, script string) (string, error) {
	// Create a temporary file for the script
	tmpFile, err := os.CreateTemp(directory, "osctrld-script-*.sh")
	if err != nil {
		return "", fmt.Errorf("error creating temporary script file: %v", err)
	}
	defer os.Remove(tmpFile.Name()) // Clean up the file when done

	// Write the script content to the file
	if _, err := tmpFile.Write([]byte(script)); err != nil {
		return "", fmt.Errorf("error writing script to temporary file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("error closing temporary file: %v", err)
	}
	// Make the script executable
	if err := os.Chmod(tmpFile.Name(), 0700); err != nil {
		return "", fmt.Errorf("error making script executable: %v", err)
	}

	// Create buffers for stdout and stderr
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// Execute the script
	cmd := exec.Command(tmpFile.Name())
	cmd.CombinedOutput()

	// Set the command's output to the buffers
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the script
	if err := cmd.Run(); err != nil {
		// If the command fails, capture the error
		return "", fmt.Errorf("error executing script: %v", err)
	}
	// Capture the output
	output := stdout.String()
	errOutput := stderr.String()

	// If stderr has content but no error was returned, log it
	if errOutput != "" {
		log.Printf("script generated warnings: %s", errOutput)
	}

	return output, nil
}
