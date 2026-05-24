package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rs/zerolog/log"
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
	code, body, err := SendRequest(http.MethodPost, osctrlURLs.Flags, jsonParam, map[string]string{}, appConfig.Insecure)
	if err != nil {
		return "", fmt.Errorf("error sending request - %v", err)
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("HTTP %d - Response: %s", code, string(body))
	}
	return strings.TrimSpace(string(body)), nil
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
		log.Error().Str("path", path).Err(err).Msg("error opening file")
		return false
	}
	defer f.Close()
	fContent, _ := io.ReadAll(f)
	return (strings.TrimSpace(string(fContent)) == content)
}

// Helper function to write content to a file if not different from existing
func writeContentExists(path, content, name string, force bool) (bool, error) {
	if checkFileExist(path) {
		if !checkFileContent(path, content) {
			if force {
				if err := os.WriteFile(path, []byte(content), 0700); err != nil {
					return false, fmt.Errorf("error overwriting %s to %s - %v", name, path, err)
				}
				return true, nil
			}
			return false, fmt.Errorf("%s exists, please use --force to overwrite", path)
		}
		return false, nil
	}
	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		return false, fmt.Errorf("error writing %s to %s - %v", name, path, err)
	}
	return true, nil
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
		log.Error().Err(err).Str("output", string(out)).Msg("error running osqueryd")
		return ""
	}
	splitted := strings.Split(strings.TrimSpace(string(out)), " ")
	if len(splitted) < 2 {
		return ""
	}
	return splitted[2]
}

