package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var (
	// hostUUIDReader is a seam so callers can be tested without osqueryd
	hostUUIDReader = readHostUUID
	// hostUUIDTimeout bounds osqueryd -S so a hung binary can never block the service loop
	hostUUIDTimeout = 15 * time.Second
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// readHostUUID returns the UUID osquery enrolls with (system_info.uuid)
func readHostUUID() (string, error) {
	var osquerydBin string
	switch runtime.GOOS {
	case DarwinOS:
		osquerydBin = OsqueryDarwin[1]
	case LinuxOS:
		osquerydBin = OsqueryLinux[1]
	case WindowsOS:
		osquerydBin = OsqueryWindows[1]
	}
	out, err := outputWithTimeout(osquerydBin, hostUUIDTimeout, "-S", "--json", "select uuid from system_info;")
	if err != nil {
		return "", fmt.Errorf("error running osqueryd - %v", err)
	}
	var rows []struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return "", fmt.Errorf("error parsing osqueryd output - %v", err)
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("osqueryd returned no system_info row")
	}
	uuid := strings.TrimSpace(rows[0].UUID)
	if !uuidPattern.MatchString(uuid) {
		return "", fmt.Errorf("invalid host uuid %q", uuid)
	}
	return uuid, nil
}

// outputWithTimeout runs a command through the execCommand seam and returns its
// stdout, killing it once timeout passes. WaitDelay bounds Wait too, in case a
// child process keeps the output pipe open after the kill.
func outputWithTimeout(name string, timeout time.Duration, args ...string) ([]byte, error) {
	cmd := execCommand(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.Bytes(), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return nil, fmt.Errorf("timed out after %s", timeout)
	}
}
