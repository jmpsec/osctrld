package main

import "fmt"

const (
	// OsctrldVersion to have the version for all components
	OsctrldVersion string = "1.1.2"
)

// Build-time metadata (overridden via -ldflags "-X main.buildVersion=... -X main.buildCommit=... -X main.buildDate=...")
var (
	buildVersion = appVersion
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// versionString is the single-line build report, matching osctrl-cli's format
func versionString() string {
	return fmt.Sprintf("%s version=%s commit=%s date=%s", appName, buildVersion, buildCommit, buildDate)
}
