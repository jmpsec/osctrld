package main

import (
	"fmt"
	"runtime"
)

const (
	// OsctrlURL to send request to
	OsctrlURL = "%s/%s"
	// OsctrlURLFlags to send request for flags
	OsctrlURLFlags = "%s/flags"
	// OsctrlURLCert to send request for certificate
	OsctrlURLCert = "%s/cert"
	// OsctrlURLScript to send request for enroll/remove
	OsctrlURLScript = "%s/%s/%s/script"
	// OsctrlEnroll to identify enrolls
	OsctrlEnroll = "enroll"
	// OsctrlRemove to identify removals
	OsctrlRemove = "remove"
)

// OsctrlURLs keeps all osctrl URLs
type OsctrlURLs struct {
	URL    string
	Flags  string
	Cert   string
	Enroll string
	Remove string
}

// Helper to generate osctrl main URL
func genOsctrlURL(base, env string) string {
	return fmt.Sprintf(OsctrlURL, base, env)
}

// Helper to generate osctrl flags URL
func genFlagsURL(osctrl string) string {
	return fmt.Sprintf(OsctrlURLFlags, osctrl)
}

// Helper to generate osctrl cert URL
func genCertURL(osctrl string) string {
	return fmt.Sprintf(OsctrlURLCert, osctrl)
}

// Helper to generate osctrl script URL for enrolling/removing osquery nodes
func genScriptURL(osctrl, action, platform string) string {
	return fmt.Sprintf(OsctrlURLScript, osctrl, action, platform)
}

// Helper to generate osctrl script URL for enrolling osquery nodes
func genEnrollURL(osctrl, platform string) string {
	return fmt.Sprintf(OsctrlURLScript, osctrl, OsctrlEnroll, platform)
}

// Helper to generate osctrl script URL for removing osquery nodes
func genRemoveURL(osctrl, platform string) string {
	return fmt.Sprintf(OsctrlURLScript, osctrl, OsctrlRemove, platform)
}

// Helper to generate all URLs
func genURLs(host, env string, insecure bool) OsctrlURLs {
	var urls OsctrlURLs
	osctrlURL := genOsctrlURL(host, env)
	urls.URL = osctrlURL
	urls.Flags = genFlagsURL(osctrlURL)
	urls.Cert = genCertURL(osctrlURL)
	urls.Enroll = genEnrollURL(osctrlURL, runtime.GOOS)
	urls.Remove = genRemoveURL(osctrlURL, runtime.GOOS)
	return urls
}
