package main

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

const (
	// OsctrlURL to send request to
	OsctrlURL = "%s/%s"
	// OsctrlURLFlags to send request for flags
	OsctrlURLFlags = "%s/osctrld-flags"
	// OsctrlURLCert to send request for certificate
	OsctrlURLCert = "%s/osctrld-cert"
	// OsctrlURLVerify to send request for verification
	OsctrlURLVerify = "%s/osctrld-verify"
	// OsctrlURLScript to send request for enroll/remove
	OsctrlURLScript = "%s/%s/%s/osctrld-script"
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
	Verify string
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

// Helper to generate osctrl verify URL
func genVerifyURL(osctrl string) string {
	return fmt.Sprintf(OsctrlURLVerify, osctrl)
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
	urls.Verify = genVerifyURL(osctrlURL)
	urls.Enroll = genEnrollURL(osctrlURL, runtime.GOOS)
	urls.Remove = genRemoveURL(osctrlURL, runtime.GOOS)
	return urls
}

// Helper to compare SemVer strings and return the highest or zero if they are the same
// returns 1 if existing is higher, 2 if required is higher, 0 is they are the same, and -1 if error
func osqueryVersionCompare(existing, required string) int {
	if existing == required {
		return 0
	}
	if existing == "" || required == "" {
		return -1
	}
	ex := strings.Split(existing, ".")
	req := strings.Split(required, ".")
	// Make sure both slices are the same length
	if len(ex) > len(req) {
		for i := 0; i < len(ex)-len(req); i++ {
			req = append(req, "0")
		}
	}
	if len(req) > len(ex) {
		for i := 0; i < len(req)-len(ex); i++ {
			ex = append(ex, "0")
		}
	}
	res := 2
	// Iterate through all elements to compare and check what is higher
	for v := 0; v < len(ex); v++ {
		exConv, err := strconv.Atoi(ex[v])
		if err != nil {
			return -1
		}
		reqConv, err := strconv.Atoi(req[v])
		if err != nil {
			return -1
		}
		if exConv > reqConv {
			return 1
		}
	}
	return res
}
