package main

import (
	"fmt"
	"runtime"
	"testing"

	"gotest.tools/assert"
)

func TestGenOsctrlURL(t *testing.T) {
	osctrlURL := genOsctrlURL("http://localhost:8080", "dev")
	assert.Equal(t, "http://localhost:8080/dev", osctrlURL)
}

func TestGenFlagsURL(t *testing.T) {
	flagsURL := genFlagsURL("http://localhost:8080/dev")
	assert.Equal(t, fmt.Sprintf(OsctrlURLFlags, "http://localhost:8080/dev"), flagsURL)
}

func TestGenCertURL(t *testing.T) {
	certURL := genCertURL("http://localhost:8080/dev")
	assert.Equal(t, fmt.Sprintf(OsctrlURLCert, "http://localhost:8080/dev"), certURL)
}

func TestGenVerifyURL(t *testing.T) {
	verifyURL := genVerifyURL("http://localhost:8080/dev")
	assert.Equal(t, fmt.Sprintf(OsctrlURLVerify, "http://localhost:8080/dev"), verifyURL)
}

func TestGenScriptURL(t *testing.T) {
	scriptURL := genScriptURL("http://localhost:8080/dev", OsctrlEnroll, "darwin")
	assert.Equal(t, fmt.Sprintf(OsctrlURLScript, "http://localhost:8080/dev", OsctrlEnroll, "darwin"), scriptURL)
}

func TestGenEnrollURL(t *testing.T) {
	enrollURL := genEnrollURL("http://localhost:8080/dev", "darwin")
	assert.Equal(t, fmt.Sprintf(OsctrlURLScript, "http://localhost:8080/dev", OsctrlEnroll, "darwin"), enrollURL)
}

func TestGenRemoveURL(t *testing.T) {
	removeURL := genRemoveURL("http://localhost:8080/dev", "darwin")
	assert.Equal(t, fmt.Sprintf(OsctrlURLScript, "http://localhost:8080/dev", OsctrlRemove, "darwin"), removeURL)
}

func TestGenExtensionsURL(t *testing.T) {
	extensionsURL := genExtensionsURL("http://localhost:8080/dev")
	assert.Equal(t, "http://localhost:8080/dev/osctrld-extensions", extensionsURL)
}

func TestGenURLs(t *testing.T) {
	urls := genURLs("http://localhost:8080", "dev", true)
	assert.Equal(t, "http://localhost:8080/dev", urls.URL)
	assert.Equal(t, fmt.Sprintf(OsctrlURLFlags, "http://localhost:8080/dev"), urls.Flags)
	assert.Equal(t, fmt.Sprintf(OsctrlURLCert, "http://localhost:8080/dev"), urls.Cert)
	assert.Equal(t, fmt.Sprintf(OsctrlURLVerify, "http://localhost:8080/dev"), urls.Verify)
	assert.Equal(t, fmt.Sprintf(OsctrlURLScript, "http://localhost:8080/dev", OsctrlEnroll, runtime.GOOS), urls.Enroll)
	assert.Equal(t, fmt.Sprintf(OsctrlURLScript, "http://localhost:8080/dev", OsctrlRemove, runtime.GOOS), urls.Remove)
	assert.Equal(t, "http://localhost:8080/dev/osctrld-extensions", urls.Extensions)
}

func TestOsqueryVersionCompare(t *testing.T) {
	cases := []struct {
		name     string
		existing string
		required string
		expected int
	}{
		{"identical", "1.2.3", "1.2.3", 0},
		{"equal with different component count", "1.2", "1.2.0", 0},
		{"equal with padding both ways", "1.2.0.0", "1.2", 0},
		{"existing higher, same magnitude", "4.0.0", "3.0.0", 1},
		{"required higher, same magnitude", "3.0.0", "4.0.0", 2},
		{"minor does not outrank major", "1.9.0", "2.0.0", 2},
		{"major outranks minor", "2.0.0", "1.9.0", 1},
		{"patch decides", "5.12.1", "5.12.2", 2},
		{"shorter existing is lower", "1.2", "1.2.1", 2},
		{"shorter existing is higher", "1.3", "1.2.9", 1},
		{"double digits are numeric, not lexical", "5.10.0", "5.9.0", 1},
		{"unparseable required", "3.0.0", "a.0.0", -1},
		{"unparseable existing", "3.0.x", "3.0.1", -1},
		{"empty existing", "", "5.0.0", -1},
		{"empty required", "5.0.0", "", -1},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, osqueryVersionCompare(tt.existing, tt.required))
		})
	}
}

func TestGenFullPath(t *testing.T) {
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp", "foobar"))
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp/", "foobar"))
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp", "/foobar"))
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp/", "/foobar"))
}
