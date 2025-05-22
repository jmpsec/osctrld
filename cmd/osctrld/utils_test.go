package main

import (
	"fmt"
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

func TestGenURLs(t *testing.T) {
	urls := genURLs("http://localhost:8080", "dev", true)
	assert.Equal(t, "http://localhost:8080/dev", urls.URL)
	assert.Equal(t, fmt.Sprintf(OsctrlURLFlags, "http://localhost:8080/dev"), urls.Flags)
	assert.Equal(t, fmt.Sprintf(OsctrlURLCert, "http://localhost:8080/dev"), urls.Cert)
	assert.Equal(t, fmt.Sprintf(OsctrlURLVerify, "http://localhost:8080/dev"), urls.Verify)
	assert.Equal(t, fmt.Sprintf(OsctrlURLScript, "http://localhost:8080/dev", OsctrlEnroll, "darwin"), urls.Enroll)
	assert.Equal(t, fmt.Sprintf(OsctrlURLScript, "http://localhost:8080/dev", OsctrlRemove, "darwin"), urls.Remove)
}

func TestOsqueryVersionCompare(t *testing.T) {
	assert.Equal(t, 0, osqueryVersionCompare("1.2.3", "1.2.3"))
	assert.Equal(t, 1, osqueryVersionCompare("4.0.0", "3.0.0"))
	assert.Equal(t, 2, osqueryVersionCompare("3.0.0", "4.0.0"))
	assert.Equal(t, -1, osqueryVersionCompare("3.0.0", "a.0.0"))
}

func TestGenFullPath(t *testing.T) {
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp", "foobar"))
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp/", "foobar"))
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp", "/foobar"))
	assert.Equal(t, "/tmp/foobar", genFullPath("/tmp/", "/foobar"))
}
