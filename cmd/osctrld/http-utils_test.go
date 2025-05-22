package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func serverMock() *httptest.Server {
	handler := http.NewServeMux()
	handler.HandleFunc("/server/testing", testingMock)
	srv := httptest.NewServer(handler)
	return srv
}

func testingMock(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("the test works"))
}

func captureOutput(f func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	f()
	log.SetOutput(os.Stderr)
	return buf.String()
}

func TestSendRequest(t *testing.T) {
	server := serverMock()
	defer server.Close()

	t.Run("empty url", func(t *testing.T) {
		code, _, err := SendRequest(http.MethodPost, "", nil, map[string]string{}, false)
		assert.Error(t, err)
		assert.Equal(t, 0, code)
	})
	t.Run("invalid url", func(t *testing.T) {
		_, _, err := SendRequest(http.MethodPost, "http://whatever/notfound", nil, map[string]string{}, false)
		assert.Error(t, err)
	})
	t.Run("url not found", func(t *testing.T) {
		code, _, err := SendRequest(http.MethodPost, server.URL+"/notfound", nil, map[string]string{}, false)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, code)
	})
	t.Run("url not found", func(t *testing.T) {
		code, body, err := SendRequest(http.MethodPost, server.URL+"/server/testing", nil, map[string]string{}, false)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, []byte("the test works"), body)
	})
	t.Run("https url", func(t *testing.T) {
		_, _, err := SendRequest(http.MethodPost, "https://whatever/notfound", nil, map[string]string{}, false)
		assert.Error(t, err)
	})
	t.Run("headers url", func(t *testing.T) {
		headers := make(map[string]string)
		headers["test"] = "aaa"
		_, _, err := SendRequest(http.MethodPost, server.URL+"/server/testing", nil, headers, false)
		assert.NoError(t, err)
	})
}
