package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// A server that accepts the connection and never answers must not hang the
// service loop forever
func TestSendRequestTimesOut(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	prev := httpTimeout
	t.Cleanup(func() { httpTimeout = prev })
	httpTimeout = 50 * time.Millisecond

	start := time.Now()
	_, _, err := SendRequest(http.MethodGet, server.URL, nil, map[string]string{}, false)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// bodyRecorder is a server that records every request body it gets
func bodyRecorder(t *testing.T, tls bool) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var got []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, string(b))
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	})
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, &got
}

// redirector answers every request with a 307 to target, which re-sends a POST body
func redirector(t *testing.T, target string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			b, _ := io.ReadAll(r.Body)
			_, _ = w.Write(b)
			return
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// localhostURL points srv at localhost instead of 127.0.0.1: another host
func localhostURL(srv *httptest.Server) string {
	return strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
}

const secretBody = `{"secret":"enroll-me"}`

// Requests to osctrl carry the enrollment secret in the body, so a redirect
// may only stay on the same scheme, host and port
func TestSendRequestRedirectPolicy(t *testing.T) {
	t.Run("https to http on another host gets no body", func(t *testing.T) {
		plain, got := bodyRecorder(t, false)
		src := redirector(t, plain.URL+"/steal")
		_, _, err := SendRequest(http.MethodPost, src.URL+"/flags", strings.NewReader(secretBody), map[string]string{}, true)
		assert.Error(t, err)
		assert.Empty(t, *got)
	})
	t.Run("https cross-host redirect refused", func(t *testing.T) {
		other, got := bodyRecorder(t, true)
		src := redirector(t, localhostURL(other)+"/steal")
		_, _, err := SendRequest(http.MethodPost, src.URL+"/flags", strings.NewReader(secretBody), map[string]string{}, true)
		assert.Error(t, err)
		assert.Empty(t, *got)
	})
	t.Run("same-origin redirect still works", func(t *testing.T) {
		var src *httptest.Server
		src = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/final" {
				b, _ := io.ReadAll(r.Body)
				_, _ = w.Write(b)
				return
			}
			http.Redirect(w, r, src.URL+"/final", http.StatusTemporaryRedirect)
		}))
		t.Cleanup(src.Close)
		code, body, err := SendRequest(http.MethodPost, src.URL+"/flags", strings.NewReader(secretBody), map[string]string{}, true)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, secretBody, string(body))
	})
	t.Run("redirect loop is bounded", func(t *testing.T) {
		var src *httptest.Server
		src = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, src.URL+"/again", http.StatusTemporaryRedirect)
		}))
		t.Cleanup(src.Close)
		_, _, err := SendRequest(http.MethodPost, src.URL, strings.NewReader(secretBody), map[string]string{}, true)
		assert.Error(t, err)
	})
}

// Package downloads carry no secret and are hash-verified, so they may follow
// an https mirror to a CDN on another host, but never down to http
func TestDownloadPackageRedirectPolicy(t *testing.T) {
	t.Run("follows https cross-host redirect", func(t *testing.T) {
		cdn, got := bodyRecorder(t, true)
		src := redirector(t, localhostURL(cdn)+"/osquery.pkg")
		path, err := downloadPackage(src.URL+"/osquery.pkg", "", true, true)
		require.NoError(t, err)
		_ = os.Remove(path)
		assert.Len(t, *got, 1)
	})
	t.Run("refuses https to http downgrade", func(t *testing.T) {
		plain, got := bodyRecorder(t, false)
		src := redirector(t, plain.URL+"/osquery.pkg")
		path, err := downloadPackage(src.URL+"/osquery.pkg", "", true, true)
		if err == nil {
			_ = os.Remove(path)
		}
		assert.Error(t, err)
		assert.Empty(t, *got)
	})
}

// The transport honours HTTPS_PROXY like the default one does for http,
// closes idle connections, and keeps its TLS settings
func TestHTTPSClientTransport(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		c, err := newHTTPClient(time.Minute, false, insecure)
		require.NoError(t, err)
		tr, ok := c.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, tr.Proxy)
		assert.Equal(t, reflect.ValueOf(http.ProxyFromEnvironment).Pointer(), reflect.ValueOf(tr.Proxy).Pointer())
		assert.Positive(t, tr.IdleConnTimeout)
		assert.Equal(t, insecure, tr.TLSClientConfig.InsecureSkipVerify)
		assert.NotNil(t, tr.TLSClientConfig.RootCAs)
		assert.Equal(t, time.Minute, c.Timeout)
		assert.NotNil(t, c.CheckRedirect)
	}
}

func TestRedirectPolicySameOrigin(t *testing.T) {
	tests := []struct {
		from, to string
		ok       bool
	}{
		{"https://h/a", "https://h/b", true},
		{"https://h/a", "https://h:443/b", true},
		{"https://h:443/a", "https://h/b", true},
		{"http://h/a", "http://h:80/b", true},
		{"http://h:80/a", "https://h:443/b", true},
		{"http://h/a", "https://h/b", true},
		{"http://h:8080/a", "https://h:8443/b", true},
		{"http://H/a", "https://h/b", true},
		{"https://h/a", "https://h:8443/b", false},
		{"http://h/a", "http://h:8080/b", false},
		{"http://a/x", "https://b/x", false},
		{"https://a/x", "https://b/x", false},
		{"https://h/a", "http://h/b", false},
		{"https://h:443/a", "http://h:80/b", false},
		{"http://h/a", "ftp://h/b", false},
	}
	for _, tt := range tests {
		t.Run(tt.from+" -> "+tt.to, func(t *testing.T) {
			from, _ := http.NewRequest(http.MethodPost, tt.from, nil)
			to, _ := http.NewRequest(http.MethodPost, tt.to, nil)
			err := redirectPolicy(false)(to, []*http.Request{from})
			if tt.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// An http osctrl behind a load balancer that redirects to https on the same
// host keeps working, and the body reaches the https side
func TestSendRequestUpgradesToHTTPS(t *testing.T) {
	tlsSrv := redirector(t, "unused")
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, tlsSrv.URL+"/final", http.StatusPermanentRedirect)
	}))
	t.Cleanup(plain.Close)
	code, body, err := SendRequest(http.MethodPost, plain.URL+"/flags", strings.NewReader(secretBody), map[string]string{}, true)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, secretBody, string(body))
}
