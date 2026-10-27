package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// JSONApplication for Content-Type headers
const JSONApplication string = "application/json"

// JSONApplicationUTF8 for Content-Type headers, UTF charset
const JSONApplicationUTF8 string = JSONApplication + "; charset=UTF-8"

// TextPlain for Content-Type headers
const TextPlain string = "text/plain"

// TextPlainUTF8 for Content-Type headers, UTF charset
const TextPlainUTF8 string = TextPlain + "; charset=UTF-8"

// ContentType for header key
const ContentType string = "Content-Type"

// UserAgent for header key
const UserAgent string = "User-Agent"

// Authorization for header key
const Authorization string = "Authorization"

// osctrlUserAgent for customized User-Agent
const osctrlUserAgent string = "osctrld-http-client/" + OsctrldVersion

// httpTimeout bounds a whole request, body included, so a stalled server
// cannot hang the service loop. It is generous because the same client
// downloads osquery packages of around 100 MB.
// ponytail: one timeout for everything; split dial/header timeouts from the
// body timeout if a stalled server must be detected faster.
var httpTimeout = 10 * time.Minute

// maxRedirects bounds a redirect chain, the same limit net/http uses by default
const maxRedirects = 10

// redirectPolicy is the CheckRedirect for every request. A redirect never goes
// from https down to http. Requests to osctrl carry the enrollment secret in
// the body, which a 307/308 re-sends, so they only follow redirects within the
// same scheme, host and port; crossHost lets a package download, which carries
// no secret and is hash-verified, follow an https mirror to a CDN.
func redirectPolicy(crossHost bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		from, to := via[0].URL, req.URL
		if from.Scheme == "https" && to.Scheme != "https" {
			return fmt.Errorf("refusing redirect from https to %s://%s", to.Scheme, to.Host)
		}
		if to.Scheme != "http" && to.Scheme != "https" {
			return fmt.Errorf("refusing redirect to %s://%s", to.Scheme, to.Host)
		}
		if crossHost || sameOrigin(from, to) {
			return nil
		}
		return fmt.Errorf("refusing redirect from %s://%s to %s://%s", from.Scheme, from.Host, to.Scheme, to.Host)
	}
}

// sameOrigin is the same scheme, host and port, with default ports filled in,
// or an upgrade from http to https on the same host name, whatever the ports
func sameOrigin(from, to *url.URL) bool {
	if !strings.EqualFold(from.Hostname(), to.Hostname()) {
		return false
	}
	if from.Scheme == "http" && to.Scheme == "https" {
		return true
	}
	return from.Scheme == to.Scheme && portOrDefault(from) == portOrDefault(to)
}

func portOrDefault(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// SendRequestStream sends an HTTP request like SendRequest but hands back the
// response unread, so a large body can be streamed. The caller closes the body.
func SendRequestStream(reqType, reqURL string, params io.Reader, headers map[string]string, insecure bool) (*http.Response, error) {
	return sendRequestTimeout(httpTimeout, reqType, reqURL, params, headers, insecure)
}

// sendRequestTimeout is SendRequestStream with an explicit whole-request timeout
func sendRequestTimeout(timeout time.Duration, reqType, reqURL string, params io.Reader, headers map[string]string, insecure bool) (*http.Response, error) {
	return sendRequest(timeout, false, reqType, reqURL, params, headers, insecure)
}

// downloadStream GETs a package that carries no secret, following redirects to
// other https hosts. The caller closes the body.
func downloadStream(reqURL string, insecure bool) (*http.Response, error) {
	return sendRequest(httpTimeout, true, http.MethodGet, reqURL, nil, map[string]string{}, insecure)
}

// newHTTPClient builds the client for one request with its own TLS settings,
// so --insecure never leaks into another request
func newHTTPClient(timeout time.Duration, crossHost bool, insecure bool) (*http.Client, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error loading x509 certificate pool: %v", err)
	}
	tlsCfg := &tls.Config{RootCAs: certPool}
	if insecure {
		tlsCfg.InsecureSkipVerify = true
	}
	// Built for http too, so an http request redirected to https keeps these
	// TLS settings. A transport per request, so idle connections must time out
	// or each request would leave one open; 90s matches http.DefaultTransport.
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: redirectPolicy(crossHost),
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			Proxy:           http.ProxyFromEnvironment,
			IdleConnTimeout: 90 * time.Second,
		},
	}, nil
}

func sendRequest(timeout time.Duration, crossHost bool, reqType, reqURL string, params io.Reader, headers map[string]string, insecure bool) (*http.Response, error) {
	if _, err := url.Parse(reqURL); err != nil {
		return nil, fmt.Errorf("invalid url: %v", err)
	}
	client, err := newHTTPClient(timeout, crossHost, insecure)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(reqType, reqURL, params)
	if err != nil {
		return nil, fmt.Errorf("could not prepare request: %v", err)
	}
	// Set custom User-Agent
	req.Header.Set(UserAgent, osctrlUserAgent)
	// Prepare headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	return client.Do(req)
}

// SendRequest - Helper function to send HTTP requests
func SendRequest(reqType, reqURL string, params io.Reader, headers map[string]string, insecure bool) (int, []byte, error) {
	resp, err := SendRequestStream(reqType, reqURL, params, headers, insecure)
	if err != nil {
		return 0, []byte("Error sending request"), err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Error().Err(err).Msg("failed to close response body")
		}
	}()
	// Read body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, []byte("Can not read response"), err
	}

	return resp.StatusCode, bodyBytes, nil
}
