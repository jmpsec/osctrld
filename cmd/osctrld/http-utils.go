package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// SendRequestStream sends an HTTP request like SendRequest but hands back the
// response unread, so a large body can be streamed. The caller closes the body.
func SendRequestStream(reqType, reqURL string, params io.Reader, headers map[string]string, insecure bool) (*http.Response, error) {
	return sendRequestTimeout(httpTimeout, reqType, reqURL, params, headers, insecure)
}

// sendRequestTimeout is SendRequestStream with an explicit whole-request timeout
func sendRequestTimeout(timeout time.Duration, reqType, reqURL string, params io.Reader, headers map[string]string, insecure bool) (*http.Response, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %v", err)
	}
	client := &http.Client{Timeout: timeout}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error loading x509 certificate pool: %v", err)
		}
		tlsCfg := &tls.Config{RootCAs: certPool}
		if insecure {
			tlsCfg.InsecureSkipVerify = true
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
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
