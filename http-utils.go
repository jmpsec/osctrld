package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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

// XRealIP for header key
const XRealIP string = "X-Real-IP"

const XForwardedFor string = "X-Forwarded-For"

// Authorization for header key
const Authorization string = "Authorization"

// osctrlUserAgent for customized User-Agent
const osctrlUserAgent string = "osctrld-http-client/" + OsctrldVersion

// SendRequest - Helper function to send HTTP requests
func SendRequest(reqType, reqURL string, params io.Reader, headers map[string]string, insecure bool) (int, []byte, error) {
	u, err := url.Parse(reqURL)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid url: %v", err)
	}
	client := &http.Client{}
	if u.Scheme == "https" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return 0, nil, fmt.Errorf("error loading x509 certificate pool: %v", err)
		}
		tlsCfg := &tls.Config{RootCAs: certPool}
		if insecure {
			tlsCfg.InsecureSkipVerify = true
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}
	req, err := http.NewRequest(reqType, reqURL, params)
	if err != nil {
		return 0, []byte("Cound not prepare request"), err
	}
	// Set custom User-Agent
	req.Header.Set(UserAgent, osctrlUserAgent)
	// Prepare headers
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return 0, []byte("Error sending request"), err
	}
	//defer resp.Body.Close()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Failed to close body %v", err)
		}
	}()
	// Read body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, []byte("Can not read response"), err
	}

	return resp.StatusCode, bodyBytes, nil
}
