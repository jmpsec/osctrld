package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
)

var (
	// upgradeRequestTimeout bounds one resolution POST like a status report
	upgradeRequestTimeout = statusTimeout
	// upgradeGOOS and upgradeGOARCH are seams so tests can pick the platform
	upgradeGOOS   = runtime.GOOS
	upgradeGOARCH = runtime.GOARCH
)

// errUpgradeUnsupported means osctrl does not serve osctrld-osquery: 404, or 405
// from a released osctrl-tls whose GET / pattern matches the path
var errUpgradeUnsupported = errors.New("osctrl does not support osquery upgrades")

// upgradeResolution is the response of POST osctrld-osquery
type upgradeResolution struct {
	Reason          string      `json:"reason"`
	Source          string      `json:"source,omitempty"`
	RequestID       string      `json:"request_id,omitempty"`
	Target          *upgradeRef `json:"target,omitempty"`
	Previous        *upgradeRef `json:"previous,omitempty"`
	ReportedVersion string      `json:"reported_version"`
}

// upgradeRequest is the body of POST osctrld-osquery
type upgradeRequest struct {
	Secret           string `json:"secret"`
	UUID             string `json:"uuid"`
	Platform         string `json:"platform"`
	Arch             string `json:"arch"`
	Format           string `json:"format"`
	InstalledVersion string `json:"installed_version"`
}

// requestUpgradeResolution asks osctrl which osquery version this host should run.
// A 404 or 405 is errUpgradeUnsupported, any other non-200 the typed *httpStatusError.
func requestUpgradeResolution(installed string) (upgradeResolution, error) {
	var res upgradeResolution
	format, err := packageFormatFor(upgradeGOOS, "")
	if err != nil {
		return res, fmt.Errorf("error determining package format - %w", err)
	}
	jsonReq, err := json.Marshal(upgradeRequest{
		Secret:           appConfig.OsctrlSecret,
		UUID:             cachedHostUUID(),
		Platform:         upgradeGOOS,
		Arch:             upgradeGOARCH,
		Format:           string(format),
		InstalledVersion: installed,
	})
	if err != nil {
		return res, fmt.Errorf("error parsing data - %w", err)
	}
	resp, err := sendRequestTimeout(upgradeRequestTimeout, http.MethodPost, osctrlURLs.Osquery, bytes.NewReader(jsonReq), map[string]string{}, appConfig.Insecure)
	if err != nil {
		return res, fmt.Errorf("error sending request - %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return res, fmt.Errorf("error reading response - %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return res, errUpgradeUnsupported
	default:
		return res, &httpStatusError{code: resp.StatusCode, body: body, retryAfter: retryAfter(resp)}
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return upgradeResolution{}, fmt.Errorf("error parsing response - %w", err)
	}
	return res, nil
}
