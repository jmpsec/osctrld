package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// statusTimeout bounds one status POST so a stalled osctrl cannot block the service loop
var statusTimeout = 15 * time.Second

// errStatusUnsupported means osctrl does not serve osctrld-status: 404, or 405
// from a released osctrl-tls whose GET / pattern matches the path
var errStatusUnsupported = errors.New("osctrl does not support status reports")

// statusStage is a rollback outcome as sent on the wire
type statusStage struct {
	Stage   string `json:"stage"`
	EventID string `json:"event_id"`
}

// statusReport is the body of POST osctrld-status
type statusReport struct {
	Secret         string      `json:"secret"`
	UUID           string      `json:"uuid"`
	OsqueryRunning bool        `json:"osquery_running"`
	DownSince      *time.Time  `json:"down_since,omitempty"`
	Flags          statusStage `json:"flags"`
	Extensions     statusStage `json:"extensions"`
	// Upgrade is the last osquery upgrade outcome, omitted when there is none
	Upgrade *upgradeReport `json:"upgrade,omitempty"`
}

// upgradeReport is an osquery upgrade outcome as sent on the wire
type upgradeReport struct {
	Result    string `json:"result"`
	Version   string `json:"version,omitempty"`
	Reason    string `json:"reason,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	EventID   string `json:"event_id,omitempty"`
}

// wireStage maps the stored empty stage to the wire "none"
func wireStage(stage, eventID string) statusStage {
	if stage == "" || stage == stageNone {
		return statusStage{Stage: "none"}
	}
	return statusStage{Stage: stage, EventID: eventID}
}

// buildStatusReport reads rollback stages from the two state files
func buildStatusReport(uuid string, running bool, downSince time.Time) statusReport {
	fs := loadFlagsState(flagsStatePath())
	es := loadExtState(extStatePath())
	r := statusReport{
		UUID:           uuid,
		OsqueryRunning: running,
		Flags:          wireStage(fs.Stage, fs.EventID),
		Extensions:     wireStage("", ""),
	}
	if es.Rollback != nil {
		r.Extensions = wireStage(es.Rollback.Stage, es.Rollback.EventID)
	}
	if !running && !downSince.IsZero() {
		r.DownSince = &downSince
	}
	r.Upgrade = wireUpgrade(loadUpgradeState(upgradeStatePath()).Last)
	return r
}

// reportedUpgradeReasons are the reasons osctrl accepts; local ones such as
// invalid_resolution are never reported
var reportedUpgradeReasons = map[string]bool{
	"": true, reasonNoTarget: true, reasonAheadOfTarget: true, reasonNoDigestForTarget: true,
	reasonNoDigestForInstalled: true, reasonUnsupportedPlatform: true, reasonPreviousUnavailable: true,
	reasonTargetUnavailable: true, reasonDigestMismatch: true, reasonVersionNotReported: true,
	reasonOsquerydNotRunning: true, reasonInstallFailed: true, reasonConfigChanged: true, reasonRolledBack: true, reasonRollbackUnavailable: true,
	reasonRolloutPending: true, reasonRolloutPaused: true,
}

// wireUpgrade maps the last upgrade outcome to the report; event_id only
// travels with a rejected result
func wireUpgrade(last *upgradeResult) *upgradeReport {
	if last == nil || last.Result == "" || !reportedUpgradeReasons[last.Reason] {
		return nil
	}
	u := &upgradeReport{Result: last.Result, Version: last.Version, Reason: last.Reason, RequestID: last.RequestID}
	if last.Result == upgradeRejected {
		u.EventID = last.EventID
	}
	return u
}

// sendStatusReport posts the report; a 404 or 405 is errStatusUnsupported, any other
// non-200 is the typed *httpStatusError
func sendStatusReport(r statusReport) error {
	r.Secret = appConfig.OsctrlSecret
	jsonReq, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("error parsing data - %w", err)
	}
	// Own short timeout: genericRetrieve's is sized for package downloads
	resp, err := sendRequestTimeout(statusTimeout, http.MethodPost, osctrlURLs.Status, bytes.NewReader(jsonReq), map[string]string{}, appConfig.Insecure)
	if err != nil {
		return fmt.Errorf("error sending request - %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return fmt.Errorf("error reading response - %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		err = &httpStatusError{code: resp.StatusCode, body: body, retryAfter: retryAfter(resp)}
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && (statusErr.code == http.StatusNotFound || statusErr.code == http.StatusMethodNotAllowed) {
		return errStatusUnsupported
	}
	return err
}

// maxRetryAfter caps how long a 429 can hold back status reports
const maxRetryAfter = time.Hour

// retryAfter reads a 429's Retry-After in whole seconds, capped at
// maxRetryAfter; absent, zero, negative or an HTTP date is no delay
func retryAfter(resp *http.Response) time.Duration {
	if resp.StatusCode != http.StatusTooManyRequests {
		return 0
	}
	s, err := strconv.ParseInt(resp.Header.Get("Retry-After"), 10, 64)
	if err != nil || s <= 0 {
		return 0
	}
	return time.Duration(min(s, int64(maxRetryAfter/time.Second))) * time.Second
}
