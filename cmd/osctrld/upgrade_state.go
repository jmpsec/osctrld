package main

import (
	"encoding/json"
	"os"
	"regexp"
	"time"

	"github.com/rs/zerolog/log"
)

// upgradeRef names an osquery package version and its expected SHA-256
type upgradeRef struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// rejectedUpgrade is a target that was tried and undone, never retried unchanged
type rejectedUpgrade struct {
	Version   string `json:"version,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	// Result is the rejected outcome, put back as Last when a skip replaced it
	Result *upgradeResult `json:"result,omitempty"`
}

// pendingUpgrade is an upgrade started but not confirmed yet
type pendingUpgrade struct {
	Target      upgradeRef `json:"target"`
	Previous    upgradeRef `json:"previous"`
	PreviousPkg string     `json:"previous_pkg,omitempty"`
	RequestID   string     `json:"request_id,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	Installed   bool       `json:"installed,omitempty"`
	// Rollback is the reason of a rollback started but not finished
	Rollback string `json:"rollback,omitempty"`
}

// upgradeResult is the last outcome, reported to osctrl in the status report
type upgradeResult struct {
	Result    string    `json:"result,omitempty"`
	Version   string    `json:"version,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	EventID   string    `json:"event_id,omitempty"`
	At        time.Time `json:"at,omitempty"`
}

// skippedUpgrade is a target whose packages could not be used, not
// downloaded again for the same request until upgradeSkipBackoff passes
type skippedUpgrade struct {
	Version   string    `json:"version,omitempty"`
	SHA256    string    `json:"sha256,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	At        time.Time `json:"at,omitempty"`
}

// upgradeState is what osctrld remembers between syncs about osquery upgrades
type upgradeState struct {
	Last     *upgradeResult   `json:"last,omitempty"`
	Rejected *rejectedUpgrade `json:"rejected,omitempty"`
	Pending  *pendingUpgrade  `json:"pending,omitempty"`
	Skipped  *skippedUpgrade  `json:"skipped,omitempty"`
	// ReportedEventID is the event id of the last rejected result osctrl accepted
	ReportedEventID string `json:"reported_event_id,omitempty"`
}

// upgradeStatePath is where upgradeState lives, next to the flagfile
func upgradeStatePath() string {
	return appConfig.OsqueryFlagFile + ".osctrld-upgrade-state.json"
}

// loadUpgradeState falls back to the zero value on any problem
func loadUpgradeState(path string) upgradeState {
	var s upgradeState
	b, err := os.ReadFile(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("no upgrade state")
		return upgradeState{}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		log.Debug().Err(err).Str("path", path).Msg("ignoring corrupt upgrade state")
		return upgradeState{}
	}
	return s
}

func saveUpgradeState(path string, s upgradeState) error {
	return writeStateFile(path, s)
}

var (
	reSHA256    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reVersion   = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,3}$`)
	reRequestID = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func validRef(r *upgradeRef) bool {
	return r != nil && reVersion.MatchString(r.Version) && reSHA256.MatchString(r.SHA256)
}

// validResolution is the trust-boundary check of an osctrl answer: osctrld
// runs as root, so only well-formed refs and request id may start an upgrade
func validResolution(res upgradeResolution) bool {
	return validRef(res.Target) && validRef(res.Previous) && reRequestID.MatchString(res.RequestID)
}

// shouldAttempt says whether to start an upgrade, and why not otherwise. A
// rejected target is retried only when its version, digest or request id changes.
func shouldAttempt(res upgradeResolution, st upgradeState) (bool, string) {
	if res.Reason != "" {
		return false, res.Reason
	}
	if res.Target == nil {
		return false, "no_target"
	}
	if !validResolution(res) {
		return false, "invalid_resolution"
	}
	if r := st.Rejected; r != nil && r.Version == res.Target.Version && r.SHA256 == res.Target.SHA256 && r.RequestID == res.RequestID {
		return false, "rejected"
	}
	return true, ""
}
