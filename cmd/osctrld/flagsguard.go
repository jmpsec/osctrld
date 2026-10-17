package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/process"
)

const (
	applyOK       = "ok"
	applyRejected = "rejected"
	// runningChecks is how many consecutive polls must see osqueryd before new
	// flags count as accepted: a service manager respawning a crashing osqueryd
	// makes it visible for a moment, which must not read as success
	runningChecks = 3
)

// rejectedError is reported to osctrl when osqueryd did not survive new flags
func rejectedError() string {
	return fmt.Sprintf("osqueryd was not running %gs after restart", restartCheckTimeout.Seconds())
}

var (
	// osquerydRunning is a seam so the restart guard can be tested without osqueryd
	osquerydRunning = isOsquerydRunning
	// processNames is a seam over the process list
	processNames         = listProcessNames
	restartCheckTimeout  = 60 * time.Second
	restartCheckInterval = 2 * time.Second
)

// flagsState is what osctrld remembers between syncs about applying flags
type flagsState struct {
	Last           *ApplyStatus `json:"last,omitempty"`
	RejectedSHA256 string       `json:"rejected_sha256,omitempty"`
	// Pending is the SHA-256 of flags written but not verified yet
	Pending string `json:"pending,omitempty"`
	// HostUUID is the last good host UUID, used when the lookup fails
	HostUUID string `json:"host_uuid,omitempty"`
}

// flagsStatePath is where flagsState lives, next to the flagfile it describes
func flagsStatePath() string {
	return appConfig.OsqueryFlagFile + ".osctrld-state.json"
}

// loadFlagsState reads the state, falling back to the zero value on any problem:
// worst case a rejected override is tried (and rolled back) once more
func loadFlagsState(path string) flagsState {
	var s flagsState
	b, err := os.ReadFile(path)
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("no flags state")
		return flagsState{}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		log.Debug().Err(err).Str("path", path).Msg("ignoring corrupt flags state")
		return flagsState{}
	}
	return s
}

func saveFlagsState(path string, s flagsState) error {
	return writeStateFile(path, s)
}

// writeStateFile writes v as JSON, readable by root only
func writeStateFile(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("error encoding state - %v", err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("error writing state to %s - %v", path, err)
	}
	// WriteFile only applies the mode when it creates the file
	if err := os.Chmod(path, 0600); err != nil {
		return fmt.Errorf("error setting mode on %s - %v", path, err)
	}
	return nil
}

// sha256Hex hashes flags exactly as they are written to the flagfile
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func listProcessNames() ([]string, error) {
	ps, err := process.Processes()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		if n, err := p.Name(); err == nil {
			names = append(names, n)
		}
	}
	return names, nil
}

// isOsquerydRunning matches the process name, which works on every OS
func isOsquerydRunning() (bool, error) {
	names, err := processNames()
	if err != nil {
		return false, fmt.Errorf("error getting processes - %v", err)
	}
	for _, n := range names {
		if strings.EqualFold(n, "osqueryd") || strings.EqualFold(n, "osqueryd.exe") {
			return true, nil
		}
	}
	return false, nil
}

func fetchFlags(uuid string, apply *ApplyStatus) (string, error) {
	return retrieveFlags(appConfig.OsctrlSecret, appConfig.OsquerySecretFile, appConfig.OsqueryCertFile, uuid, apply)
}

// syncFlags retrieves the flags for this host, sending its identity and the last
// apply status, and writes them unless they were already rejected. Changed flags
// are marked pending in the state before they reach the disk, so a check that
// never completes is resumed by resumeFlagsCheck. It returns whether the flagfile
// changed, the flags written and the uuid that was sent.
func syncFlags(ctx context.Context) (changed bool, attempted string, uuid string, err error) {
	path := flagsStatePath()
	st := loadFlagsState(path)
	dirty := false
	if uuid, err = hostUUIDReader(); err != nil {
		// A cached uuid keeps an override applied through a flaky lookup instead
		// of flapping between override and environment flags every sync
		uuid = st.HostUUID
		log.Warn().Err(err).Str("cached_uuid", uuid).Msg("host uuid lookup failed, using the last known one")
	} else if uuid != st.HostUUID {
		st.HostUUID = uuid
		dirty = true
	}
	flags, err := fetchFlags(uuid, st.Last)
	if err != nil {
		return false, "", uuid, fmt.Errorf("error retrieving flags - %v", err)
	}
	if st.RejectedSHA256 != "" && sha256Hex(flags) == st.RejectedSHA256 {
		log.Warn().Str("sha256", st.RejectedSHA256).Msg("served flags were rejected before, using environment flags")
		if flags, err = fetchFlags("", st.Last); err != nil {
			return false, "", uuid, fmt.Errorf("error retrieving environment flags - %v", err)
		}
	}
	if !checkFileExist(appConfig.OsqueryFlagFile) || !checkFileContent(appConfig.OsqueryFlagFile, flags) {
		st.Pending = sha256Hex(flags)
		dirty = true
	}
	if dirty {
		// Unverifiable flags are never written: no state, no write
		if err := saveFlagsState(path, st); err != nil {
			return false, "", uuid, err
		}
	}
	changed, err = writeContentExists(appConfig.OsqueryFlagFile, flags, "flags", true, 0700)
	if err != nil {
		return false, "", uuid, err
	}
	return changed, flags, uuid, nil
}

// resumeFlagsCheck finishes the check of flags written by an earlier sync whose
// verification never completed (osctrld stopped or crashed, host rebooted). It
// does not restart osquery first. A pending hash that no longer matches the
// flagfile (edited since) is dropped.
func resumeFlagsCheck(ctx context.Context) error {
	path := flagsStatePath()
	st := loadFlagsState(path)
	if st.Pending == "" {
		return nil
	}
	b, err := os.ReadFile(appConfig.OsqueryFlagFile)
	current := strings.TrimSpace(string(b))
	if err != nil || sha256Hex(current) != st.Pending {
		log.Warn().Str("sha256", st.Pending).Msg("flagfile changed since it was written, dropping its pending check")
		st.Pending = ""
		return saveFlagsState(path, st)
	}
	log.Info().Str("sha256", st.Pending).Msg("resuming check of unverified flags")
	return verifyFlagsAfterRestart(ctx, current, st.HostUUID)
}

// waitForOsqueryd polls until osqueryd has been seen on runningChecks
// consecutive polls, or restartCheckTimeout passes
func waitForOsqueryd(ctx context.Context) (bool, error) {
	seen := 0
	return pollUntil(ctx, func() bool {
		running, err := osquerydRunning()
		if err != nil {
			log.Debug().Err(err).Msg("error checking osqueryd")
		}
		if !running {
			seen = 0
			return false
		}
		seen++
		return seen >= runningChecks
	})
}

// pollUntil calls check every restartCheckInterval until it returns true, or
// restartCheckTimeout passes
func pollUntil(ctx context.Context, check func() bool) (bool, error) {
	deadline := time.After(restartCheckTimeout)
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline:
			return false, nil
		case <-time.After(restartCheckInterval):
		}
		if check() {
			return true, nil
		}
	}
}

// verifyFlagsAfterRestart checks osqueryd survived the attempted flags and
// clears their pending mark. If it did not, it writes the environment flags back, restarts osquery once and
// remembers the attempted content so it is not applied again. The outcome is
// reported to osctrl on the next flags request.
func verifyFlagsAfterRestart(ctx context.Context, attempted string, uuid string) error {
	path := flagsStatePath()
	sum := sha256Hex(attempted)
	running, err := waitForOsqueryd(ctx)
	if err != nil {
		// Pending stays set, the next sync resumes the check
		return err
	}
	st := loadFlagsState(path)
	// Every outcome below completes the check. The rollback's own restart is
	// deliberately not verified, so no new Pending is set for the env flags.
	st.Pending = ""
	if running {
		log.Info().Str("sha256", sum).Msg("osqueryd is running with the new flags")
		st.Last = &ApplyStatus{Result: applyOK, SHA256: sum, At: time.Now().UTC()}
		return saveFlagsState(path, st)
	}
	log.Error().Str("sha256", sum).Str("uuid", uuid).Msg("osqueryd is not running after flags change, rolling back")
	st.Last = &ApplyStatus{Result: applyRejected, SHA256: sum, Error: rejectedError(), At: time.Now().UTC()}
	env, fetchErr := fetchFlags("", nil)
	if fetchErr != nil {
		// Remember the rejection anyway: the next sync then writes the environment flags
		st.RejectedSHA256 = sum
		if err := saveFlagsState(path, st); err != nil {
			log.Error().Err(err).Msg("failed to save flags state")
		}
		return fmt.Errorf("error retrieving environment flags for rollback - %v", fetchErr)
	}
	if env == attempted {
		// Not an override that failed, nothing to roll back to
		log.Error().Msg("environment flags do not keep osqueryd running")
		return saveFlagsState(path, st)
	}
	st.RejectedSHA256 = sum
	if err := saveFlagsState(path, st); err != nil {
		return err
	}
	if _, err := writeContentExists(appConfig.OsqueryFlagFile, env, "flags", true, 0700); err != nil {
		return err
	}
	return restartOsquery()
}
