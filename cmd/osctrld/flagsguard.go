package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// Rollback stages, the outcome of the last rollback chain
const (
	stageNone          = ""
	stageEnvironment   = "environment"
	stageLastKnownGood = "last_known_good"
	stageExhausted     = "exhausted"
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
	// PendingStage is set when Pending is a rollback fallback, not what osctrl served
	PendingStage string `json:"pending_stage,omitempty"`
	// HostUUID is the last good host UUID, used when the lookup fails
	HostUUID string `json:"host_uuid,omitempty"`
	// LastGoodSHA256 is the hash of the content in lastGoodPath
	LastGoodSHA256 string `json:"last_good_sha256,omitempty"`
	// RejectedEnvSHA256 is the hash of environment flags osqueryd did not survive
	RejectedEnvSHA256 string `json:"rejected_env_sha256,omitempty"`
	// Stage is where the last rollback chain ended, EventID identifies it
	Stage   string `json:"stage,omitempty"`
	EventID string `json:"event_id,omitempty"`
}

// newEventID identifies a rollback by when it happened and what failed
func newEventID(failedContent string, at time.Time) string {
	return fmt.Sprintf("%d:%s", at.UnixNano(), sha256Hex(failedContent))
}

// lastGoodPath holds the last flags osqueryd was verified running with
func lastGoodPath() string {
	return appConfig.OsqueryFlagFile + ".osctrld-lastgood"
}

func saveLastGood(content string) error {
	return writeFileAtomic(lastGoodPath(), []byte(content), 0600)
}

// loadLastGood returns the last good flags, if the file still matches the state
func loadLastGood(st flagsState) (string, bool) {
	if st.LastGoodSHA256 == "" {
		return "", false
	}
	b, err := os.ReadFile(lastGoodPath())
	if err != nil || sha256Hex(string(b)) != st.LastGoodSHA256 {
		return "", false
	}
	return string(b), true
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
	return writeFileAtomic(path, b, 0600)
}

// writeFileAtomic replaces path with a new file owned by this process (root),
// so a failed write leaves the previous content in place
func writeFileAtomic(path string, b []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("error writing %s - %v", path, err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.Write(b); err != nil {
		return fmt.Errorf("error writing %s - %v", path, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("error writing %s - %v", path, err)
	}
	if err = os.Chmod(tmp.Name(), mode); err != nil {
		return fmt.Errorf("error setting mode on %s - %v", path, err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("error writing %s - %v", path, err)
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
	flags = settledFlags(st, flags)
	if !checkFileExist(appConfig.OsqueryFlagFile) || !checkFileContent(appConfig.OsqueryFlagFile, flags) {
		st.Pending, st.PendingStage = sha256Hex(flags), ""
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

// settledFlags is what to write instead of flags: the last known good while
// flags are environment flags that were rejected, unless the last good is a
// rejected override itself
func settledFlags(st flagsState, flags string) string {
	if st.RejectedEnvSHA256 == "" || sha256Hex(flags) != st.RejectedEnvSHA256 || st.LastGoodSHA256 == st.RejectedSHA256 {
		return flags
	}
	if lastGood, ok := loadLastGood(st); ok {
		log.Warn().Str("sha256", st.RejectedEnvSHA256).Msg("environment flags were rejected before, using last known good flags")
		return lastGood
	}
	return flags
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
		st.Pending, st.PendingStage = "", ""
		return saveFlagsState(path, st)
	}
	log.Info().Str("sha256", st.Pending).Msg("resuming check of unverified flags")
	return verifyFlagsAfterRestart(ctx, current, st.HostUUID)
}

// waitForOsqueryd polls until osqueryd has been seen on runningChecks
// consecutive polls, or restartCheckTimeout passes
func waitForOsqueryd(ctx context.Context) (bool, error) {
	seen := 0
	running, err := pollUntil(ctx, func() bool {
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
	if err == nil {
		// Completed, not cancelled: the end-of-sync report takes it as the state
		verified = &running
	}
	return running, err
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
// clears their pending mark. Flags that run become the last known good; flags
// that do not start the rollback chain. The outcome is reported to osctrl on
// the next flags request.
func verifyFlagsAfterRestart(ctx context.Context, attempted string, uuid string) error {
	path := flagsStatePath()
	sum := sha256Hex(attempted)
	running, err := waitForOsqueryd(ctx)
	if err != nil {
		// Pending stays set, the next sync resumes the check
		return err
	}
	st := loadFlagsState(path)
	// A resumed rollback fallback is not what osctrl served: its outcome
	// belongs to the chain, and Last keeps the rejection that started it
	if st.PendingStage != "" && st.Pending == sum {
		if !running {
			return rollbackFlags(ctx, &st, attempted)
		}
		log.Info().Str("stage", st.PendingStage).Msg("osqueryd is running with rolled back flags")
		return saveFlagsState(path, fallbackRan(st, attempted))
	}
	st.Pending = ""
	if running {
		log.Info().Str("sha256", sum).Msg("osqueryd is running with the new flags")
		st.Last = &ApplyStatus{Result: applyOK, SHA256: sum, At: time.Now().UTC()}
		st.Stage, st.EventID = stageNone, ""
		if err := saveLastGood(attempted); err != nil {
			log.Error().Err(err).Msg("failed to save last known good flags")
		} else {
			st.LastGoodSHA256 = sum
		}
		return saveFlagsState(path, st)
	}
	log.Error().Str("sha256", sum).Str("uuid", uuid).Msg("osqueryd is not running after flags change, rolling back")
	st.Last = &ApplyStatus{Result: applyRejected, SHA256: sum, Error: rejectedError(), At: time.Now().UTC()}
	return rollbackFlags(ctx, &st, attempted)
}

// fallbackRan ends the chain at the fallback osqueryd runs with; environment
// flags that run become the last known good
func fallbackRan(st flagsState, content string) flagsState {
	if st.PendingStage == stageEnvironment {
		if err := saveLastGood(content); err != nil {
			log.Error().Err(err).Msg("failed to save last known good flags")
		} else {
			st.LastGoodSHA256 = sha256Hex(content)
		}
	}
	st.Stage = st.PendingStage
	st.Pending, st.PendingStage = "", ""
	return st
}

// rollbackFlags records the attempted flags as failed and tries, in order, the
// environment flags and the last known good flags, each restarted once and
// verified. Content that already failed is skipped, so the chain never loops:
// after it is exhausted osqueryd is left down until osctrl serves new flags.
func rollbackFlags(ctx context.Context, st *flagsState, attempted string) error {
	path := flagsStatePath()
	sum := sha256Hex(attempted)
	lastGood, hasLastGood := loadLastGood(*st)
	env, fetchErr := fetchFlags("", nil)
	if fetchErr != nil {
		fetchErr = fmt.Errorf("error retrieving environment flags for rollback - %v", fetchErr)
		log.Error().Err(fetchErr).Msg("rolling back without environment flags")
	}
	// The attempted content is classified by what it is, so a resumed chain
	// continues where it stopped. The last known good is only a fallback once
	// the environment flags failed; otherwise it is what osctrl served.
	switch {
	case fetchErr == nil && attempted == env:
		st.RejectedEnvSHA256 = sum
	case hasLastGood && attempted == lastGood && (fetchErr != nil || sha256Hex(env) == st.RejectedEnvSHA256):
	default:
		st.RejectedSHA256 = sum
	}
	// A resumed fallback continues its chain and its event
	if st.PendingStage == "" || st.Pending != sum {
		st.EventID = newEventID(attempted, time.Now())
	}
	type candidate struct{ stage, content string }
	var candidates []candidate
	if fetchErr == nil && env != attempted && sha256Hex(env) != st.RejectedEnvSHA256 {
		candidates = append(candidates, candidate{stageEnvironment, env})
	}
	// An exhausted chain already tried the last known good, and a rejected
	// override that is also the last known good is not retried either
	if hasLastGood && st.Stage != stageExhausted && st.LastGoodSHA256 != st.RejectedSHA256 &&
		lastGood != attempted && (fetchErr != nil || lastGood != env) {
		candidates = append(candidates, candidate{stageLastKnownGood, lastGood})
	}
	for _, c := range candidates {
		csum := sha256Hex(c.content)
		st.Pending, st.PendingStage = csum, c.stage
		if err := saveFlagsState(path, *st); err != nil {
			return err
		}
		if _, err := writeContentExists(appConfig.OsqueryFlagFile, c.content, "flags", true, 0700); err != nil {
			return err
		}
		log.Warn().Str("stage", c.stage).Str("sha256", csum).Msg("rolling back flags")
		if err := restartOsquery(); err != nil {
			log.Error().Err(err).Msg("failed to restart osquery")
		}
		running, err := waitForOsqueryd(ctx)
		if err != nil {
			// Pending stays set, the next sync resumes the chain from here
			return err
		}
		if running {
			log.Info().Str("stage", c.stage).Msg("osqueryd is running with rolled back flags")
			return errors.Join(saveFlagsState(path, fallbackRan(*st, c.content)), fetchErr)
		}
		log.Error().Str("stage", c.stage).Str("sha256", csum).Msg("osqueryd is not running with rolled back flags")
		if c.stage == stageEnvironment {
			st.RejectedEnvSHA256 = csum
		}
	}
	st.Pending, st.PendingStage, st.Stage = "", "", stageExhausted
	log.Error().Msg("no flags keep osqueryd running, rollback exhausted")
	if err := saveFlagsState(path, *st); err != nil {
		return errors.Join(err, fetchErr)
	}
	if fetchErr != nil {
		return fetchErr
	}
	// Leave what the next sync serves in place, without a restart: all of it
	// already failed, and a sync that changes nothing restarts nothing
	_, err := writeContentExists(appConfig.OsqueryFlagFile, settledFlags(*st, env), "flags", true, 0700)
	return err
}
