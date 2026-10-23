package main

import (
	"context"
	"errors"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

func intervalWithJitter(base time.Duration) time.Duration {
	jitterRange := float64(base) * 0.2
	jitter := rand.Float64()*jitterRange - jitterRange/2
	return base + time.Duration(jitter)
}

func syncOnce(ctx context.Context, cmd *cli.Command) {
	originalForce := appConfig.Force
	appConfig.Force = true
	defer func() { appConfig.Force = originalForce }()

	var flagsChanged, certChanged bool
	verified = nil

	// A half-finished upgrade is repaired before flags, cert or extensions write anything
	if err := resumeUpgrade(ctx); err != nil {
		log.Error().Err(err).Msg("failed to resume osquery upgrade")
	}
	if ctx.Err() != nil {
		return
	}

	if err := resumeFlagsCheck(ctx); err != nil {
		log.Error().Err(err).Msg("failed to resume flags check")
		if ctx.Err() != nil {
			return
		}
	}

	log.Info().Msg("syncing flags")
	flagsChanged, attempted, uuid, err := syncFlags(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to sync flags")
	}

	log.Info().Msg("syncing cert")
	if changed, err := getCert(ctx, cmd); err != nil {
		log.Error().Err(err).Msg("failed to sync cert")
	} else {
		certChanged = changed
	}

	if flagsChanged || certChanged {
		log.Info().
			Bool("flags_changed", flagsChanged).
			Bool("cert_changed", certChanged).
			Msg("configuration changed, restarting osquery")
		if err := restartOsquery(); err != nil {
			// Still verify: osqueryd may be down with the new flags either way
			log.Error().Err(err).Msg("failed to restart osquery")
		}
		if flagsChanged {
			if err := verifyFlagsAfterRestart(ctx, attempted, uuid); err != nil {
				log.Error().Err(err).Msg("failed to verify flags after restart")
			}
		}
	}

	// Extensions go second, with their own restart and check, so a failure is
	// blamed on the right change and a bad extension never rolls back good flags
	if ctx.Err() != nil {
		return
	}
	if err := resumeExtensionsCheck(ctx); err != nil {
		log.Error().Err(err).Msg("failed to resume extensions check")
		if ctx.Err() != nil {
			return
		}
	}
	log.Info().Msg("syncing extensions")
	extensionsChanged, err := syncExtensionsStep(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to sync extensions")
	}
	if extensionsChanged {
		log.Info().Msg("extensions changed, restarting osquery")
		// Still verifies after a failed restart: osqueryd may be down either way
		restartForExtensions()
		if err := verifyExtensionsAfterRestart(ctx); err != nil {
			log.Error().Err(err).Msg("failed to verify extensions after restart")
		}
	}

	// A verification this sync means osquery restarted for something else: an
	// upgrade now would blame the wrong change
	upgradeStep(ctx, flagsChanged || certChanged || extensionsChanged || verified != nil)

	// Every sync ends with a report of the current state, which also re-tests an
	// osctrl that answered "unsupported"
	if ctx.Err() != nil {
		return
	}
	now := time.Now()
	observeSyncEnd(now)
	reportStatus(now)
}

func serviceNode(ctx context.Context, cmd *cli.Command) error {
	interval := syncInterval()
	log.Info().Int("interval_minutes", appConfig.Interval).Msg("starting service")

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	sweepStaleDownloads(staleDownloadAge)
	syncOnce(ctx, cmd)

	// One goroutine: the watcher never runs during a sync's verification waits
	watch := time.NewTicker(watchInterval)
	defer watch.Stop()
	next := time.NewTimer(intervalWithJitter(interval))
	defer next.Stop()
	for {
		select {
		case <-next.C:
			syncOnce(ctx, cmd)
			wait := intervalWithJitter(interval)
			log.Debug().Dur("next_sync", wait).Msg("waiting for next sync")
			next.Reset(wait)
		case now := <-watch.C:
			watchTick(now)
		case <-ctx.Done():
			log.Info().Msg("shutting down")
			return nil
		}
	}
}

// upgradeUnsupportedLogged keeps an osctrl without the upgrade route to one debug line per process
var upgradeUnsupportedLogged bool

// upgradeUnknownReasonLogged keeps unknown server reasons to one debug line per process
var upgradeUnknownReasonLogged bool

// upgradeStep makes at most one osquery upgrade attempt, at the end of a sync
// where nothing else changed and osqueryd runs
func upgradeStep(ctx context.Context, changed bool) {
	if upgradeGOOS == WindowsOS || ctx.Err() != nil || changed {
		return
	}
	path := upgradeStatePath()
	if loadUpgradeState(path).Pending != nil {
		return
	}
	// Never feeds health: the watcher's debounce alone decides what is reported
	if !health.known {
		return
	}
	notRunning := upgradeResult{Result: upgradeSkipped, Reason: reasonOsquerydNotRunning, At: time.Now().UTC()}
	if running, _ := health.state(); !running {
		recordSkipped(notRunning)
		return
	}
	// The watcher's view can be minutes old: the engine would start an
	// osqueryd that died on its own and blame its crash on the target
	if running, err := osquerydRunning(); err != nil {
		log.Debug().Err(err).Msg("failed to check osqueryd, no osquery upgrade this sync")
		return
	} else if !running {
		recordSkipped(notRunning)
		return
	}
	res, err := requestUpgradeResolution(osqueryVersionReader())
	switch {
	case errors.Is(err, errUpgradeUnsupported):
		if !upgradeUnsupportedLogged {
			upgradeUnsupportedLogged = true
			log.Debug().Err(err).Msg("osquery upgrades not available")
		}
		return
	case err != nil:
		log.Warn().Err(err).Msg("failed to request osquery upgrade target")
		return
	}
	st := loadUpgradeState(path)
	ok, reason := shouldAttempt(res, st)
	switch {
	case ok:
	case reason == "rejected":
		log.Debug().Str("version", res.Target.Version).Msg("osquery upgrade target was rejected before, not retrying")
		// A skip recorded while osqueryd was down must not outlive it: the
		// rejection is still why this host is not upgraded. osctrl dedupes
		// the rollback by event id, so reporting it again counts nothing twice.
		if r := st.Rejected.Result; r != nil && (st.Last == nil || !sameUpgradeResult(*st.Last, *r)) {
			st.Last = r
			if err := saveUpgradeState(path, st); err != nil {
				log.Error().Err(err).Msg("failed to save upgrade state")
			}
		}
		return
	case reason == reasonNoTarget || reason == reasonAheadOfTarget || reason == reasonNoDigestForTarget ||
		reason == reasonNoDigestForInstalled || reason == reasonUnsupportedPlatform ||
		reason == reasonRolloutPending || reason == reasonRolloutPaused:
		log.Debug().Str("reason", reason).Msg("no osquery upgrade")
		// A gated host that rolled back this very request keeps reporting the
		// rollback, as in the "rejected" branch, until a new request supersedes it
		if rj := st.Rejected; (reason == reasonRolloutPending || reason == reasonRolloutPaused) &&
			rj != nil && rj.Result != nil && rj.RequestID == res.RequestID {
			if st.Last == nil || !sameUpgradeResult(*st.Last, *rj.Result) {
				st.Last = rj.Result
				if err := saveUpgradeState(path, st); err != nil {
					log.Error().Err(err).Msg("failed to save upgrade state")
				}
			}
			return
		}
		r := upgradeResult{Result: upgradeSkipped, Reason: reason, At: time.Now().UTC()}
		// Server values go back to osctrl only when well-formed
		if res.Target != nil && reVersion.MatchString(res.Target.Version) {
			r.Version = res.Target.Version
		}
		if reRequestID.MatchString(res.RequestID) {
			r.RequestID = res.RequestID
		}
		recordSkipped(r)
		return
	case reason == "invalid_resolution":
		log.Warn().Msg("ignoring invalid osquery upgrade answer")
		return
	default:
		// A reason from a newer osctrl
		if !upgradeUnknownReasonLogged {
			upgradeUnknownReasonLogged = true
			log.Debug().Str("reason", reason).Msg("ignoring osquery upgrade answer")
		}
		return
	}
	r, err := upgradeOsquery(ctx, res)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		log.Error().Err(err).Msg("osquery upgrade failed")
	}
	if r.Result == "" {
		return
	}
	// The engine's skip memory does not save Last, and its fresh skips
	// overwrite it: a skip must not hide a rollback osctrl has not seen
	after := loadUpgradeState(path)
	if r.Result == upgradeSkipped && rollbackUnreported(st) {
		r = *st.Last
	}
	if after.Last == nil || !sameUpgradeResult(*after.Last, r) {
		after.Last = &r
		if err := saveUpgradeState(path, after); err != nil {
			log.Error().Err(err).Msg("failed to save upgrade state")
		}
	}
}

// rollbackUnreported is true while Last is a rejection osctrl has not accepted
func rollbackUnreported(st upgradeState) bool {
	return st.Last != nil && st.Last.Result == upgradeRejected && st.Last.EventID != st.ReportedEventID
}

func sameUpgradeResult(a, b upgradeResult) bool {
	return a.Result == b.Result && a.Version == b.Version && a.Reason == b.Reason &&
		a.RequestID == b.RequestID && a.EventID == b.EventID
}

// recordSkipped saves a skip as Last unless that hides an unreported rollback;
// a repeat of the same skip keeps the file and its first time
func recordSkipped(r upgradeResult) {
	path := upgradeStatePath()
	st := loadUpgradeState(path)
	if rollbackUnreported(st) || (st.Last != nil && sameUpgradeResult(*st.Last, r)) {
		return
	}
	st.Last = &r
	if err := saveUpgradeState(path, st); err != nil {
		log.Error().Err(err).Msg("failed to save upgrade state")
	}
}

// markUpgradeReported remembers that osctrl accepted a report carrying a rollback
func markUpgradeReported(u *upgradeReport) {
	if u == nil || u.Result != upgradeRejected || u.EventID == "" {
		return
	}
	path := upgradeStatePath()
	st := loadUpgradeState(path)
	if st.Last == nil || st.Last.EventID != u.EventID || st.ReportedEventID == u.EventID {
		return
	}
	// A 200 means osctrl stored it: the engine only produces contract-valid values and osctrl dedupes by event id
	st.ReportedEventID = u.EventID
	if err := saveUpgradeState(path, st); err != nil {
		log.Error().Err(err).Msg("failed to save upgrade state")
	}
}
