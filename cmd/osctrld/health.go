package main

import (
	"errors"
	"time"

	"github.com/rs/zerolog/log"
)

var (
	// watchInterval is how often the service polls osqueryd between syncs
	watchInterval = 60 * time.Second
	// heartbeatDown is the report cadence while osqueryd is down (jittered)
	heartbeatDown = 5 * time.Minute
	// stableUp is how long osqueryd must be back up before heartbeats stop
	stableUp = 10 * time.Minute
	// syncIntervalUnit scales appConfig.Interval, a seam so tests run fast
	syncIntervalUnit = time.Minute
)

// downMisses is how many consecutive polls must miss osqueryd to call it down
const downMisses = 2

// healthWatcher debounces osqueryd polls into an up/down state: a respawn loop
// that shows osqueryd for a moment never flips it. Only the service goroutine uses it.
type healthWatcher struct {
	known     bool
	running   bool
	hits      int
	misses    int
	firstMiss time.Time
	downSince time.Time
	// upSince is set when osqueryd comes back, zero when up from the start
	upSince  time.Time
	nextBeat time.Time
	// notBefore holds every report back after a 429 with Retry-After
	notBefore time.Time
}

// observe records one poll and reports whether the state flipped. At start the
// state is unknown: a first hit is up without counting as a change, a first
// miss stays unknown and a second consecutive miss is a change to down.
func (w *healthWatcher) observe(running bool, now time.Time) (changed bool) {
	if running {
		w.hits, w.misses = w.hits+1, 0
	} else {
		if w.misses == 0 {
			w.firstMiss = now
		}
		w.hits, w.misses = 0, w.misses+1
	}
	switch {
	case !w.known && running:
		w.known, w.running = true, true
	case (w.running || !w.known) && w.misses >= downMisses:
		w.known, w.running, w.downSince = true, false, w.firstMiss
		return true
	case w.known && !w.running && w.hits >= runningChecks:
		w.running, w.downSince, w.upSince = true, time.Time{}, now
		return true
	}
	return false
}

// settle takes a completed verification as the state: it already saw osqueryd
// on runningChecks consecutive polls, or ran out of time
func (w *healthWatcher) settle(running bool, now time.Time) {
	if running {
		if w.known && !w.running {
			w.upSince = now
		}
		w.hits, w.misses, w.downSince = runningChecks, 0, time.Time{}
	} else {
		if w.running || !w.known {
			w.downSince = now
		}
		w.hits, w.misses = 0, downMisses
	}
	w.known, w.running = true, running
}

// state is the debounced state; downSince is zero while running
func (w *healthWatcher) state() (running bool, downSince time.Time) {
	return w.running, w.downSince
}

// heartbeatDue is true while osqueryd is down, or back up for less than
// stableUp, and heartbeatDown has passed since the last report
func (w *healthWatcher) heartbeatDue(now time.Time) bool {
	if !w.known {
		return false
	}
	if w.running && (w.upSince.IsZero() || now.Sub(w.upSince) >= stableUp) {
		return false
	}
	return !now.Before(w.nextBeat)
}

// markReported schedules the next heartbeat
func (w *healthWatcher) markReported(now time.Time) {
	w.nextBeat = now.Add(intervalWithJitter(heartbeatDown))
}

var (
	// health is the service's view of osqueryd, shared by the loop and syncOnce
	health = &healthWatcher{}
	// verified is the last completed waitForOsqueryd of this sync, nil when none ran
	verified *bool
	// statusUnsupported pauses watcher reports until the next sync tests again
	statusUnsupported bool
	unsupportedLogged bool
	lastStatusWarn    time.Time
)

// observeOsqueryd polls osqueryd once into health; a failed poll is no evidence
func observeOsqueryd(now time.Time) (changed bool) {
	running, err := osquerydRunning()
	if err != nil {
		log.Debug().Err(err).Msg("failed to check osqueryd")
		return false
	}
	return health.observe(running, now)
}

// observeSyncEnd takes this sync's last verification as the state, or polls
// when none ran
func observeSyncEnd(now time.Time) {
	if verified != nil {
		health.settle(*verified, now)
		verified = nil
		return
	}
	observeOsqueryd(now)
}

// watchTick runs between syncs: it never restarts osqueryd, it only reports
func watchTick(now time.Time) {
	changed := observeOsqueryd(now)
	if statusUnsupported || (!changed && !health.heartbeatDue(now)) {
		return
	}
	reportStatus(now)
}

// reportStatus sends the current state; failures are logged, never returned
func reportStatus(now time.Time) {
	if !health.known {
		// Not "down": nothing is known yet, the next tick or sync reports
		return
	}
	if now.Before(health.notBefore) {
		log.Debug().Time("not_before", health.notBefore).Msg("status reports held back by retry-after")
		return
	}
	uuid := cachedHostUUID()
	if uuid == "" {
		log.Debug().Msg("no host uuid yet, skipping status report")
		return
	}
	running, downSince := health.state()
	err := sendStatusReport(buildStatusReport(uuid, running, downSince))
	health.markReported(now)
	statusUnsupported = errors.Is(err, errStatusUnsupported)
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.retryAfter > 0 {
		health.notBefore = now.Add(statusErr.retryAfter)
	}
	switch {
	case statusUnsupported:
		if !unsupportedLogged {
			unsupportedLogged = true
			log.Debug().Err(err).Msg("status reports paused until the next sync")
		}
	case err != nil:
		if now.Sub(lastStatusWarn) >= syncInterval() {
			lastStatusWarn = now
			log.Warn().Err(err).Msg("failed to send status report")
		}
	}
}

func syncInterval() time.Duration {
	return time.Duration(appConfig.Interval) * syncIntervalUnit
}
