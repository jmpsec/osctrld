package main

import (
	"context"
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

	// Every sync ends with a report of the current state, which also re-tests an
	// osctrl that answered "unsupported"
	if ctx.Err() != nil {
		return
	}
	now := time.Now()
	observeOsqueryd(now)
	reportStatus(now)
}

func serviceNode(ctx context.Context, cmd *cli.Command) error {
	interval := syncInterval()
	log.Info().Int("interval_minutes", appConfig.Interval).Msg("starting service")

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

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
