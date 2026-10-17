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

	var flagsChanged, certChanged, extensionsChanged bool

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

	if changed, err := syncExtensions(); err != nil {
		log.Error().Err(err).Msg("failed to sync extensions")
	} else {
		extensionsChanged = changed
	}

	if flagsChanged || certChanged || extensionsChanged {
		log.Info().
			Bool("flags_changed", flagsChanged).
			Bool("cert_changed", certChanged).
			Bool("extensions_changed", extensionsChanged).
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
}

func serviceNode(ctx context.Context, cmd *cli.Command) error {
	interval := time.Duration(appConfig.Interval) * time.Minute
	log.Info().Int("interval_minutes", appConfig.Interval).Msg("starting service")

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	syncOnce(ctx, cmd)

	for {
		wait := intervalWithJitter(interval)
		log.Debug().Dur("next_sync", wait).Msg("waiting for next sync")

		select {
		case <-time.After(wait):
			syncOnce(ctx, cmd)
		case <-ctx.Done():
			log.Info().Msg("shutting down")
			return nil
		}
	}
}
