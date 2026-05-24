package main

import (
	"context"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func intervalWithJitter(base time.Duration) time.Duration {
	jitterRange := float64(base) * 0.2
	jitter := rand.Float64()*jitterRange - jitterRange/2
	return base + time.Duration(jitter)
}

func syncOnce(c *cli.Context) {
	originalForce := appConfig.Force
	appConfig.Force = true
	defer func() { appConfig.Force = originalForce }()

	var flagsChanged, certChanged, extensionsChanged bool

	log.Info().Msg("syncing flags")
	if changed, err := getFlags(c); err != nil {
		log.Error().Err(err).Msg("failed to sync flags")
	} else {
		flagsChanged = changed
	}

	log.Info().Msg("syncing cert")
	if changed, err := getCert(c); err != nil {
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
			log.Error().Err(err).Msg("failed to restart osquery")
		}
	}
}

func serviceNode(c *cli.Context) error {
	interval := time.Duration(appConfig.Interval) * time.Minute
	log.Info().Int("interval_minutes", appConfig.Interval).Msg("starting service")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	syncOnce(c)

	for {
		wait := intervalWithJitter(interval)
		log.Debug().Dur("next_sync", wait).Msg("waiting for next sync")

		select {
		case <-time.After(wait):
			syncOnce(c)
		case <-ctx.Done():
			log.Info().Msg("shutting down")
			return nil
		}
	}
}
