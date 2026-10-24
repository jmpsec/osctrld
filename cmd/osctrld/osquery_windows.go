//go:build windows

package main

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// openOsqueryService connects to the service manager and opens the osquery service.
// The caller must close both returned handles.
func openOsqueryService() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to the service manager - %v", err)
	}
	s, err := m.OpenService(osqueryService)
	if err != nil {
		_ = m.Disconnect()
		return nil, nil, fmt.Errorf("error opening the %s service - %v", osqueryService, err)
	}
	return m, s, nil
}

// windowsServiceStop stops osqueryd and waits for it to reach Stopped. A service
// that is already stopped is not an error: stopped is the desired state.
func windowsServiceStop() error {
	m, s, err := openOsqueryService()
	if err != nil {
		log.Debug().Err(err).Msg("osquery service not present, nothing to stop")
		return nil
	}
	defer func() { _ = m.Disconnect() }()
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		log.Debug().Err(err).Msg("osquery service was not running")
		return nil
	}
	deadline := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for %s to stop", osqueryService)
		}
		time.Sleep(500 * time.Millisecond)
		if status, err = s.Query(); err != nil {
			return fmt.Errorf("error querying %s - %v", osqueryService, err)
		}
	}
	return nil
}

// windowsServiceStart starts osqueryd
func windowsServiceStart() error {
	m, s, err := openOsqueryService()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("error starting %s - %v", osqueryService, err)
	}
	return nil
}

// windowsServiceRestart stops osqueryd, waiting for it to stop, then starts it
func windowsServiceRestart() error {
	if err := windowsServiceStop(); err != nil {
		return err
	}
	return windowsServiceStart()
}

// windowsServiceEnable sets osqueryd to start automatically at boot
func windowsServiceEnable() error {
	m, s, err := openOsqueryService()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("error reading %s configuration - %v", osqueryService, err)
	}
	cfg.StartType = mgr.StartAutomatic
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("error setting %s to start automatically - %v", osqueryService, err)
	}
	return nil
}

// ensureServiceSettings sets osqueryd to start automatically with
// --flagfile=<flagFile>, which an MSI install may have reset
func ensureServiceSettings(flagFile string) error {
	m, s, err := openOsqueryService()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("error reading %s configuration - %v", osqueryService, err)
	}
	bin, changed, err := fixServiceConfig(cfg.StartType == mgr.StartAutomatic, cfg.BinaryPathName, flagFile)
	if err != nil {
		log.Warn().Err(err).Msg("not rewriting the osquery service command line")
	}
	if !changed {
		log.Debug().Str("service", osqueryService).Msg("osquery service settings unchanged")
		return nil
	}
	cfg.StartType, cfg.BinaryPathName = mgr.StartAutomatic, bin
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("error updating %s configuration - %v", osqueryService, err)
	}
	log.Info().Str("service", osqueryService).Str("command", bin).Msg("osquery service settings reapplied")
	return nil
}
