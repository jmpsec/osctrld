package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

// osqueryInstallDecision reports whether the osquery package must be installed.
// A node running NEWER than required is deliberately left alone: silently
// downgrading a fleet is worse than running ahead of the required version, which
// is the same call the osctrl quick-add script makes. An unparseable installed
// version is treated like a missing one.
func osqueryInstallDecision(installed, required string) bool {
	if installed == "" {
		return true
	}
	switch osqueryVersionCompare(installed, required) {
	case 2: // required is higher than installed
		return true
	case -1: // one side could not be parsed, treat the node as unknown
		return true
	default: // equal, or installed is higher
		return false
	}
}

// ensureOsquery installs the osquery package when the node is missing it or
// running an older version. The package URL can be overridden for mirrors.
func ensureOsquery(v VerifyResponse) error {
	installed := osqueryVersionReader()
	log.Debug().Str("installed", installed).Str("required", v.OsqueryVersion).Msg("comparing osquery version")
	if !osqueryInstallDecision(installed, v.OsqueryVersion) {
		log.Info().Str("version", installed).Msg("osquery is already at a suitable version")
		return nil
	}
	format, err := packageFormatFor(runtime.GOOS, "")
	if err != nil {
		return err
	}
	url := appConfig.OsqueryPackage
	if url == defEmptyValue {
		if url, err = osqueryPackageURL(format, v.OsqueryVersion, runtime.GOARCH); err != nil {
			return err
		}
	}
	digest := resolveDigest(v.OsquerySHA256, appConfig.OsquerySHA256)
	path, err := spin("downloading osquery "+v.OsqueryVersion, func() (string, error) {
		return downloadPackage(url, digest, appConfig.AllowUnverified, appConfig.Insecure)
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := os.Remove(path); err != nil {
			log.Debug().Err(err).Str("path", path).Msg("could not remove the downloaded package")
		}
	}()
	log.Info().Str("format", string(format)).Str("version", v.OsqueryVersion).Msg("installing osquery")
	return installPackage(format, path)
}

// installNode performs natively what the osctrl quick-add script does: ensure
// osquery is present at the required version, write the secret, flags and
// certificate, and bring the service up.
func installNode(ctx context.Context, cmd *cli.Command) error {
	if err := requirePrivileges(); err != nil {
		return err
	}
	verification, err := spin("verifying node with osctrl", func() (VerifyResponse, error) {
		return retrieveVerify(appConfig.OsctrlSecret, appConfig.OsquerySecretFile, appConfig.OsqueryCertFile, osctrlURLs.Verify, appConfig.Insecure)
	})
	if err != nil {
		return fmt.Errorf("error retrieving verification - %v", err)
	}
	if err := ensureOsquery(verification); err != nil {
		return fmt.Errorf("error installing osquery - %v", err)
	}
	if err := stopOsquery(); err != nil {
		return fmt.Errorf("error stopping osquery - %v", err)
	}
	// The secret is a credential: 0600, not the 0700 the other files get
	if err := os.MkdirAll(filepath.Dir(appConfig.OsquerySecretFile), 0755); err != nil {
		return fmt.Errorf("error creating the secret directory - %v", err)
	}
	if _, err := writeContentExists(appConfig.OsquerySecretFile, appConfig.OsctrlSecret, "secret", true, 0600); err != nil {
		return err
	}
	log.Info().Str("path", appConfig.OsquerySecretFile).Msg("secret ready")

	if err := os.MkdirAll(filepath.Dir(appConfig.OsqueryFlagFile), 0755); err != nil {
		return fmt.Errorf("error creating the flags directory - %v", err)
	}
	if _, err := writeContentExists(appConfig.OsqueryFlagFile, verification.Flags, "flags", true, 0700); err != nil {
		return err
	}
	log.Info().Str("path", appConfig.OsqueryFlagFile).Msg("flags ready")

	if err := os.MkdirAll(filepath.Dir(appConfig.OsqueryCertFile), 0755); err != nil {
		return fmt.Errorf("error creating the certificate directory - %v", err)
	}
	if _, err := writeContentExists(appConfig.OsqueryCertFile, verification.Certificate, "cert", true, 0700); err != nil {
		return err
	}
	log.Info().Str("path", appConfig.OsqueryCertFile).Msg("certificate ready")

	if err := startOsquery(); err != nil {
		return fmt.Errorf("error starting osquery - %v", err)
	}
	if err := enableOsquery(); err != nil {
		return fmt.Errorf("error enabling osquery - %v", err)
	}
	log.Info().Str("environment", appConfig.Environment).Msg("node enrolled")
	return nil
}

// removeIfExists deletes a file, treating an already-absent file as success so
// that uninstall can be re-run safely.
func removeIfExists(path, name string) error {
	if !checkFileExist(path) {
		log.Debug().Str("path", path).Msgf("%s not present, nothing to remove", name)
		return nil
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("error removing %s from %s - %v", name, path, err)
	}
	log.Info().Str("path", path).Msgf("%s removed", name)
	return nil
}

// uninstallNode performs natively what the osctrl quick-remove script does. It
// deliberately does NOT remove the osquery package, matching that script.
func uninstallNode(ctx context.Context, cmd *cli.Command) error {
	if err := requirePrivileges(); err != nil {
		return err
	}
	if err := stopOsquery(); err != nil {
		return fmt.Errorf("error stopping osquery - %v", err)
	}
	for _, f := range []struct{ path, name string }{
		{appConfig.OsquerySecretFile, "secret"},
		{appConfig.OsqueryFlagFile, "flags"},
		{appConfig.OsqueryCertFile, "cert"},
	} {
		if err := removeIfExists(f.path, f.name); err != nil {
			return err
		}
	}
	log.Info().Str("environment", appConfig.Environment).Msg("node removed, osquery itself was left installed")
	return nil
}
