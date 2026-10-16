package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

func retrieveExtensionManifest(osctrlSecret, url string, insecure bool) ([]ExtensionEntry, error) {
	reqData := ExtensionsRequest{OsctrlSecret: osctrlSecret}
	body, err := genericRetrieve(url, insecure, reqData)
	// osctrl does not serve osctrld-extensions yet. Treat its 404 as an empty
	// manifest so the daemon does not log a failure every cycle; a wrong URL or
	// environment still fails loudly earlier in the cycle, on flags and cert.
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && statusErr.code == http.StatusNotFound {
		log.Debug().Msg("osctrl server does not serve extensions, skipping")
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error retrieving extension manifest - %v", err)
	}
	var entries []ExtensionEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("error parsing extension manifest - %v", err)
	}
	return entries, nil
}

func downloadExtension(url, destPath string, insecure bool) (bool, error) {
	code, body, err := SendRequest(http.MethodGet, url, nil, map[string]string{}, insecure)
	if err != nil {
		return false, fmt.Errorf("error downloading extension - %v", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("HTTP %d downloading extension", code)
	}
	changed, err := writeContentExists(destPath, string(body), filepath.Base(destPath), true, 0755)
	if err != nil {
		return false, err
	}
	return changed, nil
}

func syncExtensions() (bool, error) {
	log.Info().Msg("syncing extensions")
	manifest, err := retrieveExtensionManifest(appConfig.OsctrlSecret, osctrlURLs.Extensions, appConfig.Insecure)
	if err != nil {
		return false, err
	}
	if len(manifest) == 0 {
		log.Debug().Msg("no extensions in manifest")
		return false, nil
	}
	if err := os.MkdirAll(appConfig.ExtensionsDir, 0755); err != nil {
		return false, fmt.Errorf("error creating extensions directory - %v", err)
	}
	anyChanged := false
	for _, ext := range manifest {
		// The name comes from the network and the file is written as root, so
		// only a plain file name, never a path, may come through
		if ext.Name == "" || ext.Name == "." || ext.Name == ".." || ext.Name != filepath.Base(ext.Name) || strings.ContainsAny(ext.Name, `/\`) {
			log.Error().Str("name", ext.Name).Msg("refusing extension whose name is not a plain file name")
			continue
		}
		destPath := filepath.Join(appConfig.ExtensionsDir, ext.Name)
		log.Debug().Str("name", ext.Name).Str("url", ext.URL).Msg("downloading extension")
		changed, err := downloadExtension(ext.URL, destPath, appConfig.Insecure)
		if err != nil {
			log.Error().Err(err).Str("name", ext.Name).Msg("failed to download extension")
			continue
		}
		if changed {
			log.Info().Str("name", ext.Name).Str("path", destPath).Msg("extension updated")
			anyChanged = true
		}
	}
	return anyChanged, nil
}
