package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

func retrieveExtensionManifest(secret, url string, insecure bool) ([]ExtensionEntry, error) {
	reqData := ExtensionsRequest{Secret: secret}
	body, err := genericRetrieve(url, insecure, reqData)
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
	changed, err := writeContentExists(destPath, string(body), filepath.Base(destPath), true)
	if err != nil {
		return false, err
	}
	if changed {
		if err := os.Chmod(destPath, 0755); err != nil {
			return false, fmt.Errorf("error setting extension permissions - %v", err)
		}
	}
	return changed, nil
}

func syncExtensions() (bool, error) {
	log.Info().Msg("syncing extensions")
	manifest, err := retrieveExtensionManifest(appConfig.Secret, osctrlURLs.Extensions, appConfig.Insecure)
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
