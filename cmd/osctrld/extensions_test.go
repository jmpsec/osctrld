package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRetrieveExtensionManifest_Success(t *testing.T) {
	manifest := []ExtensionEntry{
		{Name: "test_ext.ext", URL: "http://example.com/test_ext.ext"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer server.Close()

	entries, err := retrieveExtensionManifest("test-secret", server.URL, false)
	assert.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "test_ext.ext", entries[0].Name)
}

func TestRetrieveExtensionManifest_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]ExtensionEntry{})
	}))
	defer server.Close()

	entries, err := retrieveExtensionManifest("test-secret", server.URL, false)
	assert.NoError(t, err)
	assert.Empty(t, entries)
}

func TestRetrieveExtensionManifest_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	_, err := retrieveExtensionManifest("test-secret", server.URL, false)
	assert.Error(t, err)
}

func TestDownloadExtension_Success(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho extension")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binaryContent)
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "test_ext.ext")

	changed, err := downloadExtension(server.URL, path, false)
	assert.NoError(t, err)
	assert.True(t, changed)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())
}

func TestDownloadExtension_NoChange(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho extension")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binaryContent)
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "test_ext.ext")
	require.NoError(t, os.WriteFile(path, binaryContent, 0755))

	changed, err := downloadExtension(server.URL, path, false)
	assert.NoError(t, err)
	assert.False(t, changed, "same content should not report changed")
}

func TestSyncExtensions_Success(t *testing.T) {
	binaryContent := []byte("#!/bin/sh\necho extension")

	mux := http.NewServeMux()
	mux.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
		manifest := []ExtensionEntry{
			{Name: "test_ext.ext", URL: "http://" + r.Host + "/binary"},
		}
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binaryContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	dir := t.TempDir()
	appConfig.Secret = "test-secret"
	appConfig.ExtensionsDir = dir
	appConfig.Insecure = false
	osctrlURLs.Extensions = server.URL + "/manifest"

	changed, err := syncExtensions()
	assert.NoError(t, err)
	assert.True(t, changed)

	content, err := os.ReadFile(filepath.Join(dir, "test_ext.ext"))
	require.NoError(t, err)
	assert.Equal(t, binaryContent, content)
}

func TestSyncExtensions_EmptyManifest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]ExtensionEntry{})
	}))
	defer server.Close()

	appConfig.Secret = "test-secret"
	appConfig.Insecure = false
	osctrlURLs.Extensions = server.URL

	changed, err := syncExtensions()
	assert.NoError(t, err)
	assert.False(t, changed)
}
