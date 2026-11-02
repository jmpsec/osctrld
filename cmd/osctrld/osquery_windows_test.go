//go:build windows

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

// Only a service that is not running counts as stopped; access denied or a
// service-manager failure must fail the stop
func TestAlreadyStopped(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"no error", nil, false},
		{"not active", windows.ERROR_SERVICE_NOT_ACTIVE, true},
		{"wrapped not active", fmt.Errorf("stop - %w", windows.ERROR_SERVICE_NOT_ACTIVE), true},
		{"access denied", windows.ERROR_ACCESS_DENIED, false},
		{"cannot accept control", windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL, false},
		{"other", errors.New("scm unavailable"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, alreadyStopped(tt.err))
		})
	}
}
