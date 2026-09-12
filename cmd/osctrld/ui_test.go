package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpinnerAllowed(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Configuration
		command  string
		tty      bool
		expected bool
	}{
		{"one-shot command on a terminal", Configuration{LogFormat: "text"}, "flags", true, true},
		{"enroll on a terminal", Configuration{LogFormat: "text"}, "enroll", true, true},
		{"piped output is not a terminal", Configuration{LogFormat: "text"}, "flags", false, false},
		{"verbose already fills stderr", Configuration{LogFormat: "text", Verbose: true}, "flags", true, false},
		{"json logs already fill stderr", Configuration{LogFormat: "json"}, "flags", true, false},
		{"service runs unattended", Configuration{LogFormat: "text"}, "service", true, false},
		{"service is off even without a terminal", Configuration{LogFormat: "text"}, "service", false, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, spinnerAllowed(tt.cfg, tt.command, tt.tty))
		})
	}
}

// withSpinnerOut swaps the spinner destination and gate for one test
func withSpinnerOut(t *testing.T, on bool) *bytes.Buffer {
	t.Helper()
	prevOut, prevOn := spinnerOut, spinnerOn
	buf := &bytes.Buffer{}
	spinnerOut, spinnerOn = buf, on
	t.Cleanup(func() { spinnerOut, spinnerOn = prevOut, prevOn })
	return buf
}

func TestSpinReturnsValueAndError(t *testing.T) {
	for _, on := range []bool{false, true} {
		t.Run("spinner enabled "+map[bool]string{true: "yes", false: "no"}[on], func(t *testing.T) {
			withSpinnerOut(t, on)

			v, err := spin("working", func() (string, error) { return "payload", nil })
			assert.NoError(t, err)
			assert.Equal(t, "payload", v)

			wantErr := errors.New("boom")
			v, err = spin("working", func() (string, error) { return "", wantErr })
			assert.Equal(t, wantErr, err)
			assert.Empty(t, v)
		})
	}
}

func TestSpinWritesNothingWhenDisabled(t *testing.T) {
	buf := withSpinnerOut(t, false)
	_, err := spin("working", func() (int, error) { return 42, nil })
	assert.NoError(t, err)
	assert.Empty(t, buf.String())
}

// The goroutine owns the line clear, so by the time spin returns the label must
// already be erased, otherwise frames would bleed into whatever logs next.
func TestSpinClearsTheLine(t *testing.T) {
	buf := withSpinnerOut(t, true)
	_, err := spin("retrieving flags from osctrl", func() (int, error) { return 0, nil })
	assert.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "retrieving flags from osctrl")
	assert.Contains(t, out, spinnerFrames[0])
	assert.True(t, strings.HasSuffix(out, "\r\x1b[K"), "spinner must clear its line before returning")
}

func TestVersionString(t *testing.T) {
	prev := [3]string{buildVersion, buildCommit, buildDate}
	t.Cleanup(func() { buildVersion, buildCommit, buildDate = prev[0], prev[1], prev[2] })

	buildVersion, buildCommit, buildDate = "1.2.3", "deadbeef", "2026-09-12T00:00:00Z"
	assert.Equal(t, "osctrld version=1.2.3 commit=deadbeef date=2026-09-12T00:00:00Z", versionString())
}

func TestVersionStringDefaults(t *testing.T) {
	assert.Equal(t, OsctrldVersion, buildVersion)
	assert.Equal(t, "unknown", buildCommit)
	assert.Equal(t, "unknown", buildDate)
}
