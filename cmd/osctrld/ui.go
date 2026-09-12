package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"
)

// ui.go — terminal polish for the interactive one-shot commands: a braille
// spinner while osctrld waits on the osctrl server. Ported from osctrl's
// cmd/cli/shell_ui.go with two differences: frames go to stderr so piped
// enroll/remove script output stays clean, and the spinner is disabled
// whenever log output would interleave with it.

// ANSI color codes, only ever written when stderr is a terminal
const (
	cReset = "\x1b[0m"
	cCyan  = "\x1b[36m"
)

// spinnerOn gates the animated spinner, resolved once by initSpinner
var spinnerOn bool

// spinnerOut is where frames are written, stderr so that piped stdout stays clean
var spinnerOut io.Writer = os.Stderr

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerAllowed reports whether an animated spinner should render for this
// configuration and command. Frames are only useful on a real terminal, and
// only when nothing else is writing to stderr: verbose logging and the JSON
// log format both fill the stream, and the service daemon runs unattended.
func spinnerAllowed(cfg Configuration, command string, tty bool) bool {
	if !tty || cfg.Verbose || cfg.LogFormat == "json" {
		return false
	}
	return command != "service"
}

// initSpinner resolves the spinner gate, once configuration has been loaded
func initSpinner(cfg Configuration, command string) {
	spinnerOn = spinnerAllowed(cfg, command, isatty.IsTerminal(os.Stderr.Fd()))
}

// animate renders a spinner and label until done is closed, then clears the
// line and signals through stopped. It owns the line clear so there is no
// write race with the caller.
func animate(label string, done <-chan struct{}, stopped chan<- struct{}) {
	i := 0
	pad := strings.Repeat(" ", 4)
	t := time.NewTicker(80 * time.Millisecond)
	defer t.Stop()
	for {
		fmt.Fprintf(spinnerOut, "\r%s%s%s %s%s", cCyan, spinnerFrames[i], cReset, label, pad)
		i = (i + 1) % len(spinnerFrames)
		select {
		case <-t.C:
		case <-done:
			fmt.Fprint(spinnerOut, "\r\x1b[K")
			close(stopped)
			return
		}
	}
}

// spin runs fn while a spinner labeled label animates on stderr, and returns
// whatever fn returned. When spinners are disabled it just runs fn.
func spin[T any](label string, fn func() (T, error)) (T, error) {
	if !spinnerOn {
		return fn()
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go animate(label, done, stopped)
	v, err := fn()
	close(done)
	<-stopped
	return v, err
}
