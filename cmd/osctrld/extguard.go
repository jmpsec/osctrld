package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/process"
)

const (
	// disabledByFlagsError is the informational status when osquery will not load extensions
	disabledByFlagsError = "extensions are disabled by flags"
	// maxStatusError caps each status error, in bytes
	maxStatusError = 256
	// maxStatusPerRequest caps the statuses sent at once, newest kept; at the
	// error cap they stay under osctrl-tls's 16 KiB body limit
	maxStatusPerRequest = 24
	// applyKept reports a removal that failed: the extension is still installed
	applyKept = "kept"
	// applyRemoved reports a removal that worked
	applyRemoved = "removed"
)

var (
	// extensionsGOOS picks file names, autoload defaults and path matching; a
	// seam so the Windows flow is tested anywhere
	extensionsGOOS = runtime.GOOS
	// autoloadDirSafe reports whether only an administrator can write in the
	// autoload file's directory. A seam for tests.
	autoloadDirSafe = adminOwnedDir
	// extensionRunning is a seam over the per-extension process check
	extensionRunning = isExtensionRunning
	// processExes is a seam over the executable paths of running processes
	processExes = listProcessExes
	// staleNameRe matches the temp names osctrld leaves in the extensions
	// directory: interrupted downloads (installExtension) and retired files
	staleNameRe = regexp.MustCompile(`^\.[A-Za-z0-9_-]{1,64}\.(ext|exe)(\.prev)?\.tmp-`)
)

// extState is what osctrld remembers between syncs about the extensions it manages
type extState struct {
	// Installed is name → sha256 of every extension osctrld placed
	Installed map[string]string `json:"installed"`
	// Lines are the autoload lines osctrld owns
	Lines []string `json:"lines"`
	// Rejected is name → sha256 of content that failed the check, skipped while served
	Rejected map[string]string `json:"rejected"`
	// Pending is name → sha256 changed by the last step and not verified yet;
	// an empty sha256 is a removal
	Pending map[string]string `json:"pending,omitempty"`
	// Status is reported to osctrl on the next request
	Status []ExtensionStatus `json:"status,omitempty"`
	// Previous is name → sha256 of the version kept as <file>.prev until verified
	Previous map[string]string `json:"previous,omitempty"`
	// RejectedRemovals is name → sha256 of an extension whose removal kept
	// osqueryd down; it stays installed until osctrl serves that name again
	RejectedRemovals map[string]string `json:"rejected_removals,omitempty"`
	// Restarted is set once osquery was restarted for the pending changes, so
	// a resumed check knows whether osquery loaded them
	Restarted bool `json:"restarted,omitempty"`
	// Autoload is the autoload file osctrld last wrote its lines to
	Autoload string `json:"autoload,omitempty"`
	// RefusedAutoload is the last autoload path refused, reported once
	RefusedAutoload string `json:"refused_autoload,omitempty"`
}

func extStatePath() string {
	return appConfig.OsqueryFlagFile + ".osctrld-extensions-state.json"
}

// loadExtState reads the state, falling back to an empty one on any problem
func loadExtState(path string) extState {
	var s extState
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &s)
	}
	if err != nil {
		log.Debug().Err(err).Str("path", path).Msg("no usable extensions state")
		s = extState{}
	}
	if s.Installed == nil {
		s.Installed = map[string]string{}
	}
	if s.Rejected == nil {
		s.Rejected = map[string]string{}
	}
	if s.RejectedRemovals == nil {
		s.RejectedRemovals = map[string]string{}
	}
	return s
}

func saveExtState(path string, s extState) error {
	return writeStateFile(path, s)
}

// flagValue returns the last value of --name in the flagfile at path, as
// gflags reads it: "--name=value", or a bare "--name" with an empty value
func flagValue(path, name string) (value string, found bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-") {
			continue
		}
		if k, v, _ := strings.Cut(strings.TrimLeft(line, "-"), "="); k == name {
			value, found = v, true
		}
	}
	return value, found
}

// autoloadPath is the autoload file osquery reads: --extensions_autoload from
// the flagfile, else osquery's default for goos
func autoloadPath(flagfile string, goos string) string {
	if v, _ := flagValue(flagfile, "extensions_autoload"); v != "" {
		return filepath.Clean(v)
	}
	switch goos {
	case WindowsOS:
		return `C:\Program Files\osquery\extensions.load`
	case DarwinOS:
		return "/private/var/osquery/extensions.load"
	}
	return "/etc/osquery/extensions.load"
}

// disabledByFlags reports whether the flagfile turns extensions off
func disabledByFlags(flagfile string) bool {
	v, found := flagValue(flagfile, "disable_extensions")
	if !found {
		return false
	}
	switch strings.ToLower(v) {
	case "", "true", "1", "yes", "t", "y":
		return true
	}
	return false
}

// writeAutoload replaces osctrld's lines (prevOwned) in the autoload file with
// owned, sorted after the lines it does not own, which keep their order. The
// file is written atomically and handed to the administrator; see
// checkAutoloadPath for the paths refused.
func writeAutoload(path string, owned []string, prevOwned []string) error {
	_, err := updateAutoload(path, owned, prevOwned)
	return err
}

// protectedFiles are files an autoload path from the flags must never name
func protectedFiles() []string {
	return []string{
		appConfig.OsqueryFlagFile,
		appConfig.OsquerySecretFile,
		appConfig.OsqueryCertFile,
		flagsStatePath(),
		extStatePath(),
	}
}

// checkAutoloadPath refuses an autoload path osctrld must not write as root.
// The path comes from flags, which environment admins edit, so it must be a
// .load file directly in osquery's base directory (never e.g. /etc/sudoers),
// and not a symlink, one of the files osctrld and osquery depend on, inside
// the extensions directory, or in a directory others can write.
func checkAutoloadPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("autoload path %q is not absolute, refusing to write it", path)
	}
	clean := filepath.Clean(path)
	if appConfig.OsqueryPath == "" {
		return fmt.Errorf("osquery base directory is not configured, refusing to write autoload path %s", path)
	}
	base := filepath.Clean(appConfig.OsqueryPath)
	inBase := filepath.Dir(clean) == base && strings.HasSuffix(clean, ".load")
	if extensionsGOOS == WindowsOS {
		inBase = strings.EqualFold(filepath.Dir(clean), base) && strings.HasSuffix(strings.ToLower(clean), ".load")
	}
	if !inBase {
		return fmt.Errorf("autoload path %s is not a .load file directly in %s, refusing to write it", path, base)
	}
	info, err := os.Lstat(clean)
	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("autoload file %s is not a regular file, refusing to write it", path)
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error checking autoload file - %v", err)
	}
	for _, p := range protectedFiles() {
		if p == "" {
			continue
		}
		same := filepath.Clean(p) == clean
		if pi, perr := os.Stat(p); !same && err == nil && perr == nil {
			same = os.SameFile(info, pi)
		}
		if same {
			return fmt.Errorf("autoload path %s is %s, refusing to write it", path, p)
		}
	}
	if dir := filepath.Dir(clean); dir == filepath.Clean(appConfig.ExtensionsDir) {
		return fmt.Errorf("autoload path %s is inside the extensions directory, refusing to write it", path)
	} else if !autoloadDirSafe(dir) {
		return fmt.Errorf("autoload directory %s is not owned by root or is writable by others, refusing to write in it", dir)
	}
	return nil
}

// updateAutoload is writeAutoload, reporting whether it wrote. A file that
// already holds exactly the owned lines is left as it is.
func updateAutoload(path string, owned []string, prevOwned []string) (changed bool, err error) {
	if err := checkAutoloadPath(path); err != nil {
		return false, err
	}
	// The checks were made on the cleaned path, so every access uses it
	path = filepath.Clean(path)
	var current []byte
	mode := os.FileMode(0644)
	if info, err := os.Lstat(path); err == nil {
		// Keep an operator's mode, minus group/world write
		mode = info.Mode().Perm() &^ 0022
		if current, err = os.ReadFile(path); err != nil {
			return false, fmt.Errorf("error reading autoload file - %v", err)
		}
	}
	owned = slices.Sorted(slices.Values(owned))
	var lines, ours []string
	for _, l := range strings.Split(string(current), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case slices.Contains(owned, l) || slices.Contains(prevOwned, l):
			ours = append(ours, l)
		default:
			lines = append(lines, l)
		}
	}
	slices.Sort(ours)
	if slices.Equal(slices.Compact(ours), owned) {
		return false, nil
	}
	lines = append(lines, owned...)
	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return false, fmt.Errorf("error writing autoload file - %v", err)
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if _, err = tmp.WriteString(content); err != nil {
		return false, fmt.Errorf("error writing autoload file - %v", err)
	}
	if err = tmp.Close(); err != nil {
		return false, fmt.Errorf("error writing autoload file - %v", err)
	}
	if err = setOwner(tmp.Name()); err != nil {
		return false, fmt.Errorf("error setting owner of autoload file - %v", err)
	}
	if err = os.Chmod(tmp.Name(), mode); err != nil {
		return false, fmt.Errorf("error setting mode on autoload file - %v", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return false, fmt.Errorf("error writing autoload file - %v", err)
	}
	return true, nil
}

func listProcessExes() ([]string, error) {
	ps, err := process.Processes()
	if err != nil {
		return nil, err
	}
	exes := make([]string, 0, len(ps))
	for _, p := range ps {
		if exe, err := p.Exe(); err == nil && exe != "" {
			exes = append(exes, exe)
		}
	}
	return exes, nil
}

// isExtensionRunning reports whether a process runs the executable at path
func isExtensionRunning(path string) (bool, error) {
	exes, err := processExes()
	if err != nil {
		return false, fmt.Errorf("error getting processes - %v", err)
	}
	want := []string{filepath.Clean(path)}
	// The kernel reports the resolved path, e.g. /private/var for /var on macOS
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		want = append(want, resolved)
	}
	for _, exe := range exes {
		exe = filepath.Clean(exe)
		for _, w := range want {
			if exe == w || (extensionsGOOS == WindowsOS && strings.EqualFold(exe, w)) {
				return true, nil
			}
		}
	}
	return false, nil
}

// cachedHostUUID is the host UUID the flags step looked up (or last knew) this sync
func cachedHostUUID() string {
	return loadFlagsState(flagsStatePath()).HostUUID
}

// moveAside renames a regular file in dir to <file>.prev. A rename works on
// Windows while the executable runs, where overwriting or deleting it fails.
func moveAside(dir, fileName string) (bool, error) {
	path := filepath.Join(dir, fileName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("refusing to move %s, it is not a regular file", path)
	}
	return true, os.Rename(path, path+".prev")
}

// retire moves a file osctrld no longer wants to a temp name sweepStale
// deletes, so a file Windows still holds open is deleted on a later sweep
func retire(dir, fileName string) {
	path := filepath.Join(dir, fileName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	to := filepath.Join(dir, fmt.Sprintf(".%s.tmp-retired-%d", fileName, time.Now().UnixNano()))
	if err := os.Rename(path, to); err != nil {
		log.Error().Err(err).Str("path", path).Msg("failed to remove extension file")
	}
}

// sweepStale deletes osctrld's own temp files left in dir: interrupted
// downloads and retired files. Anything else is left alone.
func sweepStale(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Debug().Err(err).Str("dir", dir).Msg("cannot list extensions directory")
		return
	}
	for _, e := range entries {
		if !staleNameRe.MatchString(e.Name()) {
			continue
		}
		if err := removeManagedFile(dir, e.Name()); err != nil {
			// Windows keeps a running executable locked; the next sweep retries
			log.Debug().Err(err).Str("file", e.Name()).Msg("cannot remove stale extension file yet")
		}
	}
}

// ownedLines are the autoload lines for every installed extension
func ownedLines(dir string, installed map[string]string) []string {
	lines := make([]string, 0, len(installed))
	for name := range installed {
		if f, err := extensionFileName(name, extensionsGOOS); err == nil {
			lines = append(lines, filepath.Join(dir, f))
		}
	}
	slices.Sort(lines)
	return lines
}

// upToDate reports whether path already holds sha256 in a file only an
// administrator can have written
func upToDate(path, sha string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	sum, err := fileSHA256(path)
	return err == nil && sum == sha && extensionFileSafe(path)
}

// removalDownMsg is the kept error of a removal undone because osqueryd did not
// stay up without the extension
func removalDownMsg() string {
	return fmt.Sprintf("osqueryd was not running %gs after the extension was removed", restartCheckTimeout.Seconds())
}

// latestStatus keeps the newest status per name, in order
func latestStatus(all []ExtensionStatus) []ExtensionStatus {
	seen := map[string]bool{}
	var out []ExtensionStatus
	for i := len(all) - 1; i >= 0; i-- {
		if !seen[all[i].Name] {
			seen[all[i].Name] = true
			out = append(out, all[i])
		}
	}
	slices.Reverse(out)
	return out
}

func newStatus(name, sha, result, msg string) ExtensionStatus {
	if len(msg) > maxStatusError {
		n := maxStatusError
		for n > 0 && !utf8.RuneStart(msg[n]) {
			n--
		}
		msg = msg[:n]
	}
	return ExtensionStatus{Name: name, SHA256: sha, Result: result, Error: msg, At: time.Now().UTC()}
}

// restorePrevious undoes the pending changes in dir: every changed file is
// retired and its .prev, if any, put back; Installed follows
func restorePrevious(st *extState, dir string) {
	for name := range st.Pending {
		f, err := extensionFileName(name, extensionsGOOS)
		if err != nil {
			continue
		}
		retire(dir, f)
		old, had := st.Previous[name]
		if !had {
			delete(st.Installed, name)
			continue
		}
		path := filepath.Join(dir, f)
		if err := os.Rename(path+".prev", path); err != nil {
			log.Error().Err(err).Str("name", name).Msg("failed to restore previous extension")
			delete(st.Installed, name)
			continue
		}
		st.Installed[name] = old
	}
}

// syncExtensionsStep reports the last statuses, retrieves the extensions
// assigned to this host and installs, updates and removes osctrld's own
// extensions and autoload lines to match. Replaced and removed files are kept
// as <file>.prev, and the changes marked pending, until
// verifyExtensionsAfterRestart checks them. The autoload file is reconciled
// every time; repairing it re-checks the installed set. It reports whether
// osquery needs a restart.
func syncExtensionsStep(ctx context.Context) (changed bool, err error) {
	statePath := extStatePath()
	st := loadExtState(statePath)
	if len(st.Pending) > 0 {
		return false, errors.New("the last extensions change is not verified yet")
	}
	st.Status = latestStatus(st.Status)
	req := ExtensionsRequest{
		OsctrlSecret: appConfig.OsctrlSecret,
		UUID:         cachedHostUUID(),
		Platform:     extensionsGOOS,
		Arch:         runtime.GOARCH,
		Status:       st.Status[max(0, len(st.Status)-maxStatusPerRequest):],
	}
	entries, err := retrieveExtensionManifest(req, osctrlURLs.Extensions, appConfig.Insecure)
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) && (statusErr.code == http.StatusBadRequest || statusErr.code == http.StatusRequestEntityTooLarge) && len(st.Status) > 0 {
		// osctrl refuses this request and would refuse it again: drop the status.
		// Others (e.g. 403 after a secret rotation) keep it, it may be a one-time kept.
		log.Warn().Int("code", statusErr.code).Msg("osctrl refused the extensions status, dropping it")
		st.Status = nil
		if saveErr := saveExtState(statePath, st); saveErr != nil {
			log.Error().Err(saveErr).Msg("failed to save extensions state")
		}
	}
	if err != nil {
		// Otherwise status stays for the next request
		return false, err
	}
	if len(st.Status) > 0 {
		st.Status = nil
		if err := saveExtState(statePath, st); err != nil {
			return false, err
		}
	}
	served := map[string]string{}
	for _, e := range entries {
		served[e.Name] = e.SHA256
	}
	dirty := false
	for name, sha := range st.Rejected {
		// Retried once osctrl serves different content, or assigns it again later
		if served[name] != sha {
			delete(st.Rejected, name)
			dirty = true
		}
	}
	for name, sha := range st.RejectedRemovals {
		// Retried once osctrl serves the name again, which ends this removal
		if served[name] != "" || st.Installed[name] != sha {
			delete(st.RejectedRemovals, name)
			dirty = true
			if served[name] == sha && st.Installed[name] == sha {
				// Served again as installed: nothing to install, so nothing
				// else would replace the kept status
				st.Status = append(st.Status, newStatus(name, sha, applyOK, ""))
			}
			continue
		}
		// Reported every sync while it stays, so osctrl keeps the evidence
		// even if its record of the first report is gone
		st.Status = append(st.Status, newStatus(name, sha, applyKept, removalDownMsg()))
		dirty = true
	}
	// Saves only what changed, so a host without extensions gets no state file
	saveIfDirty := func() error {
		if !dirty {
			return nil
		}
		return saveExtState(statePath, st)
	}
	if len(entries) == 0 && len(st.Installed) == 0 && len(st.Lines) == 0 {
		return false, saveIfDirty()
	}
	autoload := autoloadPath(appConfig.OsqueryFlagFile, extensionsGOOS)
	if err := checkAutoloadPath(autoload); err != nil {
		// Nothing is changed while osquery reads a file osctrld must not write.
		// Every served extension is affected; reported once per refused path.
		if st.RefusedAutoload != autoload {
			for _, e := range entries {
				st.Status = append(st.Status, newStatus(e.Name, e.SHA256, applyRejected, err.Error()))
			}
			st.RefusedAutoload = autoload
			dirty = true
		}
		if saveErr := saveIfDirty(); saveErr != nil {
			log.Error().Err(saveErr).Msg("failed to save extensions state")
		}
		return false, err
	}
	if st.RefusedAutoload != "" {
		st.RefusedAutoload = ""
		dirty = true
	}
	dir := filepath.Clean(appConfig.ExtensionsDir)
	if err := ensureExtensionsDir(dir); err != nil {
		return false, err
	}
	sweepStale(dir)

	pending, previous := map[string]string{}, map[string]string{}
	wanted := map[string]bool{}
	for name := range st.RejectedRemovals {
		wanted[name] = true
	}
	for _, e := range entries {
		if st.Rejected[e.Name] == e.SHA256 {
			// Keep the last good version, if any, while the rejected one is served
			_, wanted[e.Name] = st.Installed[e.Name]
			log.Warn().Str("name", e.Name).Str("sha256", e.SHA256).Msg("extension was rejected before, skipping it")
			continue
		}
		f, err := extensionFileName(e.Name, extensionsGOOS)
		if err != nil {
			log.Error().Err(err).Msg("skipping extension")
			st.Status = append(st.Status, newStatus(e.Name, e.SHA256, applyRejected, err.Error()))
			dirty = true
			continue
		}
		wanted[e.Name] = true
		path := filepath.Join(dir, f)
		if upToDate(path, e.SHA256) {
			if st.Installed[e.Name] != e.SHA256 {
				// Already in place but not tracked (lost state): adopt and verify it
				st.Installed[e.Name] = e.SHA256
				pending[e.Name] = e.SHA256
			}
			continue
		}
		old, _ := fileSHA256(path)
		moved, err := moveAside(dir, f)
		if err != nil {
			log.Error().Err(err).Str("name", e.Name).Msg("failed to replace extension")
			st.Status = append(st.Status, newStatus(e.Name, e.SHA256, applyRejected, err.Error()))
			dirty = true
			continue
		}
		if _, _, err := installExtension(dir, e, extensionsGOOS, appConfig.OsctrlSecret, appConfig.Insecure); err != nil {
			log.Error().Err(err).Str("name", e.Name).Msg("failed to install extension")
			// Not remembered as rejected: a download can fail for many reasons
			st.Status = append(st.Status, newStatus(e.Name, e.SHA256, applyRejected, err.Error()))
			dirty = true
			if moved {
				if err := os.Rename(path+".prev", path); err != nil {
					log.Error().Err(err).Str("name", e.Name).Msg("failed to put the previous extension back")
				}
			}
			continue
		}
		log.Info().Str("name", e.Name).Str("sha256", e.SHA256).Msg("extension installed")
		if moved {
			previous[e.Name] = old
		}
		st.Installed[e.Name] = e.SHA256
		pending[e.Name] = e.SHA256
	}
	for name, sha := range st.Installed {
		if wanted[name] {
			continue
		}
		f, err := extensionFileName(name, extensionsGOOS)
		if err != nil {
			delete(st.Installed, name)
			dirty = true
			continue
		}
		moved, err := moveAside(dir, f)
		if err != nil {
			// Still installed and autoloaded; retried on the next sync
			log.Error().Err(err).Str("name", name).Msg("failed to remove extension")
			st.Status = append(st.Status, newStatus(name, sha, applyKept, err.Error()))
			dirty = true
			continue
		}
		if moved {
			previous[name] = sha
		} else {
			// Already gone from disk: nothing a restart could undo
			st.Status = append(st.Status, newStatus(name, sha, applyRemoved, ""))
		}
		log.Info().Str("name", name).Msg("extension removed")
		delete(st.Installed, name)
		pending[name] = ""
	}

	st.Pending, st.Previous, st.Restarted = pending, previous, false
	lines := ownedLines(dir, st.Installed)
	repaired, err := updateAutoload(autoload, lines, st.Lines)
	if err != nil {
		// osquery would not load the new set, so the check would blame the
		// extensions: undo the files instead and report why
		restorePrevious(&st, dir)
		for name, sha := range pending {
			if sha != "" {
				st.Status = append(st.Status, newStatus(name, sha, applyRejected, err.Error()))
			} else if old, ok := st.Installed[name]; ok {
				st.Status = append(st.Status, newStatus(name, old, applyKept, err.Error()))
			}
		}
		st.Pending, st.Previous = nil, nil
		sweepStale(dir)
		if saveErr := saveExtState(statePath, st); saveErr != nil {
			log.Error().Err(saveErr).Msg("failed to save extensions state")
		}
		return false, err
	}
	if st.Autoload != "" && st.Autoload != autoload {
		// The flags moved the autoload file: take osctrld's lines out of the old one
		if _, err := updateAutoload(st.Autoload, nil, st.Lines); err != nil {
			log.Warn().Err(err).Str("path", st.Autoload).Msg("cannot clean the previous autoload file")
		}
	}
	if st.Autoload != autoload || !slices.Equal(st.Lines, lines) {
		st.Autoload, st.Lines = autoload, lines
		dirty = true
	}
	if len(pending) == 0 && repaired {
		// osquery was not loading osctrld's lines from this file: check the
		// installed set as if it were new
		log.Warn().Str("path", autoload).Msg("autoload file was missing osctrld's lines, rewrote it")
		for name, sha := range st.Installed {
			pending[name] = sha
		}
	}
	if len(pending) == 0 {
		st.Pending, st.Previous = nil, nil
		return false, saveIfDirty()
	}
	if err := saveExtState(statePath, st); err != nil {
		return false, err
	}
	return true, nil
}

// waitForExtensions polls until each path has been seen running on
// runningChecks consecutive polls, or restartCheckTimeout passes, and returns
// the names that were not
func waitForExtensions(ctx context.Context, paths map[string]string) ([]string, error) {
	seen := map[string]int{}
	if len(paths) > 0 {
		_, err := pollUntil(ctx, func() bool {
			done := true
			for name, path := range paths {
				if seen[name] >= runningChecks {
					continue
				}
				running, err := extensionRunning(path)
				if err != nil {
					log.Debug().Err(err).Str("name", name).Msg("error checking extension")
				}
				if running {
					seen[name]++
				} else {
					seen[name] = 0
				}
				done = done && seen[name] >= runningChecks
			}
			return done
		})
		if err != nil {
			return nil, err
		}
	}
	var failed []string
	for name := range paths {
		if seen[name] < runningChecks {
			failed = append(failed, name)
		}
	}
	slices.Sort(failed)
	return failed, nil
}

// verifyExtensionsAfterRestart checks the pending extensions after osquery
// restarted. osqueryd not running: the previous set is restored (a restored
// removal is reported kept) and osquery restarted. An extension whose process
// is not running: its new file is retired, an update's previous version put
// back, the content remembered as rejected, and osquery restarted once. A
// removal that went through is reported removed. The outcome is reported on
// the next extensions request. The rollback restart is not verified.
func verifyExtensionsAfterRestart(ctx context.Context) error {
	statePath := extStatePath()
	st := loadExtState(statePath)
	if len(st.Pending) == 0 {
		return nil
	}
	running, err := waitForOsqueryd(ctx)
	if err != nil {
		// Pending stays set, the next sync resumes the check
		return err
	}
	dir := filepath.Clean(appConfig.ExtensionsDir)
	autoload := autoloadPath(appConfig.OsqueryFlagFile, extensionsGOOS)
	restart := false
	if !running {
		log.Error().Msg("osqueryd is not running after extensions changed, restoring the previous extensions")
		msg := fmt.Sprintf("osqueryd was not running %gs after extensions changed", restartCheckTimeout.Seconds())
		restorePrevious(&st, dir)
		for name, sha := range st.Pending {
			if sha != "" {
				st.Rejected[name] = sha
				st.Status = append(st.Status, newStatus(name, sha, applyRejected, msg))
			} else if old, ok := st.Installed[name]; ok {
				// Restored; kept until osctrl serves the name again, e.g. while
				// the flags still --extensions_require it
				st.RejectedRemovals[name] = old
				st.Status = append(st.Status, newStatus(name, old, applyKept, removalDownMsg()))
			}
		}
		restart = true
	} else {
		paths := map[string]string{}
		for name, sha := range st.Pending {
			if f, err := extensionFileName(name, extensionsGOOS); err == nil && sha != "" {
				paths[name] = filepath.Join(dir, f)
			}
		}
		disabled := disabledByFlags(appConfig.OsqueryFlagFile)
		var failed []string
		if !disabled {
			if failed, err = waitForExtensions(ctx, paths); err != nil {
				return err
			}
		}
		msg := fmt.Sprintf("extension process was not running %gs after restart", restartCheckTimeout.Seconds())
		restored := map[string]bool{}
		for name := range paths {
			sha := st.Pending[name]
			switch {
			case disabled:
				st.Status = append(st.Status, newStatus(name, sha, applyOK, disabledByFlagsError))
			case slices.Contains(failed, name):
				log.Error().Str("name", name).Str("sha256", sha).Msg("extension is not running, removing it")
				retire(dir, filepath.Base(paths[name]))
				delete(st.Installed, name)
				if old, ok := st.Previous[name]; ok {
					// An update: the last good version goes back in its place
					if err := os.Rename(paths[name]+".prev", paths[name]); err != nil {
						log.Error().Err(err).Str("name", name).Msg("failed to restore previous extension")
					} else {
						st.Installed[name] = old
						restored[name] = true
					}
				}
				st.Rejected[name] = sha
				st.Status = append(st.Status, newStatus(name, sha, applyRejected, msg))
				restart = true
			default:
				log.Info().Str("name", name).Str("sha256", sha).Msg("extension is running")
				st.Status = append(st.Status, newStatus(name, sha, applyOK, ""))
			}
		}
		for name, old := range st.Previous {
			if f, err := extensionFileName(name, extensionsGOOS); err == nil && !restored[name] {
				retire(dir, f+".prev")
			}
			if st.Pending[name] == "" {
				st.Status = append(st.Status, newStatus(name, old, applyRemoved, ""))
			}
		}
	}
	st.Pending, st.Previous, st.Restarted = nil, nil, false
	if restart {
		lines := ownedLines(dir, st.Installed)
		if err := writeAutoload(autoload, lines, st.Lines); err != nil {
			log.Error().Err(err).Msg("failed to write autoload file")
		} else {
			st.Lines, st.Autoload = lines, autoload
		}
	}
	if err := saveExtState(statePath, st); err != nil {
		return err
	}
	if restart {
		if err := restartOsquery(); err != nil {
			log.Error().Err(err).Msg("failed to restart osquery")
		}
	}
	sweepStale(dir)
	return nil
}

// restartForExtensions restarts osquery for the pending extensions and records
// that it did, even when the restart failed: the check then tells
func restartForExtensions() {
	if err := restartOsquery(); err != nil {
		log.Error().Err(err).Msg("failed to restart osquery")
	}
	path := extStatePath()
	st := loadExtState(path)
	if len(st.Pending) == 0 {
		return
	}
	st.Restarted = true
	if err := saveExtState(path, st); err != nil {
		log.Error().Err(err).Msg("failed to save extensions state")
	}
}

// resumeExtensionsCheck finishes a check an earlier sync did not complete.
// osquery is restarted first unless that already happened for these changes.
func resumeExtensionsCheck(ctx context.Context) error {
	st := loadExtState(extStatePath())
	if len(st.Pending) == 0 {
		return nil
	}
	if !st.Restarted {
		log.Info().Msg("restarting osquery for unverified extensions")
		restartForExtensions()
	}
	log.Info().Msg("resuming check of unverified extensions")
	return verifyExtensionsAfterRestart(ctx)
}
