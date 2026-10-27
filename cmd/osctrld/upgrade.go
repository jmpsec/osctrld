package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Upgrade results and the reasons osctrld reports for them
const (
	upgradeOK       = "ok"
	upgradeRejected = "rejected"
	upgradeSkipped  = "skipped"

	reasonTargetUnavailable   = "target_unavailable"
	reasonPreviousUnavailable = "previous_unavailable"
	reasonDigestMismatch      = "digest_mismatch"
	reasonInstallFailed       = "install_failed"
	reasonConfigChanged       = "config_changed"
	reasonVersionNotReported  = "version_not_reported"
	reasonOsquerydNotRunning  = "osqueryd_not_running"
	reasonUnsupportedPlatform = "unsupported_platform"
	reasonRolledBack          = "rolled_back"
	// reasonRollbackUnavailable is a failed Windows upgrade: there is no MSI
	// downgrade, the config is restored over the new version
	reasonRollbackUnavailable = "rollback_unavailable"
	// Reasons osctrl answers with on the upgrade route
	reasonNoTarget             = "no_target"
	reasonAheadOfTarget        = "ahead_of_target"
	reasonNoDigestForTarget    = "no_digest_for_target"
	reasonNoDigestForInstalled = "no_digest_for_installed"
	reasonRolloutPending       = "rollout_pending"
	reasonRolloutPaused        = "rollout_paused"
)

var (
	// upgradeConfirmWindow is how long osctrl gets to see the new version
	// after the restart; log batches are periodic, so longer than the process check
	upgradeConfirmWindow   = 5 * time.Minute
	upgradeConfirmInterval = 30 * time.Second
	// upgradeConfirmWait is the wait between confirmation polls; a seam for tests
	upgradeConfirmWait = time.After
	// upgradeSkipBackoff is how long a target whose packages were unusable is
	// not downloaded again for the same request, so a bad digest in the
	// library does not make every host download it every sync
	upgradeSkipBackoff = 6 * time.Hour
	// lchownPath restores a snapshotted file's owner; a seam for tests
	lchownPath = os.Lchown
	// Seams so tests run the upgrade without a package manager or service manager
	upgradePackageFormat = func() (packageFormat, error) { return packageFormatFor(upgradeGOOS, "") }
	upgradePackageURL    = upgradeOsqueryPackageURL
	upgradeStopOsquery   = stopOsquery
	// Start, not restart: after a stop launchd has unloaded the job, which
	// kickstart cannot restart; on Linux start brings a stopped service up
	upgradeStartOsquery = startOsquery
	// upgradeEnsureService reapplies the osqueryd service settings an MSI may
	// reset; Windows only, a seam for tests
	upgradeEnsureService = ensureServiceSettings
)

// upgradeOsqueryPackageURL is osqueryPackageURL for upgrades. The library
// keys MSI digests per architecture and only the x64 MSI has a known name,
// so an upgrade never fetches it for another architecture (install still does,
// for emulation).
func upgradeOsqueryPackageURL(format packageFormat, version, goarch string) (string, error) {
	if format == pkgMSI && goarch != "amd64" {
		return "", fmt.Errorf("no msi package for architecture %s", goarch)
	}
	return osqueryPackageURL(format, version, goarch)
}

// applyStashACL restricts the stash directory to SYSTEM and Administrators; a
// no-op off Windows, a seam for tests
var applyStashACL = applyStashACLOS

// upgradeDir keeps the verified packages and the config snapshot, readable by
// root only, so an upgrade can be undone after an osctrld restart or a reboot
func upgradeDir() string {
	return appConfig.OsqueryFlagFile + ".osctrld-upgrade"
}

func snapshotPath() string {
	return filepath.Join(upgradeDir(), "snapshot.json")
}

// stashPath is where the verified package with digest sha lives
func stashPath(sha string, format packageFormat) string {
	return filepath.Join(upgradeDir(), sha+"."+string(format))
}

// checkUpgradeDir refuses an upgrade directory that is not a real directory
// owned by this process (root). strictACL makes failing to restrict it on
// Windows fatal; reading back a stash to restore it only logs that, since
// not restoring would leave osqueryd on the package's defaults.
func checkUpgradeDir(strictACL bool) error {
	dir := upgradeDir()
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	// Not IsDir: a Windows junction reports ModeDir with ModeIrregular
	if info.Mode().Type() != fs.ModeDir {
		return fmt.Errorf("%s is not a directory, refusing to use it", dir)
	}
	if !ownedByCurrentUser(dir, info) {
		return fmt.Errorf("%s is not owned by osctrld, refusing to use it", dir)
	}
	// On Windows the stash holds the enrollment secret and would inherit
	// Program Files ACLs readable by Users: restrict it to SYSTEM and
	// Administrators, only now that it is a real directory with a trusted owner
	// (also re-applied for a stash left by an earlier run)
	if upgradeGOOS == WindowsOS {
		if err := applyStashACL(dir); err != nil {
			if strictACL {
				return fmt.Errorf("error restricting access to %s - %v", dir, err)
			}
			log.Warn().Err(err).Str("path", dir).Msg("failed to restrict access to the upgrade directory, using it anyway")
		}
	}
	return nil
}

// ensureUpgradeDir creates the upgrade directory 0700 if missing and checks it
func ensureUpgradeDir() (string, error) {
	dir := upgradeDir()
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("error creating %s - %v", dir, err)
	}
	if err := checkUpgradeDir(true); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("error setting mode on %s - %v", dir, err)
	}
	return dir, nil
}

// removeStash deletes the stashed packages and the snapshot
func removeStash() {
	if err := os.RemoveAll(upgradeDir()); err != nil {
		log.Error().Err(err).Str("path", upgradeDir()).Msg("failed to remove upgrade packages")
	}
}

// verifyFile checks path still has digest, right before it is installed
func verifyFile(path, digest string) error {
	sum, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if !strings.EqualFold(sum, digest) {
		return fmt.Errorf("%w for %s - expected %s, got %s", errDigestMismatch, path, digest, sum)
	}
	return nil
}

// stashPackage copies a downloaded package into the upgrade directory,
// hashing it again on the way, and removes the download
func stashPackage(src, digest string, format packageFormat) (string, error) {
	defer func() { _ = os.Remove(src) }()
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(upgradeDir(), ".stash-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	_, err = io.Copy(tmp, io.TeeReader(in, h))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if sum := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(sum, digest) {
		return "", fmt.Errorf("%w for %s - expected %s, got %s", errDigestMismatch, src, digest, sum)
	}
	dst := stashPath(digest, format)
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	syncDir(upgradeDir())
	return dst, nil
}

// fileOwnerIDs is a POSIX file owner
type fileOwnerIDs struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// snapshotFile is one config file as it was before the upgrade. Owner is nil
// where it is unknown (Windows), and setOwner hands the file to the administrator.
type snapshotFile struct {
	Path    string        `json:"path"`
	Content []byte        `json:"content"`
	Mode    os.FileMode   `json:"mode"`
	Owner   *fileOwnerIDs `json:"owner,omitempty"`
	// Autoload marks the autoload file, whose path is checked again on restore
	Autoload bool `json:"autoload,omitempty"`
}

// osquerySnapshot is the osquery config a package install may overwrite
type osquerySnapshot struct {
	Files      []snapshotFile    `json:"files"`
	Extensions map[string]string `json:"extensions"`
}

// snapshotOsqueryConfig records the flagfile, secret, certificate and autoload
// file that exist, and a listing of the extensions directory
func snapshotOsqueryConfig() (osquerySnapshot, error) {
	snap := osquerySnapshot{}
	paths := []string{appConfig.OsqueryFlagFile, appConfig.OsquerySecretFile, appConfig.OsqueryCertFile}
	// The autoload path comes from flags environment admins edit: only one
	// osctrld would write itself is snapshotted, and so rewritten as root
	autoload := autoloadPath(appConfig.OsqueryFlagFile, upgradeGOOS)
	if err := checkAutoloadPath(autoload); err != nil {
		log.Warn().Err(err).Msg("leaving the autoload file out of the upgrade snapshot")
		autoload = ""
	} else {
		autoload = filepath.Clean(autoload)
		paths = append(paths, autoload)
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		info, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return snap, fmt.Errorf("error reading %s - %v", p, err)
		}
		if !info.Mode().IsRegular() {
			return snap, fmt.Errorf("%s is not a regular file, refusing to snapshot it", p)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return snap, fmt.Errorf("error reading %s - %v", p, err)
		}
		owner, _ := fileOwner(info)
		snap.Files = append(snap.Files, snapshotFile{Path: p, Content: b, Mode: info.Mode().Perm(), Owner: owner, Autoload: p == autoload})
	}
	ext, err := extensionsListing()
	if err != nil {
		return snap, err
	}
	snap.Extensions = ext
	return snap, nil
}

// restore rewrites every snapshotted file as it was, handed to the administrator
// (the secret restricted to SYSTEM and Administrators where its owner is unknown).
// snapshot.json is not trusted with the autoload path: it is checked again,
// and an entry that is none of the fixed files counts as the autoload file
// (older snapshots have no Autoload field).
func (s osquerySnapshot) restore() error {
	var errs []error
	fixed := []string{appConfig.OsqueryFlagFile, appConfig.OsquerySecretFile, appConfig.OsqueryCertFile}
	for _, f := range s.Files {
		if f.Autoload || !slices.Contains(fixed, f.Path) {
			if err := checkAutoloadPath(f.Path); err != nil {
				log.Warn().Err(err).Str("path", f.Path).Msg("not restoring the autoload file from the upgrade snapshot")
				continue
			}
		}
		secret := fileACLFor(f.Path, appConfig.OsquerySecretFile, upgradeGOOS) == aclSecret
		if err := writeFileAtomic(f.Path, f.Content, f.Mode, secret); err != nil {
			errs = append(errs, err)
			continue
		}
		if f.Owner != nil {
			if err := lchownPath(f.Path, f.Owner.UID, f.Owner.GID); err != nil {
				errs = append(errs, fmt.Errorf("error setting owner on %s - %v", f.Path, err))
			}
		} else if secret {
			// Created with secretDACLSDDL; extensionDACL would let Users read it
			continue
		} else if err := setOwner(f.Path); err != nil {
			errs = append(errs, fmt.Errorf("error setting owner on %s - %v", f.Path, err))
		}
	}
	return errors.Join(errs...)
}

func saveSnapshot(s osquerySnapshot) error {
	return writeStateFile(snapshotPath(), s)
}

func loadSnapshot() (osquerySnapshot, error) {
	var s osquerySnapshot
	if err := checkUpgradeDir(false); err != nil {
		return s, err
	}
	b, err := os.ReadFile(snapshotPath())
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

// extensionsListing maps every entry of the extensions directory to the
// SHA-256 of its content, or its type for anything but a regular file
func extensionsListing() (map[string]string, error) {
	listing := map[string]string{}
	dir := appConfig.ExtensionsDir
	if dir == "" {
		return listing, nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return listing, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing %s - %v", dir, err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			listing[e.Name()] = e.Type().String()
			continue
		}
		sum, err := fileSHA256(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("error hashing %s - %v", e.Name(), err)
		}
		listing[e.Name()] = sum
	}
	return listing, nil
}

func sameListing(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// stopForUpgrade stops osquery; failing to stop one that is not running is fine
func stopForUpgrade() {
	if err := upgradeStopOsquery(); err != nil {
		log.Warn().Err(err).Msg("failed to stop osquery")
	}
}

// confirmMaxRetryAfter caps how long one 429 from osctrl delays the next poll
const confirmMaxRetryAfter = 5 * time.Minute

// confirmNewVersion asks osctrl until it reports the node runs target, the
// window ends or ctx is cancelled. Errors and old osctrls count as not yet; a
// 429 delays the next poll by its Retry-After, within the window.
func confirmNewVersion(ctx context.Context, target string) (bool, error) {
	end := time.Now().Add(upgradeConfirmWindow)
	deadline := time.After(upgradeConfirmWindow)
	for {
		wait := upgradeConfirmInterval
		res, err := requestUpgradeResolution(target)
		var se *httpStatusError
		switch {
		case errors.As(err, &se) && se.code == http.StatusTooManyRequests:
			if se.retryAfter > wait {
				wait = max(min(se.retryAfter, confirmMaxRetryAfter, time.Until(end)), 0)
			}
			log.Debug().Dur("retry_after", se.retryAfter).Msg("osctrl rate limited the osquery version check")
		case err != nil:
			log.Debug().Err(err).Msg("osquery version not confirmed yet")
		case res.ReportedVersion == target:
			return true, nil
		}
		// A zero wait and the fired deadline are both ready, and select picks
		// at random: never poll again once the window is over (a cancel
		// still wins, so the caller resumes instead of rolling back)
		if time.Until(end) <= 0 {
			return false, ctx.Err()
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline:
			return false, nil
		case <-upgradeConfirmWait(wait):
		}
	}
}

// upgradeOsquery installs res.Target, keeping the osquery config, and rolls
// back to res.Previous when osqueryd does not run it or osctrl never sees it.
// Windows has no previous package: a failure restores the config only.
// The caller checked shouldAttempt and that osqueryd runs. A cancelled ctx
// returns its error without an outcome; resumeUpgrade continues from the
// pending marker.
func upgradeOsquery(ctx context.Context, res upgradeResolution) (upgradeResult, error) {
	if !validResolution(res) {
		return upgradeResult{}, errors.New("invalid upgrade resolution, refusing to upgrade")
	}
	target := *res.Target
	windows := upgradeGOOS == WindowsOS
	var previous upgradeRef
	if windows {
		// Only the version, to tell an install that did not take effect
		previous.Version = osqueryVersionReader()
	} else {
		previous = *res.Previous
	}
	path := upgradeStatePath()
	st := loadUpgradeState(path)
	if st.Pending != nil {
		return upgradeResult{}, errors.New("an osquery upgrade is already pending, resume it first")
	}
	if s := st.Skipped; s != nil && s.Version == target.Version && s.SHA256 == target.SHA256 &&
		s.RequestID == res.RequestID && time.Since(s.At) >= 0 && time.Since(s.At) < upgradeSkipBackoff {
		log.Debug().Str("version", target.Version).Str("reason", s.Reason).Msg("osquery upgrade skipped recently, not downloading again")
		return upgradeResult{Result: upgradeSkipped, Version: target.Version, Reason: s.Reason, RequestID: res.RequestID, At: s.At}, nil
	}
	skip := func(reason string) (upgradeResult, error) {
		removeStash()
		r := upgradeResult{Result: upgradeSkipped, Version: target.Version, Reason: reason, RequestID: res.RequestID, At: time.Now().UTC()}
		log.Warn().Str("version", target.Version).Str("reason", reason).Msg("osquery upgrade skipped")
		st.Last = &r
		switch reason {
		case reasonTargetUnavailable, reasonPreviousUnavailable, reasonDigestMismatch, reasonInstallFailed:
			st.Skipped = &skippedUpgrade{Version: target.Version, SHA256: target.SHA256, RequestID: res.RequestID, Reason: reason, At: r.At}
		}
		return r, saveUpgradeState(path, st)
	}
	format, err := upgradePackageFormat()
	if err != nil {
		return skip(reasonUnsupportedPlatform)
	}

	// Downloads a SIGTERM interrupted are never cleaned up by their own defers
	sweepStaleDownloads(staleDownloadAge)
	// Nothing on the host changes until both packages are verified and stashed
	targetTmp, reason := downloadForUpgrade(format, target, reasonTargetUnavailable)
	if reason != "" {
		return skip(reason)
	}
	defer func() { _ = os.Remove(targetTmp) }()
	var previousTmp string
	if !windows {
		previousTmp, reason = downloadForUpgrade(format, previous, reasonPreviousUnavailable)
		if reason != "" {
			return skip(reason)
		}
		defer func() { _ = os.Remove(previousTmp) }()
	}
	if ctx.Err() != nil {
		return upgradeResult{}, ctx.Err()
	}
	removeStash()
	if _, err := ensureUpgradeDir(); err != nil {
		log.Error().Err(err).Msg("cannot keep the osquery packages")
		return skip(reasonInstallFailed)
	}
	targetPkg, err := stashPackage(targetTmp, target.SHA256, format)
	if err != nil {
		log.Error().Err(err).Msg("cannot keep the target osquery package")
		return skip(stashReason(err))
	}
	var previousPkg string
	if !windows {
		if previousPkg, err = stashPackage(previousTmp, previous.SHA256, format); err != nil {
			log.Error().Err(err).Msg("cannot keep the previous osquery package")
			return skip(stashReason(err))
		}
	}
	if err := verifyPackageSignature(format, targetPkg); err != nil {
		log.Error().Err(err).Msg("target osquery package signature")
		return skip(reasonTargetUnavailable)
	}
	if !windows {
		if err := verifyPackageSignature(format, previousPkg); err != nil {
			log.Error().Err(err).Msg("previous osquery package signature")
			return skip(reasonPreviousUnavailable)
		}
	}
	snap, err := snapshotOsqueryConfig()
	if err == nil {
		err = saveSnapshot(snap)
	}
	if err != nil {
		log.Error().Err(err).Msg("cannot snapshot the osquery config")
		return skip(reasonInstallFailed)
	}

	st.Pending = &pendingUpgrade{Target: target, Previous: previous, PreviousPkg: previousPkg,
		RequestID: res.RequestID, StartedAt: time.Now().UTC()}
	if err := saveUpgradeState(path, st); err != nil {
		removeStash()
		return upgradeResult{}, err
	}
	// Last look at the bytes about to be installed
	if err := verifyFile(targetPkg, target.SHA256); err != nil {
		log.Error().Err(err).Msg("stashed target osquery package changed")
		st.Pending = nil
		return skip(reasonDigestMismatch)
	}
	log.Info().Str("version", target.Version).Str("previous", previous.Version).Msg("upgrading osquery")
	stopForUpgrade()
	notTaken := false
	err = installPackageAs(format, targetPkg, false)
	if windows && errors.Is(err, errMSITimeout) {
		// Only the msiexec client was killed: the Windows Installer may still
		// be replacing files, so nothing is decided or started before it is idle
		log.Error().Err(err).Str("version", target.Version).Msg("msiexec timed out, waiting for the Windows Installer to finish")
		idle, werr := installerIdleWait(ctx, installerIdleTimeout)
		if ctx.Err() != nil {
			return upgradeResult{}, ctx.Err()
		}
		if werr != nil || !idle {
			// Pending stays and osqueryd stays stopped: the next sync's resume
			// decides by the version the installer leaves
			log.Error().Err(werr).Str("version", target.Version).Msg("the Windows Installer is still busy, leaving the osquery upgrade pending")
			r := upgradeResult{Result: upgradeSkipped, Version: target.Version, Reason: reasonInstallFailed, RequestID: res.RequestID, At: time.Now().UTC()}
			st.Last = &r
			st.Skipped = &skippedUpgrade{Version: target.Version, SHA256: target.SHA256, RequestID: res.RequestID, Reason: reasonInstallFailed, At: r.At}
			return r, saveUpgradeState(path, st)
		}
		if osqueryVersionReader() == target.Version {
			log.Info().Str("version", target.Version).Msg("the Windows Installer finished the osquery install after the msiexec timeout")
			err = nil
		}
	}
	if err != nil {
		log.Error().Err(err).Str("version", target.Version).Msg("osquery install failed")
		if osqueryVersionReader() != previous.Version {
			return rollbackUpgrade(ctx, &st, reasonInstallFailed)
		}
		notTaken = true
	} else if windows && previous.Version != "" && osqueryVersionReader() == previous.Version {
		// msiexec succeeded (e.g. 3010) but the swap waits for a reboot
		log.Warn().Str("version", target.Version).Msg("osquery install did not take effect, the previous version is still installed")
		notTaken = true
	}
	if notTaken {
		// The host still runs the previous version (e.g. the package manager
		// was busy): put the config and osqueryd back and retry later
		stopForUpgrade()
		if err := snap.restore(); err != nil {
			log.Error().Err(err).Msg("failed to restore the osquery config")
		}
		reapplyServiceSettings()
		if err := upgradeStartOsquery(); err != nil {
			log.Error().Err(err).Msg("failed to start osquery")
		}
		if _, err := waitForOsqueryd(ctx); err != nil {
			// Pending stays: resume finds the previous version and forgets it
			return upgradeResult{}, err
		}
		st.Pending = nil
		return skip(reasonInstallFailed)
	}
	st.Pending.Installed = true
	if err := saveUpgradeState(path, st); err != nil {
		log.Error().Err(err).Msg("failed to save upgrade state")
	}
	return verifyUpgrade(ctx, &st, snap)
}

// downloadForUpgrade fetches and verifies ref, returning the temp file or the
// reason it is not usable
func downloadForUpgrade(format packageFormat, ref upgradeRef, unavailable string) (string, string) {
	url, err := upgradePackageURL(format, ref.Version, upgradeGOARCH)
	if err != nil {
		log.Error().Err(err).Str("version", ref.Version).Msg("no osquery package for this host")
		return "", unavailable
	}
	// The official server has a public certificate: --insecure is only for osctrl
	p, err := downloadPackage(url, ref.SHA256, false, false)
	if errors.Is(err, errDigestMismatch) {
		log.Error().Err(err).Msg("osquery package digest mismatch")
		return "", reasonDigestMismatch
	}
	if err != nil {
		log.Error().Err(err).Str("version", ref.Version).Msg("osquery package unavailable")
		return "", unavailable
	}
	return p, ""
}

func stashReason(err error) string {
	if errors.Is(err, errDigestMismatch) {
		return reasonDigestMismatch
	}
	return reasonInstallFailed
}

// verifyUpgrade puts the snapshot back over what the package installed, checks
// the install, starts osquery and waits for osqueryd and osctrl to confirm.
// osquery is stopped first: it must never run with packaged defaults.
func verifyUpgrade(ctx context.Context, st *upgradeState, snap osquerySnapshot) (upgradeResult, error) {
	p := st.Pending
	stopForUpgrade()
	if err := snap.restore(); err != nil {
		log.Error().Err(err).Msg("failed to restore the osquery config after install")
		return rollbackUpgrade(ctx, st, reasonInstallFailed)
	}
	ext, err := extensionsListing()
	if err != nil || !sameListing(ext, snap.Extensions) {
		log.Error().Err(err).Msg("the osquery package changed the extensions directory")
		return rollbackUpgrade(ctx, st, reasonConfigChanged)
	}
	if v := osqueryVersionReader(); v != p.Target.Version {
		log.Error().Str("installed", v).Str("target", p.Target.Version).Msg("osquery version after install is not the target")
		return rollbackUpgrade(ctx, st, reasonInstallFailed)
	}
	// The MSI may reset the service's start type and --flagfile argument
	if upgradeGOOS == WindowsOS {
		if _, err := upgradeEnsureService(appConfig.OsqueryFlagFile); err != nil {
			log.Error().Err(err).Msg("failed to reapply the osquery service settings")
			return rollbackUpgrade(ctx, st, reasonInstallFailed)
		}
	}
	if err := upgradeStartOsquery(); err != nil {
		log.Error().Err(err).Msg("failed to start osquery")
	}
	running, err := waitForOsqueryd(ctx)
	if err != nil {
		return upgradeResult{}, err
	}
	if !running {
		log.Error().Str("version", p.Target.Version).Msg("osqueryd is not running after upgrade, rolling back")
		return rollbackUpgrade(ctx, st, reasonOsquerydNotRunning)
	}
	confirmed, err := confirmNewVersion(ctx, p.Target.Version)
	if err != nil {
		return upgradeResult{}, err
	}
	if !confirmed {
		log.Error().Str("version", p.Target.Version).Msg("osctrl never saw the new osquery version, rolling back")
		return rollbackUpgrade(ctx, st, reasonVersionNotReported)
	}
	r := upgradeResult{Result: upgradeOK, Version: p.Target.Version, RequestID: p.RequestID, At: time.Now().UTC()}
	st.Last, st.Rejected, st.Pending, st.Skipped = &r, nil, nil, nil
	err = saveUpgradeState(upgradeStatePath(), *st)
	removeStash()
	log.Info().Str("version", r.Version).Msg("osquery upgraded")
	return r, err
}

// rollbackUpgrade installs the stashed previous package, restores the
// snapshot and starts osquery, once, and records the target as rejected.
// The reason is saved first so an interrupted rollback resumes as itself.
// Windows has no MSI downgrade: the config is restored over the new version
// and the rejection says rollback_unavailable.
func rollbackUpgrade(ctx context.Context, st *upgradeState, reason string) (upgradeResult, error) {
	path := upgradeStatePath()
	p := st.Pending
	if p.Rollback != reason {
		p.Rollback = reason
		if err := saveUpgradeState(path, *st); err != nil {
			log.Error().Err(err).Msg("failed to save upgrade state")
		}
	}
	recorded := reason
	if upgradeGOOS == WindowsOS {
		recorded = reasonRollbackUnavailable
		log.Error().Str("version", p.Target.Version).Str("reason", reason).Msg("osquery upgrade failed and cannot be rolled back on Windows, restoring the config only")
	} else {
		log.Warn().Str("version", p.Target.Version).Str("previous", p.Previous.Version).Str("reason", reason).Msg("rolling back osquery upgrade")
		stopForUpgrade()
		if err := installPrevious(p); err != nil {
			log.Error().Err(err).Str("version", p.Previous.Version).Msg("failed to reinstall the previous osquery package")
		}
	}
	stopForUpgrade()
	if snap, err := loadSnapshot(); err != nil {
		log.Error().Err(err).Msg("no osquery config snapshot to restore")
	} else {
		if err := snap.restore(); err != nil {
			log.Error().Err(err).Msg("failed to restore the osquery config")
		}
		removeAddedExtensions(snap.Extensions, p.StartedAt.Add(-time.Minute))
	}
	reapplyServiceSettings()
	if err := upgradeStartOsquery(); err != nil {
		log.Error().Err(err).Msg("failed to start osquery")
	}
	if _, err := waitForOsqueryd(ctx); err != nil {
		return upgradeResult{}, err
	}
	r := upgradeResult{Result: upgradeRejected, Version: p.Target.Version, Reason: recorded, RequestID: p.RequestID,
		EventID: fmt.Sprintf("%d:%s", time.Now().UnixNano(), p.Target.SHA256), At: time.Now().UTC()}
	st.Last = &r
	rr := r
	st.Rejected = &rejectedUpgrade{Version: p.Target.Version, SHA256: p.Target.SHA256, RequestID: p.RequestID, Result: &rr}
	st.Pending, st.Skipped = nil, nil
	err := saveUpgradeState(path, *st)
	removeStash()
	return r, err
}

// reapplyServiceSettings is the Windows service settings check before a
// restart that must happen anyway: a failure is only logged
func reapplyServiceSettings() {
	if upgradeGOOS != WindowsOS {
		return
	}
	if _, err := upgradeEnsureService(appConfig.OsqueryFlagFile); err != nil {
		log.Error().Err(err).Msg("failed to reapply the osquery service settings")
	}
}

// serviceSettingsRestart restarts osqueryd after its service settings were
// repaired; a seam for tests
var serviceSettingsRestart = restartOsquery

// checkServiceSettings repairs the osqueryd service start type and --flagfile
// argument on Windows, which an MSI (also one finishing after msiexec timed
// out) may reset, and restarts osqueryd so it runs with them. Never while an
// upgrade is pending: that upgrade stops and starts osqueryd itself.
func checkServiceSettings() {
	if upgradeGOOS != WindowsOS || loadUpgradeState(upgradeStatePath()).Pending != nil {
		return
	}
	changed, err := upgradeEnsureService(appConfig.OsqueryFlagFile)
	if err != nil {
		log.Warn().Err(err).Msg("failed to check the osquery service settings")
		return
	}
	if !changed {
		return
	}
	log.Warn().Msg("the osquery service settings had been reset, restarting osquery")
	if err := serviceSettingsRestart(); err != nil {
		log.Warn().Err(err).Msg("failed to restart osquery")
	}
}

// changeTime reads a file's inode change time; a seam for tests
var changeTime = fileChangeTime

// removeAddedExtensions deletes the regular files directly in the extensions
// directory that are not in the snapshot listing and whose ctime is not before
// since, i.e. added during the upgrade. ctime, not mtime: package managers set
// mtime from the payload. Symlinks, directories and older files are left
// alone; a failed removal is only logged.
func removeAddedExtensions(listing map[string]string, since time.Time) {
	dir := appConfig.ExtensionsDir
	if dir == "" || listing == nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			log.Error().Err(err).Str("dir", dir).Msg("cannot list the extensions directory")
		}
		return
	}
	for _, e := range entries {
		if _, known := listing[e.Name()]; known {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, e.Name()))
		if err != nil || !info.Mode().IsRegular() || changeTime(info).Before(since) {
			continue
		}
		if err := removeManagedFile(dir, e.Name()); err != nil {
			log.Error().Err(err).Str("file", e.Name()).Msg("failed to remove a file the osquery package added")
			continue
		}
		log.Warn().Str("file", e.Name()).Msg("removed a file the osquery package added to the extensions directory")
	}
}

// installPrevious installs the stashed previous package, only from the
// upgrade directory and only if its digest still matches
func installPrevious(p *pendingUpgrade) error {
	format, err := upgradePackageFormat()
	if err != nil {
		return err
	}
	if err := checkUpgradeDir(false); err != nil {
		return err
	}
	if filepath.Dir(p.PreviousPkg) != filepath.Clean(upgradeDir()) {
		return fmt.Errorf("previous package %s is outside %s", p.PreviousPkg, upgradeDir())
	}
	if err := verifyFile(p.PreviousPkg, p.Previous.SHA256); err != nil {
		return err
	}
	return installPackageAs(format, p.PreviousPkg, true)
}

// resumeUpgrade finishes an upgrade an earlier sync left pending (osctrld
// stopped, host rebooted): verification continues if the target is installed,
// an install that never happened is forgotten, anything else is rolled back.
func resumeUpgrade(ctx context.Context) error {
	path := upgradeStatePath()
	st := loadUpgradeState(path)
	p := st.Pending
	if p == nil {
		return nil
	}
	if p.Rollback != "" {
		_, err := rollbackUpgrade(ctx, &st, p.Rollback)
		return err
	}
	// msiexec may have timed out with the install still running in the
	// Windows Installer: give it one wait, then decide anyway so a stuck
	// installer cannot keep osqueryd stopped
	if upgradeGOOS == WindowsOS && !p.Installed {
		// The health watcher does not tick while this sync goroutine waits
		idle, err := installerIdleWait(ctx, installerIdleTimeout)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || !idle {
			log.Warn().Err(err).Msg("the Windows Installer is still busy, resuming the osquery upgrade anyway")
		}
	}
	snap, snapErr := loadSnapshot()
	v := osqueryVersionReader()
	neverInstalled := v != "" && v == p.Previous.Version && !p.Installed
	switch {
	// A Windows install that never took effect is forgotten even without a
	// snapshot: there is no rollback, and recording one would pause the rollout
	case snapErr != nil && (upgradeGOOS != WindowsOS || !neverInstalled):
		log.Error().Err(snapErr).Msg("no osquery config snapshot for the pending upgrade")
	case v == p.Target.Version:
		log.Info().Str("version", v).Msg("resuming osquery upgrade verification")
		if !p.Installed {
			p.Installed = true
			if err := saveUpgradeState(path, st); err != nil {
				return err
			}
		}
		_, err := verifyUpgrade(ctx, &st, snap)
		return err
	case neverInstalled:
		log.Info().Str("version", v).Msg("pending osquery upgrade was never installed, forgetting it")
		if snapErr != nil {
			log.Error().Err(snapErr).Msg("no osquery config snapshot to restore")
		} else if err := snap.restore(); err != nil {
			log.Error().Err(err).Msg("failed to restore the osquery config")
		}
		// The upgrade only starts with osqueryd running, so a stopped one
		// was stopped by it
		if running, _ := osquerydRunning(); !running {
			reapplyServiceSettings()
			if err := upgradeStartOsquery(); err != nil {
				log.Error().Err(err).Msg("failed to start osquery")
			}
			if _, err := waitForOsqueryd(ctx); err != nil {
				return err
			}
		}
		st.Pending = nil
		err := saveUpgradeState(path, st)
		removeStash()
		return err
	}
	_, err := rollbackUpgrade(ctx, &st, reasonInstallFailed)
	return err
}
