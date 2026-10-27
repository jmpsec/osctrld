//go:build !windows

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/rs/zerolog/log"
)

// setOwnerRoot hands path to root:root without following a symlink
func setOwnerRoot(path string) error {
	return os.Lchown(path, 0, 0)
}

// adminOwnedFile reports whether path is a regular file owned by root at
// exactly 0755, so nobody but root can have rewritten it or rewrite it later
func adminOwnedFile(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode() != 0755 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// adminOwnedDir reports whether path is a real directory (not a symlink) owned
// by root that neither group nor others can write
func adminOwnedDir(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Type() != fs.ModeDir || info.Mode().Perm()&0022 != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// ownedByCurrentUser reports whether info (of path) belongs to this process's user
func ownedByCurrentUser(_ string, info fs.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// fileOwner is the uid and gid of info
func fileOwner(info fs.FileInfo) (*fileOwnerIDs, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, false
	}
	return &fileOwnerIDs{UID: int(st.Uid), GID: int(st.Gid)}, true
}

// rootUID is a seam: tests cannot create files owned by root
var rootUID = 0

// warnUnsafeConfigFile warns, once per problem, when osctrld runs as root from a
// configuration file, or a directory holding it, that another user could
// rewrite: the configuration picks every path root writes and the extensions
// osquery loads. A warning, not a refusal, so existing hosts keep running.
// Only the immediate directories are checked, not every ancestor.
func warnUnsafeConfigFile(path string) {
	if path == defEmptyValue || geteuid() != 0 {
		return
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return
	}
	checks := []struct{ kind, path string }{
		{"file", resolved},
		{"directory", filepath.Dir(resolved)},
		// Whoever can write the symlink's directory can point it elsewhere
		{"directory", filepath.Dir(path)},
	}
	var seen []fs.FileInfo
	for _, c := range checks {
		info, err := os.Stat(c.path)
		if err != nil || slices.ContainsFunc(seen, func(s fs.FileInfo) bool { return os.SameFile(s, info) }) {
			continue
		}
		seen = append(seen, info)
		owner, ok := fileOwner(info)
		if !ok {
			continue
		}
		for _, problem := range ownershipProblems(info.Mode(), owner.UID == rootUID) {
			log.Warn().Str("config", c.kind).Str("path", c.path).Str("problem", problem).Msg("unsafe configuration ownership: osctrld runs as root, so whoever can change this picks the paths root writes and the extensions osquery loads; make it root-owned and not group or world writable")
		}
	}
}
