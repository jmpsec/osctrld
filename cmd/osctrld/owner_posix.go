//go:build !windows

package main

import (
	"io/fs"
	"os"
	"syscall"
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

// ownedByCurrentUser reports whether info belongs to this process's user
func ownedByCurrentUser(info fs.FileInfo) bool {
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
