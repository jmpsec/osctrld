//go:build darwin

package main

import (
	"os"
	"syscall"
	"time"
)

// fileChangeTime is the inode change time, which a package payload cannot
// carry over the way it sets mtime; mtime when it is unavailable
func fileChangeTime(info os.FileInfo) time.Time {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return time.Unix(st.Ctimespec.Unix())
	}
	return info.ModTime()
}
