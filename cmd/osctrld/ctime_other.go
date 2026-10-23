//go:build !linux && !darwin

package main

import (
	"os"
	"time"
)

// fileChangeTime falls back to mtime where osctrld does not read the inode
// change time (Windows has none)
func fileChangeTime(info os.FileInfo) time.Time {
	return info.ModTime()
}
