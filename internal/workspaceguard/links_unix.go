//go:build unix

package workspaceguard

import (
	"os"
	"syscall"
)

// SingleLink rejects inode aliases that could escape a directory-only boundary.
// Call it on the opened handle before reading, truncating or transferring ownership.
func SingleLink(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
