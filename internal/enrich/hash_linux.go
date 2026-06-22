//go:build linux

package enrich

import (
	"os"
	"syscall"
)

// fileInode returns the file's inode number, which lets the hash cache notice a
// rebuilt binary at the same path (new inode => new key).
func fileInode(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
