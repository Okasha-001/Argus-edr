//go:build !linux

package enrich

import "os"

// fileInode has no portable equivalent off Linux; the cache key falls back to
// path + mtime + size, which is still enough to detect a changed file.
func fileInode(os.FileInfo) uint64 { return 0 }
