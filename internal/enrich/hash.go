package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

// Hasher computes SHA-256 digests of executables for IOC matching. Results are
// cached by a key that includes the inode and mtime, so a rebuilt binary at the
// same path is rehashed while an unchanged one is not.
type Hasher struct {
	mu       sync.Mutex
	cache    map[string]string
	maxBytes int64
}

// NewHasher returns a hasher that skips files larger than maxBytes.
func NewHasher(maxBytes int64) *Hasher {
	return &Hasher{cache: make(map[string]string), maxBytes: maxBytes}
}

// Hash returns the hex SHA-256 of the file at path, or "" if it cannot be read
// or exceeds the size limit.
func (h *Hasher) Hash(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	if h.maxBytes > 0 && info.Size() > h.maxBytes {
		return ""
	}

	key := cacheKey(path, info)
	if cached, ok := h.lookup(key); ok {
		return cached
	}

	digest := hashFile(path)
	h.store(key, digest)
	return digest
}

func (h *Hasher) lookup(key string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	value, ok := h.cache[key]
	return value, ok
}

func (h *Hasher) store(key, value string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cache[key] = value
}

func hashFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return ""
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func cacheKey(path string, info os.FileInfo) string {
	// The inode strengthens the key so a rebuilt binary at the same path is
	// re-hashed; it is OS-specific (fileInode lives in hash_linux.go / hash_other.go).
	return fmt.Sprintf("%s|%d|%d|%d", path, fileInode(info), info.ModTime().UnixNano(), info.Size())
}
