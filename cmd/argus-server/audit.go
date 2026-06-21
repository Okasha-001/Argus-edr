package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"
)

// auditEntry is one admin action recorded in a tamper-evident chain. Each entry's
// Hash covers its own fields and the previous entry's Hash, so altering any past
// entry breaks every hash after it. When the log is keyed, Sig is an HMAC of the
// hash, so the chain cannot be silently rewritten without the key either.
type auditEntry struct {
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
	Sig      string    `json:"sig,omitempty"`
}

// auditLog appends entries to a hash chain, optionally HMAC-signed, and mirrors
// each to a sink (an append-only file) and the structured logger. All exported
// operations are safe for concurrent admin requests.
type auditLog struct {
	mu     sync.Mutex
	seq    uint64
	prev   string
	key    []byte
	sink   io.Writer
	logger *slog.Logger
}

func newAuditLog(sink io.Writer, key []byte, logger *slog.Logger) *auditLog {
	return &auditLog{key: key, sink: sink, logger: logger}
}

// record appends one action and returns the sealed entry.
func (l *auditLog) record(actor, action, target, detail string) auditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	entry := auditEntry{
		Seq: l.seq, Time: time.Now().UTC(), Actor: actor,
		Action: action, Target: target, Detail: detail, PrevHash: l.prev,
	}
	entry.Hash = entry.computeHash()
	if len(l.key) > 0 {
		entry.Sig = entry.sign(l.key)
	}
	l.prev = entry.Hash

	if l.sink != nil {
		if line, err := json.Marshal(entry); err == nil {
			_, _ = l.sink.Write(append(line, '\n'))
		}
	}
	if l.logger != nil {
		l.logger.Info("admin audit",
			"seq", entry.Seq, "actor", entry.Actor, "action", entry.Action, "target", entry.Target)
	}
	return entry
}

// canonical is the exact byte sequence the hash covers — a field-separated form
// (the 0x1f unit separator can't appear in the textual fields) so two different
// field splits can never collide on the same hash.
func (e auditEntry) canonical() string {
	return fmt.Sprintf("%d\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s",
		e.Seq, e.Time.Format(time.RFC3339Nano), e.Actor, e.Action, e.Target, e.Detail, e.PrevHash)
}

func (e auditEntry) computeHash() string {
	sum := sha256.Sum256([]byte(e.canonical()))
	return hex.EncodeToString(sum[:])
}

func (e auditEntry) sign(key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(e.Hash))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyAuditChain walks entries in order and confirms the chain is intact: each
// entry links to the previous, its hash matches its contents, and — when a key is
// given — its signature is valid. A tampered or reordered log fails here.
func verifyAuditChain(entries []auditEntry, key []byte) error {
	prev := ""
	for _, entry := range entries {
		if entry.PrevHash != prev {
			return fmt.Errorf("audit entry %d: chain broken (prev_hash mismatch)", entry.Seq)
		}
		if entry.computeHash() != entry.Hash {
			return fmt.Errorf("audit entry %d: hash mismatch (record tampered)", entry.Seq)
		}
		if len(key) > 0 && !hmac.Equal([]byte(entry.sign(key)), []byte(entry.Sig)) {
			return fmt.Errorf("audit entry %d: signature mismatch", entry.Seq)
		}
		prev = entry.Hash
	}
	return nil
}
