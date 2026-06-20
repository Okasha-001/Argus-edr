package respond

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"time"
)

const (
	// nftTable/nftChain are ARGUS's own nftables objects. Keeping a dedicated
	// table means the agent never touches an operator's existing firewall and can
	// be torn down cleanly (`nft delete table inet argus`).
	nftTable   = "argus"
	nftChain   = "argus_egress"
	nftTimeout = 5 * time.Second
)

// commandRunner executes an external command. It is a seam so tests can assert
// the exact nftables invocations without a privileged host or a real firewall.
type commandRunner func(ctx context.Context, name string, args ...string) error

func execCommand(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

// networkBlocker drops outbound traffic to specific destination IPs with
// nftables. It owns one table and one chain, created on first use with a default
// `accept` policy, and only ever appends explicit per-IP `drop` rules — so a
// misfire blocks one destination, never the whole host.
type networkBlocker struct {
	run commandRunner

	mu      sync.Mutex
	chainUp bool
	blocked map[string]bool
}

func newNetworkBlocker(run commandRunner) *networkBlocker {
	return &networkBlocker{run: run, blocked: make(map[string]bool)}
}

// Block drops egress to ip. It is idempotent: a second call for an already
// blocked address is a no-op, so repeated alerts don't pile up duplicate rules.
func (b *networkBlocker) Block(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid ip %q", ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.blocked[ip] {
		return nil
	}
	if err := b.ensureChain(ctx); err != nil {
		return err
	}
	family := "ip"
	if parsed.To4() == nil {
		family = "ip6"
	}
	if err := b.run(ctx, "nft", "add", "rule", "inet", nftTable, nftChain, family, "daddr", ip, "drop"); err != nil {
		return fmt.Errorf("nft drop %s: %w", ip, err)
	}
	b.blocked[ip] = true
	return nil
}

func (b *networkBlocker) ensureChain(ctx context.Context) error {
	if b.chainUp {
		return nil
	}
	if err := b.run(ctx, "nft", "add", "table", "inet", nftTable); err != nil {
		return fmt.Errorf("nft create table: %w", err)
	}
	if err := b.run(ctx, "nft", "add", "chain", "inet", nftTable, nftChain,
		"{ type filter hook output priority 0 ; policy accept ; }"); err != nil {
		return fmt.Errorf("nft create chain: %w", err)
	}
	b.chainUp = true
	return nil
}
