// Package intel matches events against threat-intelligence indicators (IOCs):
// malicious IPs/CIDRs, domains and file hashes loaded from feed files. A feed is
// a newline-delimited list of indicators ('#' comments allowed) whose type is
// inferred per line. An external updater (a cron job, or a future control-plane
// push) refreshes the files; the matcher loads them at startup.
package intel

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/argus-edr/argus/internal/model"
)

// Indicator types.
const (
	TypeIP     = "ip"
	TypeDomain = "domain"
	TypeHash   = "hash"
)

const sha256HexLen = 64

type cidrEntry struct {
	network *net.IPNet
	source  string
}

// Matcher indexes indicators for O(1) exact lookups (IPs, domains, hashes) plus
// a linear scan of CIDR ranges. It is read-only after Load, so Match is safe to
// call concurrently.
type Matcher struct {
	ips     map[string]string
	cidrs   []cidrEntry
	domains map[string]string
	hashes  map[string]string
}

// Load reads the feed files and builds a Matcher. Per line the indicator type is
// inferred: a CIDR (contains '/'), an IP, a 64-hex SHA-256, otherwise a domain.
// Blank lines and '#' comments (whole-line or trailing) are ignored. Each
// indicator's source is the feed's file name.
func Load(paths ...string) (*Matcher, error) {
	matcher := &Matcher{
		ips:     make(map[string]string),
		domains: make(map[string]string),
		hashes:  make(map[string]string),
	}
	for _, path := range paths {
		if err := matcher.loadFile(path); err != nil {
			return nil, err
		}
	}
	return matcher, nil
}

func (m *Matcher) loadFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open intel feed: %w", err)
	}
	defer file.Close()

	source := filepath.Base(path)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			m.add(line, source)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read intel feed %s: %w", source, err)
	}
	return nil
}

func (m *Matcher) add(indicator, source string) {
	switch {
	case strings.Contains(indicator, "/"):
		if _, network, err := net.ParseCIDR(indicator); err == nil {
			m.cidrs = append(m.cidrs, cidrEntry{network: network, source: source})
		}
	case net.ParseIP(indicator) != nil:
		m.ips[indicator] = source
	case isSHA256(indicator):
		m.hashes[strings.ToLower(indicator)] = source
	default:
		m.domains[strings.ToLower(indicator)] = source
	}
}

// Size reports how many indicators are loaded, for startup logging.
func (m *Matcher) Size() int {
	return len(m.ips) + len(m.cidrs) + len(m.domains) + len(m.hashes)
}

// Match returns every indicator the event hits, in a stable order (destination
// ip, source ip, domain, hash).
func (m *Matcher) Match(event *model.Event) []model.IntelHit {
	var hits []model.IntelHit
	for _, probe := range []struct{ field, ip string }{
		{"destination.ip", event.Network.DstIP},
		{"source.ip", event.Network.SrcIP},
	} {
		if probe.ip == "" {
			continue
		}
		if source, ok := m.matchIP(probe.ip); ok {
			hits = append(hits, model.IntelHit{Indicator: probe.ip, Type: TypeIP, Field: probe.field, Source: source})
		}
	}
	if domain := strings.ToLower(event.Network.Domain); domain != "" {
		if source, ok := m.domains[domain]; ok {
			hits = append(hits, model.IntelHit{Indicator: event.Network.Domain, Type: TypeDomain, Field: "network.domain", Source: source})
		}
	}
	if hash := strings.ToLower(event.Process.SHA256); hash != "" {
		if source, ok := m.hashes[hash]; ok {
			hits = append(hits, model.IntelHit{Indicator: event.Process.SHA256, Type: TypeHash, Field: "process.sha256", Source: source})
		}
	}
	return hits
}

func (m *Matcher) matchIP(ip string) (string, bool) {
	if source, ok := m.ips[ip]; ok {
		return source, true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	for _, entry := range m.cidrs {
		if entry.network.Contains(parsed) {
			return entry.source, true
		}
	}
	return "", false
}

func isSHA256(value string) bool {
	if len(value) != sha256HexLen {
		return false
	}
	for _, char := range value {
		isHex := (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}
