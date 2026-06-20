// Package correlate finds patterns that only show up across the whole fleet: the
// same technique on many hosts (lateral movement) or many hosts contacting one
// destination (C2 fan-in). Per-host correlation already happens in the agent.
package correlate

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/argus-edr/argus/server/store"
)

// Signal kinds.
const (
	KindLateralMovement = "lateral-movement"
	KindC2FanIn         = "c2-fanin"
)

// Signal is a fleet-wide finding raised when a key is seen on enough distinct
// hosts within the window.
type Signal struct {
	Kind      string
	Key       string // technique id or destination ip
	Hosts     []string
	FirstSeen time.Time
	LastSeen  time.Time
	Summary   string
}

// CrossHost tracks, per key, which hosts have hit it recently.
type CrossHost struct {
	window   time.Duration
	minHosts int

	mu          sync.Mutex
	byTechnique map[string]*hostWindow
	byDest      map[string]*hostWindow
	clock       func() time.Time
}

type hostWindow struct {
	hosts map[string]time.Time
	first time.Time
	fired bool
}

// NewCrossHost correlates over the given window, raising a signal once a key
// reaches minHosts distinct hosts.
func NewCrossHost(window time.Duration, minHosts int) *CrossHost {
	return &CrossHost{
		window:      window,
		minHosts:    minHosts,
		byTechnique: make(map[string]*hostWindow),
		byDest:      make(map[string]*hostWindow),
		clock:       time.Now,
	}
}

// Observe folds one alert into the cross-host state and returns any signals it
// triggers (lateral movement by technique, C2 fan-in by destination).
func (c *CrossHost) Observe(record store.AlertRecord) []Signal {
	now := c.timeOf(record)

	c.mu.Lock()
	defer c.mu.Unlock()

	var signals []Signal
	if record.TechniqueID != "" {
		if signal := c.track(c.byTechnique, record.TechniqueID, record.Hostname, now, KindLateralMovement); signal != nil {
			signals = append(signals, *signal)
		}
	}
	if record.DestinationIP != "" {
		if signal := c.track(c.byDest, record.DestinationIP, record.Hostname, now, KindC2FanIn); signal != nil {
			signals = append(signals, *signal)
		}
	}
	return signals
}

func (c *CrossHost) track(index map[string]*hostWindow, key, host string, now time.Time, kind string) *Signal {
	window, ok := index[key]
	if !ok || now.Sub(window.first) > c.window {
		window = &hostWindow{hosts: make(map[string]time.Time), first: now}
		index[key] = window
	}
	window.hosts[host] = now
	pruneExpired(window.hosts, now, c.window)

	if window.fired || len(window.hosts) < c.minHosts {
		return nil
	}
	window.fired = true

	hosts := sortedKeys(window.hosts)
	return &Signal{
		Kind:      kind,
		Key:       key,
		Hosts:     hosts,
		FirstSeen: window.first,
		LastSeen:  now,
		Summary:   summarize(kind, key, hosts),
	}
}

func summarize(kind, key string, hosts []string) string {
	joined := strings.Join(hosts, ", ")
	switch kind {
	case KindLateralMovement:
		return fmt.Sprintf("technique %s seen on %d hosts: %s", key, len(hosts), joined)
	case KindC2FanIn:
		return fmt.Sprintf("%d hosts contacted %s: %s", len(hosts), key, joined)
	default:
		return key
	}
}

func pruneExpired(hosts map[string]time.Time, now time.Time, window time.Duration) {
	for host, seen := range hosts {
		if now.Sub(seen) > window {
			delete(hosts, host)
		}
	}
}

func sortedKeys(hosts map[string]time.Time) []string {
	keys := make([]string, 0, len(hosts))
	for host := range hosts {
		keys = append(keys, host)
	}
	sort.Strings(keys)
	return keys
}

func (c *CrossHost) timeOf(record store.AlertRecord) time.Time {
	if record.Time.IsZero() {
		return c.clock()
	}
	return record.Time
}
