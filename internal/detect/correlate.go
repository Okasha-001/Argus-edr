package detect

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

// Default per-alert risk contribution when a rule does not set its own score.
var severityScores = map[model.Severity]int{
	model.SeverityLow:      10,
	model.SeverityMedium:   25,
	model.SeverityHigh:     50,
	model.SeverityCritical: 80,
}

// maxTrackedProcesses bounds correlator memory; the oldest states are swept when
// the map grows past it.
const maxTrackedProcesses = 16384

// Correlator accumulates risk per process tree inside a sliding time window. A
// kill chain — several suspicious steps by the same process within the window —
// crosses the threshold and opens a single incident instead of N loose alerts.
type Correlator struct {
	window    time.Duration
	threshold int

	mu     sync.Mutex
	states map[string]*procState
	clock  func() time.Time
}

type procState struct {
	score      int
	techniques map[string]bool
	ruleIDs    []string
	first      time.Time
	last       time.Time
	opened     bool
}

// NewCorrelator builds a correlator with the given window and incident threshold.
func NewCorrelator(window time.Duration, threshold int) *Correlator {
	return &Correlator{
		window:    window,
		threshold: threshold,
		states:    make(map[string]*procState),
		clock:     time.Now,
	}
}

// Observe folds an event's alerts into its process state and returns an incident
// the first time the accumulated risk crosses the threshold.
func (c *Correlator) Observe(event *model.Event, alerts []*model.Alert) *model.Incident {
	if len(alerts) == 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.eventTime(event)
	state := c.stateFor(event.ProcessKey(), now)
	for _, alert := range alerts {
		state.score += c.scoreOf(alert)
		state.techniques[alert.Technique.ID] = true
		state.ruleIDs = append(state.ruleIDs, alert.RuleID)
	}
	state.last = now

	if state.opened || state.score < c.threshold {
		return nil
	}
	state.opened = true
	return buildIncident(event, state)
}

func (c *Correlator) stateFor(key string, now time.Time) *procState {
	state, ok := c.states[key]
	if !ok || now.Sub(state.last) > c.window {
		state = &procState{techniques: make(map[string]bool), first: now, last: now}
		c.states[key] = state
		c.sweep(now)
	}
	return state
}

func (c *Correlator) scoreOf(alert *model.Alert) int {
	if alert.RiskScore > 0 {
		return alert.RiskScore
	}
	return severityScores[alert.Severity]
}

func (c *Correlator) eventTime(event *model.Event) time.Time {
	if event.Timestamp.IsZero() {
		return c.clock()
	}
	return event.Timestamp
}

// sweep drops states whose window has elapsed once the map grows too large.
func (c *Correlator) sweep(now time.Time) {
	if len(c.states) <= maxTrackedProcesses {
		return
	}
	for key, state := range c.states {
		if now.Sub(state.last) > c.window {
			delete(c.states, key)
		}
	}
}

func buildIncident(event *model.Event, state *procState) *model.Incident {
	techniques := make([]string, 0, len(state.techniques))
	for id := range state.techniques {
		if id != "" {
			techniques = append(techniques, id)
		}
	}
	sort.Strings(techniques)

	return &model.Incident{
		ID:         fmt.Sprintf("INC-%s-%d", event.Host, state.first.UnixNano()),
		Host:       event.Host,
		ProcessKey: event.ProcessKey(),
		RiskScore:  state.score,
		Techniques: techniques,
		RuleIDs:    dedupeStrings(state.ruleIDs),
		FirstSeen:  state.first,
		LastSeen:   state.last,
		Status:     model.IncidentOpen,
		Summary: fmt.Sprintf("process %s (pid %d) accumulated risk %d across %d techniques",
			event.Process.Name, event.Process.PID, state.score, len(techniques)),
	}
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
