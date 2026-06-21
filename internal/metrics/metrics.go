// Package metrics is a tiny, dependency-free Prometheus exposition. ARGUS ships
// its own rather than pulling in the full client library, matching the project's
// minimal-dependency stance (cf. the pure-Go YARA and Sigma packages). It covers
// exactly what the agent and control plane export: counters, gauges, and latency
// histograms, each optionally labelled.
package metrics

import (
	"bufio"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
)

// lineWriter accumulates the exposition while swallowing per-write errors and
// holding the first one, so each collector can render without checking every
// call; the single error is examined once, after the flush.
type lineWriter struct {
	w   *bufio.Writer
	err error
}

func (l *lineWriter) text(s string) {
	if l.err == nil {
		_, l.err = l.w.WriteString(s)
	}
}

func (l *lineWriter) char(c byte) {
	if l.err == nil {
		l.err = l.w.WriteByte(c)
	}
}

func (l *lineWriter) uint(n uint64)   { l.text(strconv.FormatUint(n, 10)) }
func (l *lineWriter) float(v float64) { l.text(strconv.FormatFloat(v, 'g', -1, 64)) }

// collector is one metric family able to render itself in the text format.
type collector interface {
	writeProm(w *lineWriter)
}

// Registry holds the metrics a process exposes and renders them on scrape. The
// zero value is not usable; call New.
type Registry struct {
	mu         sync.Mutex
	collectors []collector
}

// New returns an empty registry.
func New() *Registry { return &Registry{} }

func (r *Registry) register(c collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, c)
}

// Counter registers and returns a monotonic counter.
func (r *Registry) Counter(name, help string) *Counter {
	counter := &Counter{name: name, help: help}
	r.register(counter)
	return counter
}

// Gauge registers and returns a gauge.
func (r *Registry) Gauge(name, help string) *Gauge {
	gauge := &Gauge{name: name, help: help}
	r.register(gauge)
	return gauge
}

// CounterVec registers and returns a counter family split by the named label.
func (r *Registry) CounterVec(name, help, label string) *CounterVec {
	vec := &CounterVec{name: name, help: help, label: label, children: map[string]*atomic.Uint64{}}
	r.register(vec)
	return vec
}

// Histogram registers and returns a latency histogram with the given second
// bucket bounds.
func (r *Registry) Histogram(name, help string, buckets []float64) *Histogram {
	histogram := newHistogram(name, help, buckets)
	r.register(histogram)
	return histogram
}

// HistogramVec registers a histogram family split by the named label.
func (r *Registry) HistogramVec(name, help, label string, buckets []float64) *HistogramVec {
	vec := &HistogramVec{name: name, help: help, label: label, buckets: buckets, children: map[string]*Histogram{}}
	r.register(vec)
	return vec
}

// Render writes every registered metric in the Prometheus text format.
func (r *Registry) Render(w io.Writer) error {
	out := &lineWriter{w: bufio.NewWriter(w)}
	r.mu.Lock()
	for _, c := range r.collectors {
		c.writeProm(out)
	}
	r.mu.Unlock()
	if flushErr := out.w.Flush(); out.err == nil {
		out.err = flushErr
	}
	return out.err
}

// Handler serves the registry at an HTTP endpoint (mount it at /metrics).
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.Render(w) // a broken client connection is the only failure; nothing to do
	})
}

// Counter is a value that only ever increases.
type Counter struct {
	name, help string
	value      atomic.Uint64
}

// Inc adds one; Add adds n.
func (c *Counter) Inc()         { c.value.Add(1) }
func (c *Counter) Add(n uint64) { c.value.Add(n) }

// Value reads the current count.
func (c *Counter) Value() uint64 { return c.value.Load() }

func (c *Counter) writeProm(w *lineWriter) {
	writeHeader(w, c.name, c.help, "counter")
	w.text(c.name)
	w.char(' ')
	w.uint(c.value.Load())
	w.char('\n')
}

// Gauge is a value that can go up or down.
type Gauge struct {
	name, help string
	bits       atomic.Uint64 // float64 bits
}

// Set replaces the value.
func (g *Gauge) Set(v float64) { g.bits.Store(math.Float64bits(v)) }

// Add adjusts the value by delta (which may be negative).
func (g *Gauge) Add(delta float64) {
	for {
		old := g.bits.Load()
		next := math.Float64bits(math.Float64frombits(old) + delta)
		if g.bits.CompareAndSwap(old, next) {
			return
		}
	}
}

// Value reads the current value.
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

func (g *Gauge) writeProm(w *lineWriter) {
	writeHeader(w, g.name, g.help, "gauge")
	w.text(g.name)
	w.char(' ')
	w.float(g.Value())
	w.char('\n')
}

// CounterVec is a set of counters sharing a name, one per value of a single
// label — e.g. ring-buffer drops by sensor program.
type CounterVec struct {
	name, help, label string
	mu                sync.Mutex
	children          map[string]*atomic.Uint64
}

// WithLabelValue returns the counter for one label value, creating it on first
// use so a never-seen value costs nothing until it fires.
func (v *CounterVec) WithLabelValue(value string) *LabelledCounter {
	v.mu.Lock()
	defer v.mu.Unlock()
	child, ok := v.children[value]
	if !ok {
		child = &atomic.Uint64{}
		v.children[value] = child
	}
	return &LabelledCounter{child}
}

func (v *CounterVec) writeProm(w *lineWriter) {
	writeHeader(w, v.name, v.help, "counter")
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, key := range sortedKeys(v.children) {
		w.text(v.name)
		w.char('{')
		writeLabel(w, v.label, key)
		w.text("} ")
		w.uint(v.children[key].Load())
		w.char('\n')
	}
}

// LabelledCounter is one series of a CounterVec.
type LabelledCounter struct{ value *atomic.Uint64 }

// Inc and Add accumulate; Set mirrors a value sampled from elsewhere (e.g. a
// kernel counter read whole each scrape rather than incremented).
func (c *LabelledCounter) Inc()         { c.value.Add(1) }
func (c *LabelledCounter) Add(n uint64) { c.value.Add(n) }
func (c *LabelledCounter) Set(n uint64) { c.value.Store(n) }

// writeHeader emits the # HELP / # TYPE preamble shared by every family.
func writeHeader(w *lineWriter, name, help, kind string) {
	w.text("# HELP ")
	w.text(name)
	w.char(' ')
	w.text(help)
	w.text("\n# TYPE ")
	w.text(name)
	w.char(' ')
	w.text(kind)
	w.char('\n')
}

func writeLabel(w *lineWriter, name, value string) {
	w.text(name)
	w.text(`="`)
	w.text(escapeLabel(value))
	w.char('"')
}

// escapeLabel quotes the three characters the text format reserves in a label
// value, so a program name with a backslash or quote can't corrupt the output.
func escapeLabel(value string) string {
	if !needsEscape(value) {
		return value
	}
	var b []byte
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\', '"':
			b = append(b, '\\', value[i])
		case '\n':
			b = append(b, '\\', 'n')
		default:
			b = append(b, value[i])
		}
	}
	return string(b)
}

func needsEscape(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' || value[i] == '"' || value[i] == '\n' {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
