package metrics

import (
	"sort"
	"strconv"
	"sync"
)

// DefaultLatencyBuckets spans roughly 1µs to 100ms in seconds — the range a
// per-stage pipeline timing falls in (decode ~700ns, engine ~2µs per the
// benchmarks), with headroom for a slow enrich or a stalled sink.
var DefaultLatencyBuckets = []float64{
	1e-6, 5e-6, 1e-5, 5e-5, 1e-4, 5e-4, 1e-3, 5e-3, 1e-2, 5e-2, 0.1,
}

// Histogram counts observations into cumulative buckets plus a sum and count. A
// single mutex guards the whole observation, which is fine: the hot-path writer
// is the pipeline's single consumer goroutine, so there is no contention.
type Histogram struct {
	name, help string
	bounds     []float64 // ascending upper bounds; the implicit +Inf bucket trails
	mu         sync.Mutex
	counts     []uint64 // len(bounds)+1
	sum        float64
	total      uint64
}

func newHistogram(name, help string, buckets []float64) *Histogram {
	bounds := append([]float64(nil), buckets...)
	sort.Float64s(bounds)
	return &Histogram{name: name, help: help, bounds: bounds, counts: make([]uint64, len(bounds)+1)}
}

// Observe records one value (seconds), landing it in the first bucket whose upper
// bound is at least v, or the +Inf bucket when it exceeds them all.
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	h.counts[h.bucketIndex(v)]++
	h.sum += v
	h.total++
	h.mu.Unlock()
}

func (h *Histogram) bucketIndex(v float64) int {
	for i, bound := range h.bounds {
		if v <= bound {
			return i
		}
	}
	return len(h.bounds) // +Inf
}

func (h *Histogram) writeProm(w *lineWriter) {
	writeHeader(w, h.name, h.help, "histogram")
	h.writeSeries(w, "")
}

// writeSeries renders the buckets, sum and count. prefix is the already-formatted
// inner label for a vec child (e.g. `stage="enrich"`), or empty for a plain one.
func (h *Histogram) writeSeries(w *lineWriter, prefix string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	cumulative := uint64(0)
	for i, bound := range h.bounds {
		cumulative += h.counts[i]
		writeBucket(w, h.name, prefix, strconv.FormatFloat(bound, 'g', -1, 64), cumulative)
	}
	cumulative += h.counts[len(h.bounds)]
	writeBucket(w, h.name, prefix, "+Inf", cumulative)

	writeSuffix(w, h.name, "_sum", prefix)
	w.float(h.sum)
	w.char('\n')
	writeSuffix(w, h.name, "_count", prefix)
	w.uint(h.total)
	w.char('\n')
}

// HistogramVec is a set of histograms sharing a name, split by one label — e.g.
// processing latency by pipeline stage.
type HistogramVec struct {
	name, help, label string
	buckets           []float64
	mu                sync.Mutex
	children          map[string]*Histogram
}

// WithLabelValue returns the histogram for one label value, created on first use.
func (v *HistogramVec) WithLabelValue(value string) *Histogram {
	v.mu.Lock()
	defer v.mu.Unlock()
	child, ok := v.children[value]
	if !ok {
		child = newHistogram(v.name, v.help, v.buckets)
		v.children[value] = child
	}
	return child
}

func (v *HistogramVec) writeProm(w *lineWriter) {
	writeHeader(w, v.name, v.help, "histogram")
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, key := range sortedKeys(v.children) {
		v.children[key].writeSeries(w, v.label+`="`+escapeLabel(key)+`"`)
	}
}

func writeBucket(w *lineWriter, name, prefix, le string, count uint64) {
	w.text(name)
	w.text("_bucket{")
	if prefix != "" {
		w.text(prefix)
		w.char(',')
	}
	w.text(`le="`)
	w.text(le)
	w.text(`"} `)
	w.uint(count)
	w.char('\n')
}

// writeSuffix emits `name_suffix{prefix} ` (or without braces when prefix empty),
// shared by the _sum and _count lines.
func writeSuffix(w *lineWriter, name, suffix, prefix string) {
	w.text(name)
	w.text(suffix)
	if prefix != "" {
		w.char('{')
		w.text(prefix)
		w.char('}')
	}
	w.char(' ')
}
