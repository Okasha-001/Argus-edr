package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func render(r *Registry) string {
	var b strings.Builder
	if err := r.Render(&b); err != nil {
		panic(err)
	}
	return b.String()
}

func TestCounterExposition(t *testing.T) {
	reg := New()
	events := reg.Counter("argus_events_total", "Events processed.")
	events.Inc()
	events.Add(4)

	out := render(reg)
	if events.Value() != 5 {
		t.Errorf("value = %d, want 5", events.Value())
	}
	for _, want := range []string{
		"# HELP argus_events_total Events processed.",
		"# TYPE argus_events_total counter",
		"argus_events_total 5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q in:\n%s", want, out)
		}
	}
}

func TestGaugeUpAndDown(t *testing.T) {
	reg := New()
	depth := reg.Gauge("argus_ring_depth", "Ring buffer depth.")
	depth.Set(10)
	depth.Add(-3)
	if depth.Value() != 7 {
		t.Errorf("value = %v, want 7", depth.Value())
	}
	if !strings.Contains(render(reg), "argus_ring_depth 7") {
		t.Errorf("gauge value not exposed:\n%s", render(reg))
	}
}

func TestCounterVecSortedAndLabelled(t *testing.T) {
	reg := New()
	drops := reg.CounterVec("argus_ring_drops_total", "Ring drops by program.", "program")
	drops.WithLabelValue("handle_exec").Add(2)
	drops.WithLabelValue("handle_connect").Inc()
	// Same label reuses the child rather than creating a second series.
	drops.WithLabelValue("handle_exec").Inc()

	out := render(reg)
	exec := `argus_ring_drops_total{program="handle_exec"} 3`
	conn := `argus_ring_drops_total{program="handle_connect"} 1`
	if !strings.Contains(out, exec) || !strings.Contains(out, conn) {
		t.Fatalf("labelled series missing in:\n%s", out)
	}
	// connect sorts before exec, so its line must come first.
	if strings.Index(out, conn) > strings.Index(out, exec) {
		t.Errorf("series not sorted by label value:\n%s", out)
	}
}

func TestHistogramCumulativeBuckets(t *testing.T) {
	reg := New()
	h := reg.Histogram("argus_stage_seconds", "Stage latency.", []float64{0.001, 0.01, 0.1})
	h.Observe(0.0005) // bucket 0.001
	h.Observe(0.005)  // bucket 0.01
	h.Observe(0.5)    // +Inf only

	out := render(reg)
	for _, want := range []string{
		`argus_stage_seconds_bucket{le="0.001"} 1`,
		`argus_stage_seconds_bucket{le="0.01"} 2`, // cumulative: 0.0005 + 0.005
		`argus_stage_seconds_bucket{le="0.1"} 2`,
		`argus_stage_seconds_bucket{le="+Inf"} 3`,
		`argus_stage_seconds_count 3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("histogram missing %q in:\n%s", want, out)
		}
	}
}

func TestHistogramVecLabelsBuckets(t *testing.T) {
	reg := New()
	stages := reg.HistogramVec("argus_pipeline_stage_seconds", "Per-stage latency.", "stage", []float64{0.001})
	stages.WithLabelValue("enrich").Observe(0.0005)
	stages.WithLabelValue("detect").Observe(0.002)

	out := render(reg)
	for _, want := range []string{
		`argus_pipeline_stage_seconds_bucket{stage="enrich",le="0.001"} 1`,
		`argus_pipeline_stage_seconds_bucket{stage="detect",le="+Inf"} 1`,
		`argus_pipeline_stage_seconds_count{stage="enrich"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("vec histogram missing %q in:\n%s", want, out)
		}
	}
}

func TestGaugeFuncReadsAtScrape(t *testing.T) {
	reg := New()
	count := 3
	reg.GaugeFunc("argus_server_agents", "Enrolled agents.", func() float64 { return float64(count) })

	if !strings.Contains(render(reg), "argus_server_agents 3") {
		t.Errorf("gauge func not read at first scrape:\n%s", render(reg))
	}
	count = 5 // the source changed; the next scrape must reflect it
	if !strings.Contains(render(reg), "argus_server_agents 5") {
		t.Errorf("gauge func not re-read on second scrape:\n%s", render(reg))
	}
}

func TestEscapeLabelValue(t *testing.T) {
	reg := New()
	vec := reg.CounterVec("argus_x_total", "x", "name")
	vec.WithLabelValue(`a"b\c`).Inc()
	if got := render(reg); !strings.Contains(got, `name="a\"b\\c"`) {
		t.Errorf("label not escaped: %s", got)
	}
}

func TestHandlerServesExposition(t *testing.T) {
	reg := New()
	reg.Counter("argus_up", "up").Inc()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
	if !strings.Contains(rec.Body.String(), "argus_up 1") {
		t.Errorf("body missing metric:\n%s", rec.Body.String())
	}
}
