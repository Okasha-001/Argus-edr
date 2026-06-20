package detect

import "testing"

// BenchmarkEngineEvaluate measures evaluating one event against the full shipped
// ruleset — the per-event cost of the detection stage. It loads the real rules
// so the number reflects production conditions, not a toy set.
func BenchmarkEngineEvaluate(b *testing.B) {
	rules, err := LoadDir("../../rules")
	if err != nil {
		b.Fatalf("load rules: %v", err)
	}
	engine := NewEngine(rules, nil)
	event := reverseShellEvent()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Evaluate(event)
	}
}
