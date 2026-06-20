package anomaly

import (
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/argus-edr/argus/internal/model"
)

func execEvent(name, path string) *model.Event {
	e := &model.Event{Type: model.EventExec, Action: "exec", Timestamp: time.Unix(1000, 0)}
	e.Process.Name = name
	e.Process.Executable = path
	e.Process.ParentName = "systemd"
	return e
}

func TestRarityDecreasesWithCount(t *testing.T) {
	prev := 2.0
	for _, count := range []uint64{0, 1, 3, 7, 15} {
		got := rarity(count)
		if got <= 0 || got > 1 {
			t.Errorf("rarity(%d) = %v, want within (0,1]", count, got)
		}
		if got >= prev {
			t.Errorf("rarity should fall as count grows: rarity(%d)=%v not < %v", count, got, prev)
		}
		prev = got
	}
}

func TestBaselineFrequentScoresLowerThanRare(t *testing.T) {
	base := NewBaseline()
	common := execEvent("bash", "/bin/bash")
	for i := 0; i < 64; i++ {
		base.Observe(common)
	}
	rare := execEvent("xmrig", "/tmp/xmrig")

	commonScore := base.Rarity(common)
	rareScore := base.Rarity(rare)
	if commonScore >= rareScore {
		t.Errorf("frequent (%v) should score below rare (%v)", commonScore, rareScore)
	}
	if rareScore < 0.9 {
		t.Errorf("never-seen executable should score near 1.0, got %v", rareScore)
	}
}

func TestBaselineNoFeaturesScoresZero(t *testing.T) {
	if got := NewBaseline().Rarity(&model.Event{}); got != 0 {
		t.Errorf("event with no judgeable features = %v, want 0", got)
	}
}

// normalVector draws a point from a tight cluster, the bulk of "normal" traffic.
func normalVector(src *rand.Rand) []float64 {
	jitter := func(center float64) float64 { return center + src.Float64()*2 - 1 }
	return []float64{jitter(5), jitter(20), jitter(3), jitter(12), jitter(0), jitter(1000), jitter(2), jitter(3)}
}

func TestForestScoresOutlierAboveNormal(t *testing.T) {
	src := rand.New(rand.NewSource(1))
	samples := make([][]float64, 0, 400)
	for i := 0; i < 400; i++ {
		samples = append(samples, normalVector(src))
	}
	forest := BuildForest(samples, 100, 256, src)
	if forest == nil {
		t.Fatal("BuildForest returned nil for non-empty samples")
	}

	normal := []float64{5, 20, 3, 12, 0, 1000, 2, 3}
	outlier := []float64{60, 4000, 40, 3, 65535, 0, 9, 7.9}
	if forest.NormalizedScore(outlier) <= forest.NormalizedScore(normal) {
		t.Errorf("outlier (%v) should score above normal (%v)",
			forest.NormalizedScore(outlier), forest.NormalizedScore(normal))
	}
}

func TestForestEmptyAndNilSafe(t *testing.T) {
	if BuildForest(nil, 10, 10, rand.New(rand.NewSource(1))) != nil {
		t.Error("BuildForest of no samples should be nil")
	}
	var forest *IsolationForest
	if forest.Score([]float64{1, 2, 3, 4, 5, 6, 7, 8}) != 0 {
		t.Error("nil forest should score 0")
	}
}

func TestDetectorSaveLoadRoundTrip(t *testing.T) {
	trainer := NewTrainer()
	for i := 0; i < 200; i++ {
		trainer.Observe(execEvent("bash", "/bin/bash"))
	}
	if trainer.Count() != 200 {
		t.Fatalf("Count = %d, want 200", trainer.Count())
	}
	detector := trainer.Build(rand.New(rand.NewSource(7)))

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := detector.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	common := execEvent("bash", "/bin/bash")
	rare := execEvent("evil", "/tmp/evil")
	if loaded.Score(rare) <= loaded.Score(common) {
		t.Errorf("after reload, rare (%v) should score above common (%v)", loaded.Score(rare), loaded.Score(common))
	}
}

func TestNilDetectorScoresZero(t *testing.T) {
	var detector *Detector
	if detector.Score(&model.Event{}) != 0 {
		t.Error("nil detector should score 0")
	}
}

func TestTrainerSkipsFeaturelessEvents(t *testing.T) {
	trainer := NewTrainer()
	trainer.Observe(&model.Event{}) // nothing to learn
	if trainer.Count() != 0 {
		t.Errorf("featureless event should not be counted, got %d", trainer.Count())
	}
}
