package anomaly

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/argus-edr/argus/internal/model"
)

// Detector combines the two anomaly layers behind a single score. It satisfies
// the pipeline's Scorer (Score(*model.Event) float64), so the pipeline depends on
// the behaviour, not this package.
type Detector struct {
	Baseline *Baseline        `json:"baseline"`
	Forest   *IsolationForest `json:"forest,omitempty"`
}

// Score returns the event's anomaly score in [0,1] — the stronger of its rarity
// and its structural outlierness. A nil detector scores 0 (scoring disabled).
func (d *Detector) Score(e *model.Event) float64 {
	if d == nil {
		return 0
	}
	score := 0.0
	if d.Baseline != nil {
		score = d.Baseline.Rarity(e)
	}
	if d.Forest != nil {
		if structural := d.Forest.NormalizedScore(featureVector(e)); structural > score {
			score = structural
		}
	}
	return score
}

// Save writes the detector to path as JSON so a trained model can be shipped to
// agents and loaded at evaluation time.
func (d *Detector) Save(path string) error {
	encoded, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("encode baseline: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return fmt.Errorf("write baseline %s: %w", path, err)
	}
	return nil
}

// Load reads a detector previously written by Save.
func Load(path string) (*Detector, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var detector Detector
	if err := json.Unmarshal(raw, &detector); err != nil {
		return nil, fmt.Errorf("decode baseline %s: %w", path, err)
	}
	if detector.Baseline == nil {
		detector.Baseline = NewBaseline()
	}
	detector.Baseline.ensureInitialized()
	return &detector, nil
}

// Trainer accumulates observed events into a baseline and a sample set, then
// builds a Detector. It is the offline-training counterpart to Detector.Score.
type Trainer struct {
	baseline *Baseline
	vectors  [][]float64
}

// NewTrainer returns an empty trainer.
func NewTrainer() *Trainer {
	return &Trainer{baseline: NewBaseline()}
}

// Observe folds one event into the training set, skipping events with no
// judgeable features so empty records do not skew the model.
func (t *Trainer) Observe(e *model.Event) {
	if !hasFeatures(e) {
		return
	}
	t.baseline.Observe(e)
	t.vectors = append(t.vectors, featureVector(e))
}

// Count is how many events have contributed to the model so far.
func (t *Trainer) Count() int {
	return len(t.vectors)
}

// Build finalizes the trained detector, fitting the Isolation Forest over the
// collected feature vectors. source seeds the forest's randomness.
func (t *Trainer) Build(source rng) *Detector {
	return &Detector{Baseline: t.baseline, Forest: BuildForest(t.vectors, 0, 0, source)}
}
