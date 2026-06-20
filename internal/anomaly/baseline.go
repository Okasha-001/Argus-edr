package anomaly

import (
	"math"

	"github.com/argus-edr/argus/internal/model"
)

// Baseline records how often each categorical feature has been seen. Rarity is a
// function of a feature's absolute count: never-seen is maximally suspicious, and
// suspicion falls off as the count grows. Counts are simple and serializable, so
// a baseline trains offline (`argus baseline build`) and loads at evaluation.
type Baseline struct {
	Executable  map[string]uint64 `json:"executable"`
	ParentChild map[string]uint64 `json:"parent_child"`
	DestPort    map[string]uint64 `json:"dest_port"`
	UserProcess map[string]uint64 `json:"user_process"`
}

// NewBaseline returns an empty baseline ready to Observe events.
func NewBaseline() *Baseline {
	return &Baseline{
		Executable:  make(map[string]uint64),
		ParentChild: make(map[string]uint64),
		DestPort:    make(map[string]uint64),
		UserProcess: make(map[string]uint64),
	}
}

// counts returns the map backing a category, so Observe and rarity share one
// source of truth and a new category is wired in exactly one place.
func (b *Baseline) counts(cat category) map[string]uint64 {
	switch cat {
	case catExecutable:
		return b.Executable
	case catParentChild:
		return b.ParentChild
	case catDestPort:
		return b.DestPort
	default:
		return b.UserProcess
	}
}

// Observe folds an event into the baseline, incrementing the count of each
// feature it carries. This is the training step.
func (b *Baseline) Observe(e *model.Event) {
	for _, f := range featuresOf(e) {
		b.counts(f.cat)[f.key]++
	}
}

// Rarity scores an event in [0,1] by its rarest feature: the dimension on which
// it is most unusual drives the score, since one strange aspect is enough to be
// worth surfacing. An event with no judgeable features scores 0.
func (b *Baseline) Rarity(e *model.Event) float64 {
	highest := 0.0
	for _, f := range featuresOf(e) {
		if r := rarity(b.counts(f.cat)[f.key]); r > highest {
			highest = r
		}
	}
	return highest
}

// rarity maps a feature's observation count to a suspicion score in (0,1]:
// 0→1.0 (never seen), 1→0.5, 3→0.33, 7→0.25 — a smooth, count-driven decay.
func rarity(count uint64) float64 {
	return 1.0 / (1.0 + math.Log2(float64(1+count)))
}

// ensureInitialized fills nil maps after a baseline is loaded from JSON with a
// missing section, so Observe and Rarity never panic on a partial file.
func (b *Baseline) ensureInitialized() {
	if b.Executable == nil {
		b.Executable = make(map[string]uint64)
	}
	if b.ParentChild == nil {
		b.ParentChild = make(map[string]uint64)
	}
	if b.DestPort == nil {
		b.DestPort = make(map[string]uint64)
	}
	if b.UserProcess == nil {
		b.UserProcess = make(map[string]uint64)
	}
}
