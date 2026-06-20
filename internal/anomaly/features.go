// Package anomaly scores events for rarity and structural outlierness in
// userspace, so ARGUS can flag the unknown, not only what a rule names. It has
// two independent layers: frequency-based rarity baselining and a lightweight
// Isolation Forest. Neither touches the kernel ABI — scoring is pure Go over a
// model.Event, inserted between enrichment and detection.
package anomaly

import (
	"math"
	"strconv"
	"strings"

	"github.com/argus-edr/argus/internal/model"
)

// category enumerates the behavioural dimensions whose historical frequency the
// baseline tracks. A value rarely seen on a given dimension is suspicious.
type category int

const (
	catExecutable category = iota
	catParentChild
	catDestPort
	catUserProcess
)

// feature is one categorical observation drawn from an event.
type feature struct {
	cat category
	key string
}

// featuresOf returns the categorical observations present in an event. Empty or
// zero dimensions are skipped so an event is judged only on what it actually
// carries (an exec has no destination port; a bare connect has no executable).
func featuresOf(e *model.Event) []feature {
	var features []feature
	if e.Process.Executable != "" {
		features = append(features, feature{catExecutable, e.Process.Executable})
	}
	if e.Process.Name != "" {
		parent := e.Process.ParentName
		if parent == "" {
			parent = "?"
		}
		features = append(features, feature{catParentChild, parent + ">" + e.Process.Name})
		features = append(features, feature{catUserProcess, strconv.FormatUint(uint64(e.User.ID), 10) + ">" + e.Process.Name})
	}
	if e.Network.DstPort != 0 {
		features = append(features, feature{catDestPort, strconv.Itoa(int(e.Network.DstPort))})
	}
	return features
}

// hasFeatures reports whether an event carries anything the baseline can judge.
func hasFeatures(e *model.Event) bool {
	return e.Process.Executable != "" || e.Process.Name != "" || e.Network.DstPort != 0
}

// featureVector projects an event onto the fixed numeric vector the Isolation
// Forest splits on. Order is stable: a saved forest and a live event must agree.
func featureVector(e *model.Event) []float64 {
	return []float64{
		float64(len(e.Process.Name)),
		float64(len(e.Process.CommandLine)),
		float64(len(e.Process.Args)),
		float64(e.Timestamp.UTC().Hour()),
		float64(e.Network.DstPort),
		float64(e.User.ID),
		float64(pathDepth(e.Process.Executable)),
		shannonEntropy(e.Process.Name),
	}
}

// featureDim is the length of featureVector; kept as a constant so the forest can
// validate vectors without an example event.
const featureDim = 8

func pathDepth(path string) int {
	if path == "" {
		return 0
	}
	return strings.Count(path, "/")
}

// shannonEntropy is the per-character entropy (bits) of s — high for random or
// packed names, low for ordinary command names.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
