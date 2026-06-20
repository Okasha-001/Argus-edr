package anomaly

import "math"

// Isolation Forest, after Liu, Ting & Zhou (2008). An anomaly is "few and
// different", so a random partitioning isolates it in fewer splits than a normal
// point. We build many random trees on small subsamples; the mean path length to
// isolate a point becomes its score. This is a deliberately small implementation
// — a few hundred lines of arithmetic, no dependencies — fit for an EDR hot path.

// eulerGamma is the Euler–Mascheroni constant, used in the expected-path-length
// normalization c(n).
const eulerGamma = 0.5772156649015329

// defaultTrees and defaultSubsample are the canonical iForest hyperparameters.
const (
	defaultTrees     = 100
	defaultSubsample = 256
)

// iTree is a node of an isolation tree: either an internal split on one feature
// or an external (leaf) node carrying the subsample size that reached it.
type iTree struct {
	Feature int     `json:"f,omitempty"`
	Split   float64 `json:"s,omitempty"`
	Left    *iTree  `json:"l,omitempty"`
	Right   *iTree  `json:"r,omitempty"`
	Size    int     `json:"n,omitempty"`
}

// IsolationForest is an ensemble of isolation trees plus the subsample size used
// to build them (needed to normalize path lengths at scoring time).
type IsolationForest struct {
	Trees      []*iTree `json:"trees"`
	SampleSize int      `json:"sample_size"`
}

// rng is the minimal random source the forest needs; math/rand satisfies it. A
// caller injects a seeded one for reproducible training and tests.
type rng interface {
	Intn(n int) int
	Float64() float64
}

// BuildForest trains an Isolation Forest on samples. Trees and subsample default
// to the canonical 100/256 when non-positive. Returns nil if there is no data.
func BuildForest(samples [][]float64, numTrees, subsample int, source rng) *IsolationForest {
	if len(samples) == 0 {
		return nil
	}
	if numTrees <= 0 {
		numTrees = defaultTrees
	}
	if subsample <= 0 {
		subsample = defaultSubsample
	}
	if subsample > len(samples) {
		subsample = len(samples)
	}
	maxDepth := int(math.Ceil(math.Log2(float64(subsample))))
	if maxDepth < 1 {
		maxDepth = 1
	}

	forest := &IsolationForest{SampleSize: subsample, Trees: make([]*iTree, 0, numTrees)}
	for t := 0; t < numTrees; t++ {
		forest.Trees = append(forest.Trees, buildTree(subsampleOf(samples, subsample, source), 0, maxDepth, source))
	}
	return forest
}

// subsampleOf draws size points uniformly at random (with replacement, which is
// adequate for isolation and keeps the draw allocation-light).
func subsampleOf(samples [][]float64, size int, source rng) [][]float64 {
	out := make([][]float64, size)
	for i := range out {
		out[i] = samples[source.Intn(len(samples))]
	}
	return out
}

func buildTree(samples [][]float64, depth, maxDepth int, source rng) *iTree {
	if depth >= maxDepth || len(samples) <= 1 {
		return &iTree{Size: len(samples)}
	}
	feature := source.Intn(featureDim)
	low, high := featureRange(samples, feature)
	if low == high {
		return &iTree{Size: len(samples)}
	}
	split := low + source.Float64()*(high-low)

	var left, right [][]float64
	for _, s := range samples {
		if s[feature] < split {
			left = append(left, s)
		} else {
			right = append(right, s)
		}
	}
	return &iTree{
		Feature: feature,
		Split:   split,
		Left:    buildTree(left, depth+1, maxDepth, source),
		Right:   buildTree(right, depth+1, maxDepth, source),
	}
}

func featureRange(samples [][]float64, feature int) (low, high float64) {
	low, high = samples[0][feature], samples[0][feature]
	for _, s := range samples {
		if s[feature] < low {
			low = s[feature]
		}
		if s[feature] > high {
			high = s[feature]
		}
	}
	return low, high
}

// Score returns the raw isolation score in (0,1): ~0.5 for a typical point,
// approaching 1 for an easily isolated (anomalous) one.
func (f *IsolationForest) Score(vector []float64) float64 {
	if f == nil || len(f.Trees) == 0 || len(vector) != featureDim {
		return 0
	}
	total := 0.0
	for _, tree := range f.Trees {
		total += pathLength(tree, vector, 0)
	}
	mean := total / float64(len(f.Trees))
	return math.Pow(2, -mean/expectedPathLength(f.SampleSize))
}

// NormalizedScore rescales the raw score so a normal point is ~0 and a clearly
// anomalous one approaches 1, matching the Baseline's [0,1] convention.
func (f *IsolationForest) NormalizedScore(vector []float64) float64 {
	normalized := (f.Score(vector) - 0.5) * 2
	if normalized < 0 {
		return 0
	}
	return normalized
}

func pathLength(node *iTree, vector []float64, depth int) float64 {
	if node.Left == nil && node.Right == nil {
		return float64(depth) + expectedPathLength(node.Size)
	}
	if vector[node.Feature] < node.Split {
		return pathLength(node.Left, vector, depth+1)
	}
	return pathLength(node.Right, vector, depth+1)
}

// expectedPathLength c(n): the average path length of an unsuccessful search in a
// binary search tree of n points, used to normalize tree depth across sizes.
func expectedPathLength(n int) float64 {
	if n <= 1 {
		return 0
	}
	return 2*(math.Log(float64(n-1))+eulerGamma) - 2*float64(n-1)/float64(n)
}
