// Package yara is a small, dependency-free engine for a practical subset of the
// YARA rule language. It exists so ARGUS can ship signature-based file detection
// without a cgo dependency on libyara — keeping the golden rule that the Go build
// needs no C toolchain (the agent still loads the eBPF object at runtime).
//
// Supported subset (enough for real malware/webshell signatures):
//   - text strings:  $a = "evil" [nocase]
//   - hex strings:   $b = { 4D 5A ?? 00 }      (?? is a wildcard byte)
//   - conditions:    $a, and / or / not, parentheses, true/false,
//                    and the quantifiers "all of them", "any of them", "N of them".
//
// Anything outside the subset is a compile error, so a rule never silently
// matches nothing. Scanning is plain substring/byte-pattern search — O(n*m) — which
// is fine for the bounded file slices the agent feeds it.
package yara

import "fmt"

// Engine is a compiled, immutable set of rules. Scan is safe for concurrent use.
type Engine struct {
	rules []*rule
}

type rule struct {
	name     string
	meta     map[string]string
	patterns []pattern
	cond     condition
}

type pattern struct {
	id     string // "$a"
	bytes  []hexByte
	nocase bool // text strings only
	text   bool // true: text string; false: hex string
}

// hexByte is one position in a pattern: a concrete value, or a wildcard that
// matches any byte (from a "??" in a hex string).
type hexByte struct {
	value byte
	wild  bool
}

// Rules compiles YARA-subset source into an Engine.
func Compile(source string) (*Engine, error) {
	p := &parser{src: source}
	var rules []*rule
	for {
		p.skipSpace()
		if p.eof() {
			break
		}
		r, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("yara: no rules found")
	}
	return &Engine{rules: rules}, nil
}

// Scan returns the names of every rule whose condition matches data, in rule
// order. A nil/empty result means nothing matched.
func (e *Engine) Scan(data []byte) []string {
	if e == nil || len(data) == 0 {
		return nil
	}
	var matched []string
	for _, r := range e.rules {
		hits := make(map[string]bool, len(r.patterns))
		count := 0
		for _, pat := range r.patterns {
			if patternMatches(pat, data) {
				hits[pat.id] = true
				count++
			}
		}
		if r.cond.eval(hits, len(r.patterns), count) {
			matched = append(matched, r.name)
		}
	}
	return matched
}

func patternMatches(pat pattern, data []byte) bool {
	n, m := len(data), len(pat.bytes)
	if m == 0 || m > n {
		return false
	}
	for start := 0; start+m <= n; start++ {
		if matchAt(pat, data[start:start+m]) {
			return true
		}
	}
	return false
}

func matchAt(pat pattern, window []byte) bool {
	for i, hb := range pat.bytes {
		if hb.wild {
			continue
		}
		got := window[i]
		if pat.nocase {
			if fold(got) != fold(hb.value) {
				return false
			}
		} else if got != hb.value {
			return false
		}
	}
	return true
}

func fold(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// --- condition AST ---

type condition interface {
	eval(hits map[string]bool, total, count int) bool
}

type identNode struct{ id string }

func (n identNode) eval(hits map[string]bool, _, _ int) bool { return hits[n.id] }

type boolNode struct{ v bool }

func (n boolNode) eval(map[string]bool, int, int) bool { return n.v }

type notNode struct{ inner condition }

func (n notNode) eval(hits map[string]bool, total, count int) bool {
	return !n.inner.eval(hits, total, count)
}

type andNode struct{ left, right condition }

func (n andNode) eval(hits map[string]bool, total, count int) bool {
	return n.left.eval(hits, total, count) && n.right.eval(hits, total, count)
}

type orNode struct{ left, right condition }

func (n orNode) eval(hits map[string]bool, total, count int) bool {
	return n.left.eval(hits, total, count) || n.right.eval(hits, total, count)
}

// quantNode is "all of them" (need == -1), "any of them" (need == 0 meaning >=1),
// or "N of them" (need == N).
type quantNode struct{ need int }

func (n quantNode) eval(_ map[string]bool, total, count int) bool {
	switch {
	case n.need < 0: // all
		return count == total
	case n.need == 0: // any
		return count >= 1
	default:
		return count >= n.need
	}
}
