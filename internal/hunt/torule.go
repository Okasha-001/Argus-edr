package hunt

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// RuleMeta is the metadata an analyst supplies when promoting a saved hunt to a
// detection rule. The match tree is derived from the query itself, so the rule
// fires on exactly what the hunt found — closing the loop between hunting the
// unknown (Phase 14) and codifying it as a rule (Phase 16).
type RuleMeta struct {
	ID          string
	Name        string
	Description string
	Severity    string
	RiskScore   int
	Response    string
	Technique   Technique
}

// Technique is the ATT&CK mapping carried on a generated rule.
type Technique struct {
	ID     string
	Name   string
	Tactic string
}

// ruleCond mirrors internal/detect's polymorphic match node so a converted hunt
// serialises to the exact YAML the rule loader expects. omitempty keeps a leaf
// from emitting empty all/any/not keys, which the loader rejects as ambiguous.
type ruleCond struct {
	All   []*ruleCond `yaml:"all,omitempty"`
	Any   []*ruleCond `yaml:"any,omitempty"`
	Not   *ruleCond   `yaml:"not,omitempty"`
	Field string      `yaml:"field,omitempty"`
	Op    string      `yaml:"op,omitempty"`
	Value any         `yaml:"value,omitempty"`
}

// ruleDoc is one detection rule in the YAML shape internal/detect.LoadDir reads.
type ruleDoc struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Description string    `yaml:"description,omitempty"`
	Severity    string    `yaml:"severity"`
	RiskScore   int       `yaml:"risk_score,omitempty"`
	Response    string    `yaml:"response,omitempty"`
	Technique   techDoc   `yaml:"technique"`
	Match       *ruleCond `yaml:"match"`
}

type techDoc struct {
	ID     string `yaml:"id,omitempty"`
	Name   string `yaml:"name,omitempty"`
	Tactic string `yaml:"tactic,omitempty"`
}

// ToRule converts a simple ARQL query into a detection rule and returns the YAML
// a rule file expects (a one-element list). Sequence queries describe a temporal
// chain a single per-event rule cannot express, so they are rejected with a
// clear error rather than silently producing a rule that means something else.
func (q *Query) ToRule(meta RuleMeta) ([]byte, error) {
	if q.seq != nil {
		return nil, fmt.Errorf("a sequence hunt cannot become a single rule; save its first stage or use correlation")
	}
	if meta.ID == "" || meta.Name == "" {
		return nil, fmt.Errorf("a rule needs an id and a name")
	}
	doc := ruleDoc{
		ID: meta.ID, Name: meta.Name, Description: meta.Description,
		Severity: meta.Severity, RiskScore: meta.RiskScore, Response: meta.Response,
		Technique: techDoc(meta.Technique),
		Match:     q.matchTree(),
	}
	out, err := yaml.Marshal([]ruleDoc{doc})
	if err != nil {
		return nil, fmt.Errorf("marshal rule: %w", err)
	}
	return out, nil
}

// matchTree builds the rule's match condition: the class verb as an event.type
// guard (unless the query matched any class), ANDed with the where filter and
// every pipe filter. A single condition is emitted bare; several are wrapped in
// an `all` group, matching how rules are hand-written.
func (q *Query) matchTree() *ruleCond {
	var conds []*ruleCond
	if !q.simple.class.all {
		conds = append(conds, &ruleCond{Field: "event.type", Op: "eq", Value: q.simple.class.action})
	}
	if q.simple.filter != nil {
		conds = append(conds, q.simple.filter.toCond())
	}
	for _, p := range q.simple.pipes {
		if p.filter != nil {
			conds = append(conds, p.filter.toCond())
		}
	}
	switch len(conds) {
	case 0:
		// `any where` with no predicate: match every event of any class. exists on
		// a field that is always present is the rule engine's "match anything".
		return &ruleCond{Field: "event.action", Op: "exists"}
	case 1:
		return conds[0]
	default:
		return &ruleCond{All: conds}
	}
}

func (e andExpr) toCond() *ruleCond {
	return &ruleCond{All: flatten(e, func(x expr) (expr, expr, bool) {
		a, ok := x.(andExpr)
		return a.left, a.right, ok
	})}
}

func (e orExpr) toCond() *ruleCond {
	return &ruleCond{Any: flatten(e, func(x expr) (expr, expr, bool) {
		o, ok := x.(orExpr)
		return o.left, o.right, ok
	})}
}

func (e notExpr) toCond() *ruleCond { return &ruleCond{Not: e.inner.toCond()} }

func (c comparison) toCond() *ruleCond {
	leaf := &ruleCond{Field: c.field, Op: ruleOps[c.op]}
	switch c.op {
	case "in":
		values := make([]any, len(c.values))
		for i, v := range c.values {
			values[i] = v.literal()
		}
		leaf.Value = values
	default:
		leaf.Value = c.value.literal()
	}
	return leaf
}

// ruleOps maps ARQL operators to the detection engine's operator names. The
// engine accepts the word operators (contains/startswith/endswith/in) verbatim;
// the symbolic ones translate.
var ruleOps = map[string]string{
	"==": "eq", "!=": "ne",
	">": "gt", "<": "lt", ">=": "ge", "<=": "le",
	"=~":         "regex",
	"contains":   "contains",
	"startswith": "startswith",
	"endswith":   "endswith",
	"in":         "in",
}

// literal returns a YAML-friendly value: a number stays numeric so a rule reads
// `value: 4444`, everything else is a string.
func (v value) literal() any {
	if v.isNum {
		if v.num == float64(int64(v.num)) {
			return int64(v.num)
		}
		return v.num
	}
	return v.str
}

// flatten collapses a right-leaning chain of the same binary operator into a
// single list, so `a and b and c` yields three siblings rather than nested
// pairs — the readable shape a human writes by hand.
func flatten(e expr, split func(expr) (expr, expr, bool)) []*ruleCond {
	left, right, ok := split(e)
	if !ok {
		return []*ruleCond{e.toCond()}
	}
	return append(flatten(left, split), flatten(right, split)...)
}
