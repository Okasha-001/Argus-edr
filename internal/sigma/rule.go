package sigma

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// techniqueDoc, condDoc and ruleDoc mirror the rule schema that
// internal/detect.LoadDir consumes, so a converted Sigma rule marshals straight
// into a file the agent and the fleet can load unchanged. Keep these tags in
// sync with internal/detect/loader.go and condition.go.
type techniqueDoc struct {
	ID     string `yaml:"id,omitempty"`
	Name   string `yaml:"name,omitempty"`
	Tactic string `yaml:"tactic,omitempty"`
}

// condDoc is one node of the ARGUS match tree: exactly one of an all/any/not
// group or a field/op/value leaf. It is the serialisable twin of
// detect.Condition.
type condDoc struct {
	All []*condDoc `yaml:"all,omitempty"`
	Any []*condDoc `yaml:"any,omitempty"`
	Not *condDoc   `yaml:"not,omitempty"`

	Field string `yaml:"field,omitempty"`
	Op    string `yaml:"op,omitempty"`
	Value any    `yaml:"value,omitempty"`
}

type ruleDoc struct {
	ID          string        `yaml:"id"`
	Name        string        `yaml:"name"`
	Description string        `yaml:"description,omitempty"`
	Severity    string        `yaml:"severity"`
	Technique   *techniqueDoc `yaml:"technique,omitempty"`
	RiskScore   int           `yaml:"risk_score,omitempty"`
	Match       *condDoc      `yaml:"match"`
}

// Rule is a Sigma detection compiled into the ARGUS rule format.
type Rule struct {
	doc ruleDoc
}

// ID is the generated ARGUS rule id (SIGMA-XXXXXXXX).
func (r *Rule) ID() string { return r.doc.ID }

// Name is the rule's human title, carried over from the Sigma rule.
func (r *Rule) Name() string { return r.doc.Name }

// MarshalRules renders the rules as a single YAML document — a sequence of rule
// objects, exactly the shape internal/detect expects in a *.yaml rule file.
func MarshalRules(rules []*Rule) ([]byte, error) {
	docs := make([]ruleDoc, len(rules))
	for i, rule := range rules {
		docs[i] = rule.doc
	}
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(docs); err != nil {
		return nil, err
	}
	_ = encoder.Close()
	return buf.Bytes(), nil
}

func leaf(field, op string, value any) *condDoc {
	return &condDoc{Field: field, Op: op, Value: value}
}

// allOf and anyOf collapse a single child to itself so the emitted tree carries
// no redundant one-element groups.
func allOf(children ...*condDoc) *condDoc {
	if len(children) == 1 {
		return children[0]
	}
	return &condDoc{All: children}
}

func anyOf(children ...*condDoc) *condDoc {
	if len(children) == 1 {
		return children[0]
	}
	return &condDoc{Any: children}
}
