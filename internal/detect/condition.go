// Package detect evaluates events against behavioural rules and correlates the
// resulting alerts into incidents.
package detect

import (
	"fmt"

	"github.com/argus-edr/argus/internal/model"
	"gopkg.in/yaml.v3"
)

// Condition is a node in a rule's match tree. A node is exactly one of: an `all`
// group (AND), an `any` group (OR), a `not` (negation), or a leaf comparison
// (field/op/value). Groups nest to any depth.
type Condition struct {
	All []*Condition
	Any []*Condition
	Not *Condition

	Field string
	Op    string
	Value any

	predicate func(*model.Event) bool
}

type conditionYAML struct {
	All   []*Condition `yaml:"all"`
	Any   []*Condition `yaml:"any"`
	Not   *Condition   `yaml:"not"`
	Field string       `yaml:"field"`
	Op    string       `yaml:"op"`
	Value any          `yaml:"value"`
}

// UnmarshalYAML reads the polymorphic node into the condition's raw fields;
// validation and predicate compilation happen later in Compile.
func (c *Condition) UnmarshalYAML(node *yaml.Node) error {
	var raw conditionYAML
	if err := node.Decode(&raw); err != nil {
		return err
	}
	c.All, c.Any, c.Not = raw.All, raw.Any, raw.Not
	c.Field, c.Op, c.Value = raw.Field, raw.Op, raw.Value
	return nil
}

// Compile validates the shape of the (sub)tree and builds the fast predicate
// used at evaluation time. Errors here surface bad rules at load, not at runtime.
func (c *Condition) Compile() error {
	kind, err := c.classify()
	if err != nil {
		return err
	}
	switch kind {
	case kindAll:
		if err := compileChildren(c.All); err != nil {
			return err
		}
		c.predicate = c.evalAll
	case kindAny:
		if err := compileChildren(c.Any); err != nil {
			return err
		}
		c.predicate = c.evalAny
	case kindNot:
		if err := c.Not.Compile(); err != nil {
			return err
		}
		c.predicate = c.evalNot
	default:
		leaf, err := compileLeaf(c.Field, c.Op, c.Value)
		if err != nil {
			return err
		}
		c.predicate = leaf
	}
	return nil
}

// Eval reports whether the event satisfies the condition.
func (c *Condition) Eval(event *model.Event) bool {
	return c.predicate(event)
}

type conditionKind int

const (
	kindLeaf conditionKind = iota
	kindAll
	kindAny
	kindNot
)

func (c *Condition) classify() (conditionKind, error) {
	kinds := make([]conditionKind, 0, 1)
	if len(c.All) > 0 {
		kinds = append(kinds, kindAll)
	}
	if len(c.Any) > 0 {
		kinds = append(kinds, kindAny)
	}
	if c.Not != nil {
		kinds = append(kinds, kindNot)
	}
	if c.Field != "" || c.Op != "" {
		kinds = append(kinds, kindLeaf)
	}
	if len(kinds) != 1 {
		return 0, fmt.Errorf("condition must be exactly one of all/any/not/leaf, found %d", len(kinds))
	}
	return kinds[0], nil
}

func compileChildren(children []*Condition) error {
	for _, child := range children {
		if err := child.Compile(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Condition) evalAll(event *model.Event) bool {
	for _, child := range c.All {
		if !child.predicate(event) {
			return false
		}
	}
	return true
}

func (c *Condition) evalAny(event *model.Event) bool {
	for _, child := range c.Any {
		if child.predicate(event) {
			return true
		}
	}
	return false
}

func (c *Condition) evalNot(event *model.Event) bool {
	return !c.Not.predicate(event)
}
