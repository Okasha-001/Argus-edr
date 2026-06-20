package sigma

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// compileDetection turns a Sigma `detection:` block into one ARGUS condition.
// Every key but `condition` is a named search-identifier (a selection); the
// `condition` expression combines them with and/or/not and `N of` quantifiers.
func compileDetection(detection map[string]yaml.Node) (*condDoc, error) {
	conditionNode, ok := detection["condition"]
	if !ok {
		return nil, errors.New("detection block has no condition")
	}
	expression, err := conditionExpression(conditionNode)
	if err != nil {
		return nil, err
	}

	selections := make(map[string]*condDoc, len(detection))
	names := make([]string, 0, len(detection))
	for name, node := range detection {
		if name == "condition" {
			continue
		}
		selection, err := compileSelection(node)
		if err != nil {
			return nil, fmt.Errorf("selection %q: %w", name, err)
		}
		selections[name] = selection
		names = append(names, name)
	}
	if len(selections) == 0 {
		return nil, errors.New("detection block has no selections")
	}
	sort.Strings(names)

	return parseCondition(expression, selections, names)
}

// conditionExpression reads the `condition` value, which Sigma allows to be a
// single expression or a list of expressions that are OR-ed together.
func conditionExpression(node yaml.Node) (string, error) {
	var single string
	if err := node.Decode(&single); err == nil {
		return single, nil
	}
	var list []string
	if err := node.Decode(&list); err == nil && len(list) > 0 {
		parenthesised := make([]string, len(list))
		for i, expression := range list {
			parenthesised[i] = "(" + expression + ")"
		}
		return strings.Join(parenthesised, " or "), nil
	}
	return "", errors.New("condition must be a string or a non-empty list of strings")
}

// compileSelection compiles one search-identifier. A map of field→value is an
// AND of its fields; a list of maps is an OR of those (Sigma list semantics).
func compileSelection(node yaml.Node) (*condDoc, error) {
	switch node.Kind {
	case yaml.MappingNode:
		return selectionMap(node)
	case yaml.SequenceNode:
		alternatives := make([]*condDoc, 0, len(node.Content))
		for _, item := range node.Content {
			if item.Kind != yaml.MappingNode {
				return nil, &UnsupportedError{Reason: "keyword (full-text) selections"}
			}
			alternative, err := selectionMap(*item)
			if err != nil {
				return nil, err
			}
			alternatives = append(alternatives, alternative)
		}
		return anyOf(alternatives...), nil
	default:
		return nil, &UnsupportedError{Reason: "selection that is neither a map nor a list of maps"}
	}
}

// selectionMap compiles a field→value map into an AND of per-field conditions.
// Keys are sorted so the emitted rule is deterministic regardless of YAML order.
func selectionMap(node yaml.Node) (*condDoc, error) {
	type fieldEntry struct {
		key   string
		value *yaml.Node
	}
	entries := make([]fieldEntry, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		entries = append(entries, fieldEntry{key: node.Content[i].Value, value: node.Content[i+1]})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	leaves := make([]*condDoc, 0, len(entries))
	for _, entry := range entries {
		condition, err := fieldCondition(entry.key, entry.value)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, condition)
	}
	if len(leaves) == 0 {
		return nil, errors.New("empty selection")
	}
	return allOf(leaves...), nil
}

// fieldCondition compiles one `Field|modifiers: value(s)` entry. A list of
// values is OR-ed by default, or AND-ed when the `|all` modifier is present.
func fieldCondition(rawKey string, valueNode *yaml.Node) (*condDoc, error) {
	parts := strings.Split(rawKey, "|")
	field, ok := argusField(parts[0])
	if !ok {
		return nil, &UnsupportedError{Reason: fmt.Sprintf("field %q", parts[0])}
	}
	op, requireAll, err := modifierOp(parts[1:])
	if err != nil {
		return nil, err
	}

	values, err := decodeValues(valueNode)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, &UnsupportedError{Reason: fmt.Sprintf("null/empty value for field %q", parts[0])}
	}

	leaves := make([]*condDoc, len(values))
	for i, value := range values {
		condition, err := valueLeaf(field, op, value)
		if err != nil {
			return nil, err
		}
		leaves[i] = condition
	}
	if requireAll {
		return allOf(leaves...), nil
	}
	return anyOf(leaves...), nil
}

// modifierOp reads a field's Sigma modifiers, returning the explicit operator
// (empty when it must be inferred from the value) and whether `|all` asks for
// every list value to match.
func modifierOp(modifiers []string) (op string, requireAll bool, err error) {
	for _, modifier := range modifiers {
		switch strings.ToLower(modifier) {
		case "all":
			requireAll = true
		case "contains", "startswith", "endswith":
			op = strings.ToLower(modifier)
		case "re":
			op = "regex"
		case "cidr":
			op = "cidr"
		default:
			return "", false, &UnsupportedError{Reason: fmt.Sprintf("value modifier %q", modifier)}
		}
	}
	return op, requireAll, nil
}

// valueLeaf builds a single leaf. With an explicit operator the value is used
// verbatim; otherwise the operator is inferred from Sigma `*`/`?` wildcards. The
// regex and CIDR operators are validated here so a converted rule that the loader
// would reject is caught at import time, not when the agent tries to load it.
func valueLeaf(field, op string, value any) (*condDoc, error) {
	if op == "" {
		if text, isString := value.(string); isString {
			op, value = inferStringOp(text)
		} else {
			op = "eq"
		}
	}
	if err := validateOperatorValue(op, value); err != nil {
		return nil, err
	}
	return leaf(field, op, value), nil
}

// validateOperatorValue rejects values the ARGUS loader could not compile, so a
// bad regex or CIDR in one Sigma rule fails just that rule rather than breaking
// the whole converted bundle.
func validateOperatorValue(op string, value any) error {
	switch op {
	case "regex":
		if _, err := regexp.Compile(textValue(value)); err != nil {
			return fmt.Errorf("invalid regex %q: %w", value, err)
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(textValue(value)); err != nil {
			return fmt.Errorf("invalid cidr %q: %w", value, err)
		}
	}
	return nil
}

func textValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

// inferStringOp turns a Sigma string value into an operator and cleaned value:
// edge `*` become startswith/endswith/contains; any interior `*` or `?` becomes
// an anchored regex; a plain string is an exact match.
func inferStringOp(value string) (op string, cleaned any) {
	hasLeading := strings.HasPrefix(value, "*")
	hasTrailing := strings.HasSuffix(value, "*")
	core := strings.Trim(value, "*")
	if strings.ContainsAny(core, "*?") {
		return "regex", wildcardToRegex(value)
	}
	switch {
	case hasLeading && hasTrailing:
		return "contains", core
	case hasLeading:
		return "endswith", core
	case hasTrailing:
		return "startswith", core
	default:
		return "eq", value
	}
}

// wildcardToRegex converts a Sigma wildcard pattern into an anchored regex,
// escaping regex metacharacters and mapping `*`→`.*` and `?`→`.`.
func wildcardToRegex(pattern string) string {
	const metacharacters = `\.+()|[]{}^$`
	var builder strings.Builder
	builder.WriteByte('^')
	for _, char := range pattern {
		switch char {
		case '*':
			builder.WriteString(".*")
		case '?':
			builder.WriteByte('.')
		default:
			if strings.ContainsRune(metacharacters, char) {
				builder.WriteByte('\\')
			}
			builder.WriteRune(char)
		}
	}
	builder.WriteByte('$')
	return builder.String()
}

// decodeValues reads a scalar or sequence node into a flat slice of values; a
// null node yields no values.
func decodeValues(node *yaml.Node) ([]any, error) {
	if node.Kind == yaml.SequenceNode {
		values := make([]any, 0, len(node.Content))
		for _, item := range node.Content {
			value, err := scalarValue(item)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	}
	if node.Tag == "!!null" {
		return nil, nil
	}
	value, err := scalarValue(node)
	if err != nil {
		return nil, err
	}
	return []any{value}, nil
}

func scalarValue(node *yaml.Node) (any, error) {
	var value any
	if err := node.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode value: %w", err)
	}
	return value, nil
}
