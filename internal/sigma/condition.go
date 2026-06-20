package sigma

import (
	"fmt"
	"strconv"
	"strings"
)

// parseCondition compiles a Sigma condition expression into an ARGUS condition
// tree, resolving each identifier to its compiled selection. It supports the
// common grammar: and / or / not, parentheses, and the `all of` / `1 of` /
// `any of` quantifiers over `them` or a `prefix*` pattern.
func parseCondition(expression string, selections map[string]*condDoc, names []string) (*condDoc, error) {
	parser := &conditionParser{
		tokens:     tokenize(expression),
		selections: selections,
		names:      names,
	}
	tree, err := parser.parseExpression()
	if err != nil {
		return nil, err
	}
	if parser.position != len(parser.tokens) {
		return nil, fmt.Errorf("unexpected token %q in condition %q", parser.tokens[parser.position], expression)
	}
	return tree, nil
}

type conditionParser struct {
	tokens     []string
	position   int
	selections map[string]*condDoc
	names      []string // selection names, sorted, for stable `of` expansion
}

// tokenize splits the expression on whitespace, treating parentheses as their
// own tokens. Selection names contain no spaces, so this is sufficient.
func tokenize(expression string) []string {
	expression = strings.ReplaceAll(expression, "(", " ( ")
	expression = strings.ReplaceAll(expression, ")", " ) ")
	return strings.Fields(expression)
}

func (p *conditionParser) parseExpression() (*condDoc, error) {
	return p.parseOr()
}

func (p *conditionParser) parseOr() (*condDoc, error) {
	terms, err := p.collectTerms("or", p.parseAnd)
	if err != nil {
		return nil, err
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return &condDoc{Any: terms}, nil
}

func (p *conditionParser) parseAnd() (*condDoc, error) {
	terms, err := p.collectTerms("and", p.parseNot)
	if err != nil {
		return nil, err
	}
	if len(terms) == 1 {
		return terms[0], nil
	}
	return &condDoc{All: terms}, nil
}

// collectTerms parses one operand, then repeatedly consumes `keyword operand`.
func (p *conditionParser) collectTerms(keyword string, operand func() (*condDoc, error)) ([]*condDoc, error) {
	first, err := operand()
	if err != nil {
		return nil, err
	}
	terms := []*condDoc{first}
	for p.consumeKeyword(keyword) {
		next, err := operand()
		if err != nil {
			return nil, err
		}
		terms = append(terms, next)
	}
	return terms, nil
}

func (p *conditionParser) parseNot() (*condDoc, error) {
	if p.consumeKeyword("not") {
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &condDoc{Not: inner}, nil
	}
	return p.parseAtom()
}

func (p *conditionParser) parseAtom() (*condDoc, error) {
	token := p.peek()
	switch {
	case token == "":
		return nil, fmt.Errorf("unexpected end of condition")
	case token == "(":
		return p.parseGroup()
	case isQuantifier(token):
		return p.parseQuantifier()
	default:
		p.advance()
		selection, ok := p.selections[token]
		if !ok {
			return nil, fmt.Errorf("condition references unknown selection %q", token)
		}
		return selection, nil
	}
}

func (p *conditionParser) parseGroup() (*condDoc, error) {
	p.advance() // consume '('
	inner, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	if !p.consumeToken(")") {
		return nil, fmt.Errorf("missing closing parenthesis in condition")
	}
	return inner, nil
}

// parseQuantifier handles `all of <pattern>`, `1 of <pattern>` and
// `any of <pattern>`. A count above one cannot be expressed in a boolean tree,
// so it is reported as unsupported rather than silently approximated.
func (p *conditionParser) parseQuantifier() (*condDoc, error) {
	quantifier := strings.ToLower(p.advance())
	if !p.consumeKeyword("of") {
		return nil, fmt.Errorf("expected 'of' after %q in condition", quantifier)
	}
	pattern := p.advance()
	if pattern == "" {
		return nil, fmt.Errorf("expected a pattern after 'of' in condition")
	}
	matched := p.selectionsMatching(pattern)
	if len(matched) == 0 {
		return nil, fmt.Errorf("condition pattern %q matched no selections", pattern)
	}

	switch quantifier {
	case "all":
		return allOf(matched...), nil
	case "1", "any":
		return anyOf(matched...), nil
	default:
		return nil, &UnsupportedError{Reason: fmt.Sprintf("quantifier %q of (only all/1/any are supported)", quantifier)}
	}
}

func (p *conditionParser) selectionsMatching(pattern string) []*condDoc {
	var matched []*condDoc
	for _, name := range p.names { // names is sorted, so output order is stable
		if patternMatches(name, pattern) {
			matched = append(matched, p.selections[name])
		}
	}
	return matched
}

func patternMatches(name, pattern string) bool {
	if strings.EqualFold(pattern, "them") {
		return true
	}
	if prefix, found := strings.CutSuffix(pattern, "*"); found {
		return strings.HasPrefix(name, prefix)
	}
	return name == pattern
}

func isQuantifier(token string) bool {
	lower := strings.ToLower(token)
	if lower == "all" || lower == "any" {
		return true
	}
	_, err := strconv.Atoi(token)
	return err == nil
}

func (p *conditionParser) peek() string {
	if p.position < len(p.tokens) {
		return p.tokens[p.position]
	}
	return ""
}

func (p *conditionParser) advance() string {
	token := p.peek()
	if token != "" {
		p.position++
	}
	return token
}

func (p *conditionParser) consumeKeyword(keyword string) bool {
	if strings.EqualFold(p.peek(), keyword) {
		p.position++
		return true
	}
	return false
}

func (p *conditionParser) consumeToken(token string) bool {
	if p.peek() == token {
		p.position++
		return true
	}
	return false
}
