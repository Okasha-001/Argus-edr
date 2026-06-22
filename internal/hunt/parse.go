package hunt

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/argus-edr/argus/internal/model"
)

// ARQL grammar (recursive descent):
//
//	query     := sequence | simple
//	simple    := class ("where" expr)? ("|" pipe)*
//	sequence  := "sequence" ("by" field)? ("within" duration)? ":" stage (";" stage)+
//	stage     := class ("where" expr)?
//	pipe      := "where" expr | "limit" int
//	class     := IDENT                 // an action verb, or "event"/"any" for all
//	expr      := or ; or := and ("or" and)* ; and := unary ("and" unary)*
//	unary     := "not" unary | "(" expr ")" | comparison
//	comparison:= field (op value | "in" "(" value ("," value)* ")")
//	op        := "==" "!=" ">" "<" ">=" "<=" "=~" "contains" "startswith" "endswith"
//	field     := IDENT("."IDENT)*      // validated against model.KnownField
//	value     := STRING | NUMBER | IDENT

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokString
	tokNumber
	tokDuration
	tokOp
	tokPipe
	tokLParen
	tokRParen
	tokComma
	tokColon
	tokSemicolon
)

type token struct {
	kind tokenKind
	text string
}

func lex(src string) ([]token, error) {
	var tokens []token
	runes := []rune(src)
	for pos := 0; pos < len(runes); {
		ch := runes[pos]
		switch {
		case unicode.IsSpace(ch):
			pos++
		case ch == '"' || ch == '\'':
			text, next, err := lexString(runes, pos)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token{tokString, text})
			pos = next
		case unicode.IsDigit(ch):
			tok, next := lexNumber(runes, pos)
			tokens = append(tokens, tok)
			pos = next
		case isIdentStart(ch):
			text, next := lexWhile(runes, pos, isIdentPart)
			tokens = append(tokens, token{tokIdent, text})
			pos = next
		default:
			tok, next, err := lexSymbol(runes, pos)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, tok)
			pos = next
		}
	}
	return append(tokens, token{tokEOF, ""}), nil
}

func lexString(runes []rune, pos int) (string, int, error) {
	quote := runes[pos]
	var sb strings.Builder
	for i := pos + 1; i < len(runes); i++ {
		if runes[i] == '\\' && i+1 < len(runes) {
			sb.WriteRune(runes[i+1])
			i++
			continue
		}
		if runes[i] == quote {
			return sb.String(), i + 1, nil
		}
		sb.WriteRune(runes[i])
	}
	return "", 0, fmt.Errorf("unterminated string literal")
}

func lexNumber(runes []rune, pos int) (token, int) {
	text, next := lexWhile(runes, pos, func(r rune) bool { return unicode.IsDigit(r) || r == '.' })
	// A number immediately followed by a unit letter is a duration (5m, 30s, 1h).
	if next < len(runes) && isDurationUnit(runes[next]) {
		unit, after := lexWhile(runes, next, isDurationUnit)
		return token{tokDuration, text + unit}, after
	}
	return token{tokNumber, text}, next
}

func lexSymbol(runes []rune, pos int) (token, int, error) {
	two := ""
	if pos+1 < len(runes) {
		two = string(runes[pos : pos+2])
	}
	switch two {
	case "==", "!=", ">=", "<=", "=~":
		return token{tokOp, two}, pos + 2, nil
	}
	switch runes[pos] {
	case '>', '<':
		return token{tokOp, string(runes[pos])}, pos + 1, nil
	case '|':
		return token{tokPipe, "|"}, pos + 1, nil
	case '(':
		return token{tokLParen, "("}, pos + 1, nil
	case ')':
		return token{tokRParen, ")"}, pos + 1, nil
	case ',':
		return token{tokComma, ","}, pos + 1, nil
	case ':':
		return token{tokColon, ":"}, pos + 1, nil
	case ';':
		return token{tokSemicolon, ";"}, pos + 1, nil
	}
	return token{}, 0, fmt.Errorf("unexpected character %q", string(runes[pos]))
}

func lexWhile(runes []rune, pos int, keep func(rune) bool) (string, int) {
	start := pos
	for pos < len(runes) && keep(runes[pos]) {
		pos++
	}
	return string(runes[start:pos]), pos
}

func isIdentStart(r rune) bool { return unicode.IsLetter(r) || r == '_' }
func isIdentPart(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.'
}
func isDurationUnit(r rune) bool {
	return r == 's' || r == 'm' || r == 'h' || r == 'd'
}

// parser is a single-pass recursive-descent parser over the token slice.
type parser struct {
	tokens []token
	pos    int
}

func parse(source string) (*Query, error) {
	tokens, err := lex(source)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	query, err := p.parseQuery()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %q after query", p.peek().text)
	}
	query.source = source
	return query, nil
}

func (p *parser) peek() token { return p.tokens[p.pos] }
func (p *parser) next() token { tok := p.tokens[p.pos]; p.pos++; return tok }
func (p *parser) isKeyword(word string) bool {
	return p.peek().kind == tokIdent && p.peek().text == word
}

func (p *parser) parseQuery() (*Query, error) {
	if p.isKeyword("sequence") {
		seq, err := p.parseSequence()
		if err != nil {
			return nil, err
		}
		return &Query{seq: seq}, nil
	}
	simple, err := p.parseSimple()
	if err != nil {
		return nil, err
	}
	return &Query{simple: simple}, nil
}

func (p *parser) parseSimple() (*simpleQuery, error) {
	class, err := p.parseClass()
	if err != nil {
		return nil, err
	}
	simple := &simpleQuery{class: class}
	if p.isKeyword("where") {
		p.next()
		if simple.filter, err = p.parseExpr(); err != nil {
			return nil, err
		}
	}
	for p.peek().kind == tokPipe {
		p.next()
		pipe, err := p.parsePipe()
		if err != nil {
			return nil, err
		}
		simple.pipes = append(simple.pipes, pipe)
	}
	return simple, nil
}

func (p *parser) parsePipe() (pipe, error) {
	switch {
	case p.isKeyword("where"):
		p.next()
		filter, err := p.parseExpr()
		return pipe{filter: filter}, err
	case p.isKeyword("limit"):
		p.next()
		if p.peek().kind != tokNumber {
			return pipe{}, fmt.Errorf("limit expects a number, got %q", p.peek().text)
		}
		n, err := strconv.Atoi(p.next().text)
		if err != nil {
			return pipe{}, fmt.Errorf("invalid limit: %w", err)
		}
		return pipe{limit: n, hasLimit: true}, nil
	default:
		return pipe{}, fmt.Errorf("expected 'where' or 'limit' after '|', got %q", p.peek().text)
	}
}

func (p *parser) parseSequence() (*sequenceQuery, error) {
	p.next() // consume "sequence"
	seq := &sequenceQuery{}
	if p.isKeyword("by") {
		p.next()
		field, err := p.parseField()
		if err != nil {
			return nil, err
		}
		seq.by = field
	}
	if p.isKeyword("within") {
		p.next()
		within, err := p.parseDuration()
		if err != nil {
			return nil, err
		}
		seq.within = within
	}
	if p.peek().kind != tokColon {
		return nil, fmt.Errorf("expected ':' before sequence stages, got %q", p.peek().text)
	}
	p.next()
	for {
		stage, err := p.parseStage()
		if err != nil {
			return nil, err
		}
		seq.stages = append(seq.stages, stage)
		if p.peek().kind != tokSemicolon {
			break
		}
		p.next()
	}
	if len(seq.stages) < 2 {
		return nil, fmt.Errorf("a sequence needs at least two stages separated by ';'")
	}
	return seq, nil
}

func (p *parser) parseStage() (stage, error) {
	class, err := p.parseClass()
	if err != nil {
		return stage{}, err
	}
	st := stage{class: class}
	if p.isKeyword("where") {
		p.next()
		if st.filter, err = p.parseExpr(); err != nil {
			return stage{}, err
		}
	}
	return st, nil
}

func (p *parser) parseClass() (classRef, error) {
	if p.peek().kind != tokIdent {
		return classRef{}, fmt.Errorf("expected an event class, got %q", p.peek().text)
	}
	name := p.next().text
	if name == "event" || name == "any" {
		return classRef{all: true}, nil
	}
	return classRef{action: name}, nil
}

func (p *parser) parseExpr() (expr, error) { return p.parseOr() }

func (p *parser) parseOr() (expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("or") {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orExpr{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.isKeyword("and") {
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andExpr{left, right}
	}
	return left, nil
}

func (p *parser) parseUnary() (expr, error) {
	if p.isKeyword("not") {
		p.next()
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notExpr{inner}, nil
	}
	if p.peek().kind == tokLParen {
		p.next()
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("expected ')', got %q", p.peek().text)
		}
		p.next()
		return inner, nil
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() (expr, error) {
	field, err := p.parseField()
	if err != nil {
		return nil, err
	}
	if p.isKeyword("in") {
		p.next()
		return p.parseIn(field)
	}
	op, err := p.parseOperator()
	if err != nil {
		return nil, err
	}
	val, err := p.parseValue()
	if err != nil {
		return nil, err
	}
	cmp := comparison{field: field, op: op, value: val}
	if op == "=~" {
		re, err := regexp.Compile(val.str)
		if err != nil {
			return nil, fmt.Errorf("invalid regular expression %q: %w", val.str, err)
		}
		cmp.re = re
	}
	return cmp, nil
}

func (p *parser) parseIn(field string) (expr, error) {
	if p.peek().kind != tokLParen {
		return nil, fmt.Errorf("expected '(' after 'in', got %q", p.peek().text)
	}
	p.next()
	cmp := comparison{field: field, op: "in"}
	for {
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		cmp.values = append(cmp.values, val)
		if p.peek().kind == tokComma {
			p.next()
			continue
		}
		break
	}
	if p.peek().kind != tokRParen {
		return nil, fmt.Errorf("expected ')' to close 'in' list, got %q", p.peek().text)
	}
	p.next()
	return cmp, nil
}

func (p *parser) parseOperator() (string, error) {
	if p.peek().kind == tokOp {
		return p.next().text, nil
	}
	if tok := p.peek(); tok.kind == tokIdent {
		switch tok.text {
		case "contains", "startswith", "endswith":
			return p.next().text, nil
		}
	}
	return "", fmt.Errorf("expected a comparison operator, got %q", p.peek().text)
}

func (p *parser) parseField() (string, error) {
	if p.peek().kind != tokIdent {
		return "", fmt.Errorf("expected a field name, got %q", p.peek().text)
	}
	field := p.next().text
	if !model.KnownField(field) {
		return "", fmt.Errorf("unknown field %q", field)
	}
	return field, nil
}

func (p *parser) parseValue() (value, error) {
	tok := p.next()
	switch tok.kind {
	case tokString:
		return value{str: tok.text}, nil
	case tokNumber:
		num, err := strconv.ParseFloat(tok.text, 64)
		if err != nil {
			return value{}, fmt.Errorf("invalid number %q: %w", tok.text, err)
		}
		return value{str: tok.text, num: num, isNum: true}, nil
	case tokIdent:
		return value{str: tok.text}, nil
	default:
		return value{}, fmt.Errorf("expected a value, got %q", tok.text)
	}
}

func (p *parser) parseDuration() (time.Duration, error) {
	tok := p.next()
	switch tok.kind {
	case tokDuration:
		return time.ParseDuration(tok.text)
	case tokNumber:
		secs, err := strconv.Atoi(tok.text)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", tok.text, err)
		}
		return time.Duration(secs) * time.Second, nil
	default:
		return 0, fmt.Errorf("expected a duration (e.g. 5m), got %q", tok.text)
	}
}
