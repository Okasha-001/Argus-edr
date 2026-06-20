package yara

import "fmt"

// parser is a cursor over YARA-subset source. The grammar is small enough that a
// hand-written recursive-descent parser over the raw text (rather than a separate
// lexer) is the clearest fit — it lets hex blocks and string literals own their
// braces and quotes without confusing the tokenizer.
type parser struct {
	src string
	pos int
}

func (p *parser) eof() bool { return p.pos >= len(p.src) }

func (p *parser) peekChar() byte {
	if p.pos < len(p.src) {
		return p.src[p.pos]
	}
	return 0
}

func (p *parser) charAt(i int) byte {
	if i >= 0 && i < len(p.src) {
		return p.src[i]
	}
	return 0
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("yara: "+format+" (at offset %d)", append(a, p.pos)...)
}

func (p *parser) skipSpace() {
	for p.pos < len(p.src) {
		switch c := p.src[p.pos]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.pos++
		case c == '/' && p.charAt(p.pos+1) == '/':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case c == '/' && p.charAt(p.pos+1) == '*':
			p.pos += 2
			for p.pos < len(p.src) && (p.peekChar() != '*' || p.charAt(p.pos+1) != '/') {
				p.pos++
			}
			p.pos += 2
		default:
			return
		}
	}
}

func (p *parser) parseIdent() string {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		isAlpha := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isDigit := c >= '0' && c <= '9'
		if isAlpha || (p.pos > start && isDigit) {
			p.pos++
		} else {
			break
		}
	}
	return p.src[start:p.pos]
}

// acceptKeyword consumes the keyword if it is the next identifier; otherwise it
// leaves the cursor untouched and returns false.
func (p *parser) acceptKeyword(kw string) bool {
	save := p.pos
	p.skipSpace()
	if p.parseIdent() == kw {
		return true
	}
	p.pos = save
	return false
}

// atSectionHeader reports whether the cursor sits on a `name:` section header,
// used to stop entry-list parsing (meta/strings) without consuming the header.
func (p *parser) atSectionHeader() bool {
	save := p.pos
	defer func() { p.pos = save }()
	p.skipSpace()
	id := p.parseIdent()
	p.skipSpace()
	return id != "" && p.peekChar() == ':'
}

func (p *parser) parseRule() (*rule, error) {
	if !p.acceptKeyword("rule") {
		return nil, p.errf("expected 'rule'")
	}
	p.skipSpace()
	name := p.parseIdent()
	if name == "" {
		return nil, p.errf("expected rule name")
	}
	p.skipSpace()
	if p.peekChar() == ':' { // optional tag list
		p.pos++
		for {
			p.skipSpace()
			if p.peekChar() == '{' || p.parseIdent() == "" {
				break
			}
		}
	}
	p.skipSpace()
	if p.peekChar() != '{' {
		return nil, p.errf("expected '{' to open rule %q", name)
	}
	p.pos++

	r := &rule{name: name, meta: map[string]string{}}
	for {
		p.skipSpace()
		if p.peekChar() == '}' {
			p.pos++
			break
		}
		if p.eof() {
			return nil, p.errf("unterminated rule %q", name)
		}
		section := p.parseIdent()
		p.skipSpace()
		if p.peekChar() != ':' {
			return nil, p.errf("expected ':' after section %q", section)
		}
		p.pos++

		var err error
		switch section {
		case "meta":
			err = p.parseMeta(r)
		case "strings":
			err = p.parseStrings(r)
		case "condition":
			r.cond, err = p.parseCondition()
		default:
			return nil, p.errf("unknown section %q", section)
		}
		if err != nil {
			return nil, err
		}
	}
	if r.cond == nil {
		return nil, p.errf("rule %q has no condition", name)
	}
	return r, nil
}

func (p *parser) parseMeta(r *rule) error {
	for {
		if p.atSectionHeader() {
			return nil
		}
		p.skipSpace()
		if p.peekChar() == '}' {
			return nil
		}
		key := p.parseIdent()
		if key == "" {
			return p.errf("expected meta key")
		}
		p.skipSpace()
		if p.peekChar() != '=' {
			return p.errf("expected '=' after meta key %q", key)
		}
		p.pos++
		p.skipSpace()
		if p.peekChar() == '"' {
			v, err := p.parseString()
			if err != nil {
				return err
			}
			r.meta[key] = string(v)
		} else {
			r.meta[key] = p.parseBareWord()
		}
	}
}

func (p *parser) parseStrings(r *rule) error {
	for {
		if p.atSectionHeader() {
			return nil
		}
		p.skipSpace()
		if p.peekChar() == '}' {
			return nil
		}
		if p.peekChar() != '$' {
			return p.errf("expected a $string identifier")
		}
		pat := pattern{id: p.parseStringID()}
		p.skipSpace()
		if p.peekChar() != '=' {
			return p.errf("expected '=' after %s", pat.id)
		}
		p.pos++
		p.skipSpace()
		switch p.peekChar() {
		case '"':
			text, err := p.parseString()
			if err != nil {
				return err
			}
			pat.text = true
			pat.bytes = bytesToHex(text)
			pat.nocase = p.parseStringModifiers()
		case '{':
			hx, err := p.parseHex()
			if err != nil {
				return err
			}
			pat.bytes = hx
		default:
			return p.errf("expected a \"text\" or { hex } value for %s", pat.id)
		}
		if len(pat.bytes) == 0 {
			return p.errf("empty pattern %s", pat.id)
		}
		r.patterns = append(r.patterns, pat)
	}
}

func (p *parser) parseStringID() string {
	start := p.pos
	p.pos++ // '$'
	p.parseIdent()
	return p.src[start:p.pos]
}

func (p *parser) parseStringModifiers() bool {
	nocase := false
	for {
		save := p.pos
		p.skipSpace()
		switch p.parseIdent() {
		case "nocase":
			nocase = true
		case "ascii", "wide", "fullword", "private":
			// accepted for compatibility; no effect in this subset
		default:
			p.pos = save
			return nocase
		}
	}
}

func (p *parser) parseString() ([]byte, error) {
	p.pos++ // opening quote
	var out []byte
	for {
		if p.eof() {
			return nil, p.errf("unterminated string")
		}
		c := p.src[p.pos]
		switch c {
		case '"':
			p.pos++
			return out, nil
		case '\\':
			p.pos++
			esc, err := p.parseEscape()
			if err != nil {
				return nil, err
			}
			out = append(out, esc)
		default:
			out = append(out, c)
			p.pos++
		}
	}
}

func (p *parser) parseEscape() (byte, error) {
	if p.eof() {
		return 0, p.errf("dangling escape")
	}
	c := p.src[p.pos]
	p.pos++
	switch c {
	case 'n':
		return '\n', nil
	case 't':
		return '\t', nil
	case 'r':
		return '\r', nil
	case '\\':
		return '\\', nil
	case '"':
		return '"', nil
	case 'x':
		hi, lo := hexVal(p.charAt(p.pos)), hexVal(p.charAt(p.pos+1))
		if hi < 0 || lo < 0 {
			return 0, p.errf("bad \\x escape")
		}
		p.pos += 2
		return byte(hi<<4 | lo), nil
	default:
		return 0, p.errf("unknown escape \\%c", c)
	}
}

func (p *parser) parseHex() ([]hexByte, error) {
	p.pos++ // '{'
	var out []hexByte
	for {
		p.skipSpace()
		if p.eof() {
			return nil, p.errf("unterminated hex string")
		}
		if p.peekChar() == '}' {
			p.pos++
			return out, nil
		}
		if p.peekChar() == '?' {
			if p.charAt(p.pos+1) != '?' {
				return nil, p.errf("only full-byte '??' wildcards are supported")
			}
			out = append(out, hexByte{wild: true})
			p.pos += 2
			continue
		}
		hi, lo := hexVal(p.charAt(p.pos)), hexVal(p.charAt(p.pos+1))
		if hi < 0 || lo < 0 {
			return nil, p.errf("invalid hex byte")
		}
		out = append(out, hexByte{value: byte(hi<<4 | lo)})
		p.pos += 2
	}
}

func (p *parser) parseBareWord() string {
	start := p.pos
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case ' ', '\t', '\n', '\r':
			return p.src[start:p.pos]
		}
		p.pos++
	}
	return p.src[start:p.pos]
}

// --- condition: or > and > not > primary ---

func (p *parser) parseCondition() (condition, error) { return p.parseOr() }

func (p *parser) parseOr() (condition, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.acceptKeyword("or") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = orNode{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (condition, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.acceptKeyword("and") {
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = andNode{left, right}
	}
	return left, nil
}

func (p *parser) parseUnary() (condition, error) {
	if p.acceptKeyword("not") {
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (condition, error) {
	p.skipSpace()
	switch c := p.peekChar(); {
	case c == '(':
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.peekChar() != ')' {
			return nil, p.errf("expected ')'")
		}
		p.pos++
		return inner, nil
	case c == '$':
		return identNode{p.parseStringID()}, nil
	case c >= '0' && c <= '9':
		return p.parseQuantifier(p.parseNumber())
	}
	switch word := p.parseIdent(); word {
	case "true":
		return boolNode{true}, nil
	case "false":
		return boolNode{false}, nil
	case "all":
		return p.parseQuantifier(-1)
	case "any":
		return p.parseQuantifier(0)
	default:
		return nil, p.errf("unexpected token %q in condition", word)
	}
}

// parseQuantifier finishes an "<n> of them" expression; need<0 means all, 0 any.
func (p *parser) parseQuantifier(need int) (condition, error) {
	if !p.acceptKeyword("of") {
		return nil, p.errf("expected 'of'")
	}
	if !p.acceptKeyword("them") {
		return nil, p.errf("expected 'them' (only 'of them' is supported)")
	}
	return quantNode{need: need}, nil
}

func (p *parser) parseNumber() int {
	n := 0
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		n = n*10 + int(p.src[p.pos]-'0')
		p.pos++
	}
	return n
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func bytesToHex(b []byte) []hexByte {
	out := make([]hexByte, len(b))
	for i, c := range b {
		out[i] = hexByte{value: c}
	}
	return out
}
