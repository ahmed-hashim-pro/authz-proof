package schema

import (
	"fmt"
	"strings"
)

type tokKind int

const (
	tEOF tokKind = iota
	tNL
	tIdent
	tPunct
)

type token struct {
	kind tokKind
	text string
	line int
	pos  int // byte offset, for slicing the source of an expression
}

func lex(src string) ([]token, error) {
	var out []token
	line := 1
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '\n':
			out = append(out, token{tNL, "\n", line, i})
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case strings.HasPrefix(src[i:], "//"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return nil, &Error{line, "unterminated comment"}
			}
			line += strings.Count(src[i:i+2+end], "\n")
			i += end + 4
		case strings.HasPrefix(src[i:], "->"):
			out = append(out, token{tPunct, "->", line, i})
			i += 2
		case strings.ContainsRune("{}():|#*+&-=.,", rune(c)):
			out = append(out, token{tPunct, string(c), line, i})
			i++
		case isIdentByte(c):
			j := i
			for j < len(src) && (isIdentByte(src[j]) || src[j] == '/') {
				j++
			}
			out = append(out, token{tIdent, src[i:j], line, i})
			i = j
		default:
			return nil, &Error{line, fmt.Sprintf("unexpected character %q", c)}
		}
	}
	out = append(out, token{tEOF, "", line, len(src)})
	return out, nil
}

func isIdentByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

type parser struct {
	src   string
	toks  []token
	i     int
	mixed bool // the expression being parsed mixes operators without parentheses
}

func (p *parser) peek() token { return p.toks[p.i] }
func (p *parser) next() token { t := p.toks[p.i]; p.i++; return t }

func (p *parser) skipNL() {
	for p.peek().kind == tNL {
		p.i++
	}
}

func (p *parser) errf(t token, format string, args ...any) error {
	return &Error{t.line, fmt.Sprintf(format, args...)}
}

func (p *parser) expect(text string) (token, error) {
	t := p.next()
	if t.text != text || t.kind == tIdent && text != t.text {
		return t, p.errf(t, "expected %q, found %s", text, describe(t))
	}
	return t, nil
}

func (p *parser) ident(what string) (token, error) {
	t := p.next()
	if t.kind != tIdent {
		return t, p.errf(t, "expected %s, found %s", what, describe(t))
	}
	return t, nil
}

func describe(t token) string {
	switch t.kind {
	case tEOF:
		return "end of file"
	case tNL:
		return "end of line"
	}
	return fmt.Sprintf("%q", t.text)
}

// Parse parses and validates a schema.
func Parse(src string) (*Schema, error) {
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{src: src, toks: toks}
	s := &Schema{byDef: map[string]*Definition{}}
	defLine := map[*Definition]int{}
	for {
		p.skipNL()
		t := p.peek()
		if t.kind == tEOF {
			break
		}
		if t.text == "caveat" {
			return nil, p.errf(t, "caveats are not supported")
		}
		if t.text != "definition" {
			return nil, p.errf(t, "expected \"definition\", found %s", describe(t))
		}
		p.next()
		name, err := p.ident("a definition name")
		if err != nil {
			return nil, err
		}
		d := &Definition{Name: name.text, names: map[string]any{}}
		if s.byDef[d.Name] != nil {
			return nil, p.errf(name, "definition %s is defined twice", d.Name)
		}
		s.byDef[d.Name] = d
		s.Defs = append(s.Defs, d)
		defLine[d] = name.line
		if _, err := p.expect("{"); err != nil {
			return nil, err
		}
		if err := p.body(d); err != nil {
			return nil, err
		}
	}
	if err := s.validate(defLine); err != nil {
		return nil, err
	}
	return s, nil
}

func (p *parser) body(d *Definition) error {
	for {
		p.skipNL()
		t := p.next()
		switch t.text {
		case "}":
			return nil
		case "relation":
			r, err := p.relation(t)
			if err != nil {
				return err
			}
			if d.names[r.Name] != nil {
				return p.errf(t, "%s#%s is defined twice", d.Name, r.Name)
			}
			d.names[r.Name] = r
			d.Relations = append(d.Relations, r)
		case "permission":
			pm, err := p.permission(t)
			if err != nil {
				return err
			}
			if d.names[pm.Name] != nil {
				return p.errf(t, "%s#%s is defined twice", d.Name, pm.Name)
			}
			d.names[pm.Name] = pm
			d.Perms = append(d.Perms, pm)
		default:
			return p.errf(t, "expected \"relation\", \"permission\" or \"}\", found %s", describe(t))
		}
	}
}

func (p *parser) endStatement() error {
	t := p.peek()
	if t.kind == tNL {
		p.next()
		return nil
	}
	if t.text == "}" {
		// SpiceDB wants a line break before the closing brace.
		return p.errf(t, "expected end of line before \"}\"")
	}
	return p.errf(t, "expected end of line, found %s", describe(t))
}

func (p *parser) relation(kw token) (*Relation, error) {
	name, err := p.ident("a relation name")
	if err != nil {
		return nil, err
	}
	r := &Relation{Name: name.text, Line: kw.line}
	if _, err := p.expect(":"); err != nil {
		return nil, err
	}
	for {
		tt, err := p.ident("a subject type")
		if err != nil {
			return nil, err
		}
		a := Allowed{Type: tt.text}
		switch p.peek().text {
		case ":":
			p.next()
			if _, err := p.expect("*"); err != nil {
				return nil, err
			}
			a.Wildcard = true
		case "#":
			p.next()
			rt, err := p.ident("a relation name")
			if err != nil {
				return nil, err
			}
			a.Relation = rt.text
		}
		if p.peek().text == "with" {
			return nil, p.errf(p.peek(), "caveats are not supported")
		}
		r.Allowed = append(r.Allowed, a)
		if p.peek().text != "|" {
			break
		}
		p.next()
	}
	return r, p.endStatement()
}

func (p *parser) permission(kw token) (*Permission, error) {
	name, err := p.ident("a permission name")
	if err != nil {
		return nil, err
	}
	if _, err := p.expect("="); err != nil {
		return nil, err
	}
	start := p.peek().pos
	p.mixed = false
	e, _, err := p.exclusion(0)
	if err != nil {
		return nil, err
	}
	end := p.peek().pos
	pm := &Permission{Name: name.text, Expr: e, Line: kw.line, Source: strings.TrimSpace(p.src[start:end]), Mixed: p.mixed}
	return pm, p.endStatement()
}

// SpiceDB's precedence, loosest first: exclusion, intersection, union,
// then arrows. All three are left-associative, so `a - b + c` is
// `a - (b + c)` and `a - b - c` is `(a - b) - c`.

func (p *parser) exclusion(depth int) (Expr, bool, error) {
	return p.binary(depth, "-", Exclusion, p.intersection)
}

func (p *parser) intersection(depth int) (Expr, bool, error) {
	return p.binary(depth, "&", Intersection, p.union)
}

func (p *parser) union(depth int) (Expr, bool, error) {
	return p.binary(depth, "+", Union, p.arrow)
}

// binary parses operand (op operand)*. It reports whether the result is a
// bare operand that was parenthesised, so callers can tell `(a + b) - c`
// from `a + b - c`.
func (p *parser) binary(depth int, sym string, kind OpKind, operand func(int) (Expr, bool, error)) (Expr, bool, error) {
	first, paren, err := operand(depth)
	if err != nil {
		return nil, false, err
	}
	args := []Expr{first}
	parens := []bool{paren}
	for {
		if depth > 0 {
			p.skipNL()
		}
		if p.peek().text != sym {
			break
		}
		p.next()
		p.skipNL()
		e, pr, err := operand(depth)
		if err != nil {
			return nil, false, err
		}
		args = append(args, e)
		parens = append(parens, pr)
	}
	if len(args) == 1 {
		return first, paren, nil
	}
	for i, a := range args {
		if o, ok := a.(*Op); ok && o.Kind != kind && !parens[i] {
			p.mixed = true
		}
	}
	if kind != Exclusion {
		return &Op{Kind: kind, Args: args}, false, nil
	}
	e := args[0]
	for _, a := range args[1:] {
		e = &Op{Kind: Exclusion, Args: []Expr{e, a}}
	}
	return e, false, nil
}

func (p *parser) arrow(depth int) (Expr, bool, error) {
	t := p.peek()
	if t.text == "(" {
		p.next()
		p.skipNL()
		e, _, err := p.exclusion(depth + 1)
		if err != nil {
			return nil, false, err
		}
		p.skipNL()
		if _, err := p.expect(")"); err != nil {
			return nil, false, err
		}
		return e, true, nil
	}
	name, err := p.ident("a relation or permission name")
	if err != nil {
		return nil, false, err
	}
	if name.text == "nil" {
		return nil, false, p.errf(name, "nil is not supported")
	}
	if p.peek().text != "->" {
		if p.peek().text == "." {
			return nil, false, p.errf(p.peek(), "arrow functions (.any/.all) are not supported")
		}
		return Ref{name.text}, false, nil
	}
	p.next()
	target, err := p.ident("a relation or permission name after ->")
	if err != nil {
		return nil, false, err
	}
	if p.peek().text == "->" || p.peek().text == "." {
		return nil, false, p.errf(p.peek(), "chained arrows and arrow functions are not supported")
	}
	return Arrow{name.text, target.text}, false, nil
}
