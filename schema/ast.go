// Package schema parses and checks a subset of the SpiceDB schema language:
// definitions, relations with allowed subject types (direct, wildcard and
// subject sets), and permissions built from union (+), intersection (&),
// exclusion (-) and arrows (->), with SpiceDB's operator precedence.
package schema

import (
	"fmt"
	"strings"
)

// Schema is a parsed, validated schema.
type Schema struct {
	Defs  []*Definition
	byDef map[string]*Definition
	// Order lists every relation and permission so that each node's
	// dependencies come before it, except inside a strongly connected
	// group, where the members depend on each other only positively.
	Order [][]Node
	// Warnings are things SpiceDB accepts that are probably not what the
	// author meant: mixed operators without parentheses, arrows to a name
	// no target type has.
	Warnings []string
}

// Definition is one object type.
type Definition struct {
	Name      string
	Relations []*Relation
	Perms     []*Permission
	names     map[string]any
}

// Relation is a stored relation and the subject types it may hold.
type Relation struct {
	Name    string
	Allowed []Allowed
	Line    int
}

// Allowed is one allowed subject type: `user`, `user:*` or `team#member`.
type Allowed struct {
	Type     string
	Relation string
	Wildcard bool
}

func (a Allowed) String() string {
	switch {
	case a.Wildcard:
		return a.Type + ":*"
	case a.Relation != "":
		return a.Type + "#" + a.Relation
	}
	return a.Type
}

// Permission is a computed permission.
type Permission struct {
	Name string
	Expr Expr
	Line int
	// Source is the expression as written.
	Source string
	// Mixed is set when the expression combines different operators
	// without parentheses, so its meaning rests on precedence.
	Mixed bool
}

// Node names one relation or permission of one type.
type Node struct{ Type, Name string }

func (n Node) String() string { return n.Type + "#" + n.Name }

// Expr is a permission expression.
type Expr interface {
	String() string
	isExpr()
}

// Ref names a relation or permission on the same object.
type Ref struct{ Name string }

// Arrow follows Tupleset to each related object and takes Target there.
type Arrow struct{ Tupleset, Target string }

// OpKind is the kind of a set operation.
type OpKind int

const (
	Union OpKind = iota
	Intersection
	Exclusion
)

func (k OpKind) Symbol() string { return [...]string{"+", "&", "-"}[k] }

func (k OpKind) Word() string { return [...]string{"union", "intersection", "exclusion"}[k] }

// Op is a set operation. Union and intersection take two or more
// arguments; exclusion takes exactly two, Args[0] - Args[1].
type Op struct {
	Kind OpKind
	Args []Expr
}

func (Ref) isExpr()   {}
func (Arrow) isExpr() {}
func (*Op) isExpr()   {}

func (r Ref) String() string   { return r.Name }
func (a Arrow) String() string { return a.Tupleset + "->" + a.Target }

// String prints the expression with a parenthesis around every nested
// operation, so it reads the same under any precedence rules.
func (o *Op) String() string {
	parts := make([]string, len(o.Args))
	for i, a := range o.Args {
		if _, ok := a.(*Op); ok {
			parts[i] = "(" + a.String() + ")"
		} else {
			parts[i] = a.String()
		}
	}
	return strings.Join(parts, " "+o.Kind.Symbol()+" ")
}

// Def returns the named definition, or nil.
func (s *Schema) Def(name string) *Definition { return s.byDef[name] }

// Relation returns the named relation of d, or nil.
func (d *Definition) Relation(name string) *Relation {
	r, _ := d.names[name].(*Relation)
	return r
}

// Permission returns the named permission of d, or nil.
func (d *Definition) Permission(name string) *Permission {
	p, _ := d.names[name].(*Permission)
	return p
}

// Has reports whether d has a relation or permission with this name.
func (d *Definition) Has(name string) bool { _, ok := d.names[name]; return ok }

// Names lists d's relations then permissions, in source order.
func (d *Definition) Names() []string {
	var out []string
	for _, r := range d.Relations {
		out = append(out, r.Name)
	}
	for _, p := range d.Perms {
		out = append(out, p.Name)
	}
	return out
}

// Has reports whether type t has a relation or permission called name.
func (s *Schema) Has(t, name string) bool {
	d := s.byDef[t]
	return d != nil && d.Has(name)
}

// DirectTypes lists the types whose objects can be members of some
// relation directly or by wildcard: the only types a check can succeed
// for.
func (s *Schema) DirectTypes() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range s.Defs {
		for _, r := range d.Relations {
			for _, a := range r.Allowed {
				if a.Relation == "" && !seen[a.Type] {
					seen[a.Type] = true
					out = append(out, a.Type)
				}
			}
		}
	}
	return out
}

// Error is a schema error with its line.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}
