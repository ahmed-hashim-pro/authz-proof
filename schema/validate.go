package schema

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// SpiceDB's own name rules. Being stricter than SpiceDB would reject real
// schemas; being looser would accept schemas SpiceDB refuses.
var (
	nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}[a-z0-9]$`)
	typeRE = regexp.MustCompile(`^([a-z][a-z0-9_]{1,62}[a-z0-9]/)*[a-z][a-z0-9_]{1,62}[a-z0-9]$`)
)

type edge struct {
	to       Node
	negative bool // the target is subtracted, directly or further down
}

func (s *Schema) validate(defLine map[*Definition]int) error {
	for _, d := range s.Defs {
		if !typeRE.MatchString(d.Name) {
			return &Error{defLine[d], fmt.Sprintf("definition name %q must match %s", d.Name, typeRE)}
		}
		for _, r := range d.Relations {
			if !nameRE.MatchString(r.Name) {
				return &Error{r.Line, fmt.Sprintf("relation name %q must match %s", r.Name, nameRE)}
			}
			for _, a := range r.Allowed {
				t := s.byDef[a.Type]
				if t == nil {
					return &Error{r.Line, fmt.Sprintf("%s#%s allows %s, which is not defined", d.Name, r.Name, a)}
				}
				if a.Relation != "" && !t.Has(a.Relation) {
					return &Error{r.Line, fmt.Sprintf("%s#%s allows %s, but %s has no %s", d.Name, r.Name, a, a.Type, a.Relation)}
				}
			}
		}
		for _, p := range d.Perms {
			if !nameRE.MatchString(p.Name) {
				return &Error{p.Line, fmt.Sprintf("permission name %q must match %s", p.Name, nameRE)}
			}
			if err := s.checkExpr(d, p, p.Expr); err != nil {
				return err
			}
			if p.Mixed {
				s.Warnings = append(s.Warnings, fmt.Sprintf(
					"line %d: %s#%s mixes operators without parentheses: `%s` means `%s` (SpiceDB binds + before & before -)",
					p.Line, d.Name, p.Name, p.Source, p.Expr))
			}
		}
	}
	for _, d := range s.Defs {
		if err := permCycle(d); err != nil {
			return err
		}
		if err := s.wildcardSubjectSets(d); err != nil {
			return err
		}
	}
	return s.stratify()
}

// wildcardSubjectSets applies SpiceDB's rule that a relation may not allow
// a subject set on another definition whose members can come from a
// wildcard, through relations (a permission in between ends the search).
// SpiceDB does not apply the rule to subject sets on the same definition,
// so neither does this.
func (s *Schema) wildcardSubjectSets(d *Definition) error {
	for _, r := range d.Relations {
		for _, a := range r.Allowed {
			if a.Relation == "" || a.Type == d.Name || s.byDef[a.Type].Relation(a.Relation) == nil {
				continue
			}
			seen := map[Node]bool{}
			var find func(n Node) (Node, Allowed, bool)
			find = func(n Node) (Node, Allowed, bool) {
				if seen[n] {
					return Node{}, Allowed{}, false
				}
				seen[n] = true
				rr := s.byDef[n.Type].Relation(n.Name)
				if rr == nil {
					return Node{}, Allowed{}, false
				}
				for _, b := range rr.Allowed {
					if b.Wildcard {
						return n, b, true
					}
				}
				for _, b := range rr.Allowed {
					if b.Relation != "" {
						if m, w, ok := find(Node{b.Type, b.Relation}); ok {
							return m, w, true
						}
					}
				}
				return Node{}, Allowed{}, false
			}
			if via, w, ok := find(Node{a.Type, a.Relation}); ok {
				return &Error{r.Line, fmt.Sprintf(
					"%s#%s allows %s, which can include %s through %s; SpiceDB does not allow wildcards to be included through a subject set",
					d.Name, r.Name, a, w, via)}
			}
		}
	}
	return nil
}

// permCycle refuses permissions that are plain aliases of each other in a
// loop (`permission a = b`, `permission b = a`), as SpiceDB does. A
// permission that refers to itself inside a larger expression is fine:
// it has a least meaning, and SpiceDB accepts it too.
func permCycle(d *Definition) error {
	alias := func(name string) string {
		if p := d.Permission(name); p != nil {
			if r, ok := p.Expr.(Ref); ok && d.Permission(r.Name) != nil {
				return r.Name
			}
		}
		return ""
	}
	for _, p := range d.Perms {
		path := []string{p.Name}
		for next := alias(p.Name); next != ""; next = alias(next) {
			for i, q := range path {
				if q == next {
					if i != 0 {
						break // reported when the loop's own member is checked
					}
					return &Error{p.Line, fmt.Sprintf("permissions of %s are aliases of each other in a loop: %s -> %s",
						d.Name, strings.Join(path, " -> "), next)}
				}
			}
			if len(path) > len(d.Perms) {
				break
			}
			path = append(path, next)
		}
	}
	return nil
}

func (s *Schema) checkExpr(d *Definition, p *Permission, e Expr) error {
	switch e := e.(type) {
	case Ref:
		if !d.Has(e.Name) {
			return &Error{p.Line, fmt.Sprintf("%s#%s uses %s, which %s does not have", d.Name, p.Name, e.Name, d.Name)}
		}
	case Arrow:
		ts := d.Relation(e.Tupleset)
		if ts == nil {
			if d.Permission(e.Tupleset) != nil {
				return &Error{p.Line, fmt.Sprintf("%s#%s: permissions cannot be used on the left of an arrow (%s)", d.Name, p.Name, e)}
			}
			return &Error{p.Line, fmt.Sprintf("%s#%s uses %s, but %s has no relation %s", d.Name, p.Name, e, d.Name, e.Tupleset)}
		}
		found := false
		for _, a := range ts.Allowed {
			if a.Wildcard {
				return &Error{p.Line, fmt.Sprintf("%s#%s: %s#%s allows %s, and wildcard relations cannot be used on the left of an arrow", d.Name, p.Name, d.Name, ts.Name, a)}
			}
			if a.Relation != "" {
				return &Error{p.Line, fmt.Sprintf("%s#%s: arrows over a relation that allows subject sets (%s#%s allows %s) are not supported", d.Name, p.Name, d.Name, ts.Name, a)}
			}
			if s.byDef[a.Type].Has(e.Target) {
				found = true
			}
		}
		if !found {
			s.Warnings = append(s.Warnings, fmt.Sprintf(
				"line %d: %s#%s uses %s, but none of %s's types has %s, so it is always empty",
				p.Line, d.Name, p.Name, e, e.Tupleset, e.Target))
		}
	case *Op:
		for _, a := range e.Args {
			if err := s.checkExpr(d, p, a); err != nil {
				return err
			}
		}
	}
	return nil
}

// Edges lists what a node's members are computed from. A negative edge
// means the target is subtracted somewhere on the way.
func (s *Schema) edges(n Node) []edge {
	d := s.byDef[n.Type]
	var out []edge
	if r := d.Relation(n.Name); r != nil {
		for _, a := range r.Allowed {
			if a.Relation != "" {
				out = append(out, edge{Node{a.Type, a.Relation}, false})
			}
		}
		return out
	}
	var walk func(e Expr, neg bool)
	walk = func(e Expr, neg bool) {
		switch e := e.(type) {
		case Ref:
			out = append(out, edge{Node{n.Type, e.Name}, neg})
		case Arrow:
			out = append(out, edge{Node{n.Type, e.Tupleset}, neg})
			for _, a := range d.Relation(e.Tupleset).Allowed {
				if s.byDef[a.Type].Has(e.Target) {
					out = append(out, edge{Node{a.Type, e.Target}, neg})
				}
			}
		case *Op:
			for i, a := range e.Args {
				walk(a, neg || e.Kind == Exclusion && i == 1)
			}
		}
	}
	walk(d.Permission(n.Name).Expr, false)
	return out
}

// stratify finds the strongly connected groups of the dependency graph,
// orders them so dependencies come first, and refuses a schema where a
// node depends on itself through a subtraction: "you may view unless you
// may view" has no single meaning.
func (s *Schema) stratify() error {
	var nodes []Node
	for _, d := range s.Defs {
		for _, name := range d.Names() {
			nodes = append(nodes, Node{d.Name, name})
		}
	}
	index := map[Node]int{}
	low := map[Node]int{}
	onStack := map[Node]bool{}
	var stack []Node
	counter := 0
	var groups [][]Node
	var strong func(v Node)
	strong = func(v Node) {
		index[v] = counter
		low[v] = counter
		counter++
		stack = append(stack, v)
		onStack[v] = true
		for _, e := range s.edges(v) {
			if _, seen := index[e.to]; !seen {
				strong(e.to)
				low[v] = min(low[v], low[e.to])
			} else if onStack[e.to] {
				low[v] = min(low[v], index[e.to])
			}
		}
		if low[v] == index[v] {
			var g []Node
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				g = append(g, w)
				if w == v {
					break
				}
			}
			groups = append(groups, g)
		}
	}
	for _, v := range nodes {
		if _, seen := index[v]; !seen {
			strong(v)
		}
	}
	for _, g := range groups {
		in := map[Node]bool{}
		for _, v := range g {
			in[v] = true
		}
		for _, v := range g {
			for _, e := range s.edges(v) {
				if e.negative && in[e.to] {
					names := make([]string, len(g))
					for i, w := range g {
						names[i] = w.String()
					}
					sort.Strings(names)
					return &Error{0, fmt.Sprintf(
						"%s subtracts %s, which depends on %s again (cycle through %s); a permission cannot depend on itself through an exclusion",
						v, e.to, v, strings.Join(names, ", "))}
				}
			}
		}
	}
	// Tarjan emits a group only after every group it reaches.
	s.Order = groups
	return nil
}
