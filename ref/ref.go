// Package ref is the reference evaluator the engine is tested against. It
// is deliberately naive: it computes every relation and permission of
// every object for every subject, by repeating rounds until nothing
// changes, one group of mutually dependent nodes at a time. It shares no
// code with the engine beyond the schema and relationship types.
package ref

import (
	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

// Fact is one (resource, name, subject) triple that holds.
type Fact struct {
	Resource rel.Object
	Name     string
	Subject  rel.Object
}

// Model is the full set of facts for one schema and relationships.
type Model struct {
	Facts    map[Fact]bool
	Subjects []rel.Object
}

// Compute evaluates everything. subjects is the set of subjects to
// evaluate for, normally rel.Universe.
func Compute(s *schema.Schema, st *rel.Store, subjects []rel.Object) *Model {
	m := &Model{Facts: map[Fact]bool{}, Subjects: subjects}
	for _, group := range s.Order {
		for changed := true; changed; {
			changed = false
			for _, n := range group {
				for _, obj := range st.Objects(n.Type) {
					for _, sub := range subjects {
						f := Fact{obj, n.Name, sub}
						if m.Facts[f] {
							continue
						}
						if m.holds(s, st, obj, n.Name, sub) {
							m.Facts[f] = true
							changed = true
						}
					}
				}
			}
		}
	}
	return m
}

// holds applies one node's rule once, reading other nodes from the facts
// found so far.
func (m *Model) holds(s *schema.Schema, st *rel.Store, obj rel.Object, name string, sub rel.Object) bool {
	d := s.Def(obj.Type)
	if d.Relation(name) != nil {
		for _, t := range st.Subjects(obj, name) {
			switch {
			case t.ID == "*":
				if t.Type == sub.Type {
					return true
				}
			case t.Relation == "":
				if t.Object == sub {
					return true
				}
			default:
				if m.Facts[Fact{t.Object, t.Relation, sub}] {
					return true
				}
			}
		}
		return false
	}
	return m.expr(s, st, obj, d.Permission(name).Expr, sub)
}

func (m *Model) expr(s *schema.Schema, st *rel.Store, obj rel.Object, e schema.Expr, sub rel.Object) bool {
	switch e := e.(type) {
	case schema.Ref:
		return m.Facts[Fact{obj, e.Name, sub}]
	case schema.Arrow:
		for _, t := range st.Subjects(obj, e.Tupleset) {
			if m.Facts[Fact{t.Object, e.Target, sub}] {
				return true
			}
		}
		return false
	case *schema.Op:
		vals := make([]bool, len(e.Args))
		for i, a := range e.Args {
			vals[i] = m.expr(s, st, obj, a, sub)
		}
		switch e.Kind {
		case schema.Union:
			for _, v := range vals {
				if v {
					return true
				}
			}
			return false
		case schema.Intersection:
			for _, v := range vals {
				if !v {
					return false
				}
			}
			return true
		default:
			return vals[0] && !vals[1]
		}
	}
	return false
}

// Has reports whether a fact holds.
func (m *Model) Has(resource rel.Object, name string, subject rel.Object) bool {
	return m.Facts[Fact{resource, name, subject}]
}
