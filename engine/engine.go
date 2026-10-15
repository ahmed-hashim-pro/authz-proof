// Package engine answers permission questions over a schema and a set of
// relationships: Check, LookupResources, LookupSubjects, Expand, and
// Explain, which finds the shortest chain of relationships behind a yes.
package engine

import (
	"math"

	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

// Mutant names a deliberate bug, for showing that the property tests
// would notice one. The zero value is the correct engine.
type Mutant string

const (
	Correct              Mutant = ""
	IntersectionAsUnion  Mutant = "intersection-as-union"
	WildcardAnyType      Mutant = "wildcard-any-type"
	ArrowFirstOnly       Mutant = "arrow-first-only"
	SubjectSetOneLevel   Mutant = "subject-set-one-level"
	MemoFalseInCycle     Mutant = "memo-false-in-cycle"
	VisitedNotPath       Mutant = "visited-not-path"
	DiffKnownSubjectOnly Mutant = "diff-known-subjects-only"
)

// Mutants lists every deliberate bug.
var Mutants = []Mutant{IntersectionAsUnion, WildcardAnyType, ArrowFirstOnly, SubjectSetOneLevel, MemoFalseInCycle, VisitedNotPath, DiffKnownSubjectOnly}

// Engine evaluates permissions over one schema and one set of
// relationships.
type Engine struct {
	Schema *schema.Schema
	Store  *rel.Store
	Mutant Mutant
	// sessions cache answers per subject; relationships never change
	// under an engine, so the cache is always valid.
	sessions map[rel.Object]*Session
}

// New returns an engine for s and st.
func New(s *schema.Schema, st *rel.Store) *Engine {
	return &Engine{Schema: s, Store: st, sessions: map[rel.Object]*Session{}}
}

type goal struct {
	obj  rel.Object
	name string
}

const none = math.MaxInt

// Session answers questions about one subject and remembers the answers.
type Session struct {
	e       *Engine
	subject rel.Object
	memo    map[goal]bool
	onPath  map[goal]int // goals being evaluated, by stack depth
	depth   int
	visited map[goal]bool // only for the visited-not-path mutant
}

// Session returns the session for subject, creating it on first use.
func (e *Engine) Session(subject rel.Object) *Session {
	if s := e.sessions[subject]; s != nil {
		return s
	}
	s := &Session{e: e, subject: subject, memo: map[goal]bool{}, onPath: map[goal]int{}}
	e.sessions[subject] = s
	return s
}

// Check reports whether subject has name (a relation or permission) on
// resource.
func (e *Engine) Check(resource rel.Object, name string, subject rel.Object) bool {
	return e.Session(subject).Check(resource, name)
}

// Check reports whether the session's subject has name on resource.
func (s *Session) Check(resource rel.Object, name string) bool {
	if s.e.Mutant == VisitedNotPath {
		s.visited = map[goal]bool{}
	}
	v, _ := s.eval(goal{resource, name})
	return v
}

// eval works out one goal by depth-first search. Cycles are cut by
// treating a goal already on the current path as false: the shortest
// derivation of a goal never passes through the goal itself. A false
// answer that leaned on such a cut is only remembered once the goal it
// leaned on has finished, because until then it may be wrong. low is the
// shallowest goal still on the path that the answer leaned on.
func (s *Session) eval(g goal) (v bool, low int) {
	if s.e.Mutant == VisitedNotPath {
		// The bug: cutting cycles with "seen anywhere in this query"
		// instead of "on the current path".
		if s.visited[g] {
			return false, none
		}
		s.visited[g] = true
	}
	if v, ok := s.memo[g]; ok {
		return v, none
	}
	if d, ok := s.onPath[g]; ok {
		return false, d
	}
	d := s.depth
	s.onPath[g] = d
	s.depth++
	v, low = s.evalGoal(g)
	s.depth--
	delete(s.onPath, g)
	if low >= d {
		low = none
	}
	if v || low == none || s.e.Mutant == MemoFalseInCycle {
		s.memo[g] = v
	}
	return v, low
}

func (s *Session) evalGoal(g goal) (bool, int) {
	d := s.e.Schema.Def(g.obj.Type)
	if d == nil {
		return false, none
	}
	if r := d.Relation(g.name); r != nil {
		return s.evalRelation(g)
	}
	if p := d.Permission(g.name); p != nil {
		return s.evalExpr(g.obj, p.Expr)
	}
	return false, none
}

func (s *Session) evalRelation(g goal) (bool, int) {
	low := none
	for _, sub := range s.e.Store.Subjects(g.obj, g.name) {
		switch {
		case sub.Wildcard():
			if sub.Type == s.subject.Type || s.e.Mutant == WildcardAnyType {
				return true, low
			}
		case sub.Relation == "":
			if sub.Object == s.subject {
				return true, low
			}
		case s.e.Mutant == SubjectSetOneLevel:
			for _, inner := range s.e.Store.Subjects(sub.Object, sub.Relation) {
				if inner.Relation == "" && (inner.Object == s.subject || inner.Wildcard() && inner.Type == s.subject.Type) {
					return true, low
				}
			}
		default:
			v, l := s.eval(goal{sub.Object, sub.Relation})
			low = min(low, l)
			if v {
				return true, low
			}
		}
	}
	return false, low
}

func (s *Session) evalExpr(obj rel.Object, e schema.Expr) (bool, int) {
	switch e := e.(type) {
	case schema.Ref:
		return s.eval(goal{obj, e.Name})
	case schema.Arrow:
		low := none
		for _, sub := range s.e.Store.Subjects(obj, e.Tupleset) {
			if !s.e.Schema.Has(sub.Type, e.Target) {
				continue
			}
			v, l := s.eval(goal{sub.Object, e.Target})
			low = min(low, l)
			if v {
				return true, low
			}
			if s.e.Mutant == ArrowFirstOnly {
				break
			}
		}
		return false, low
	case *schema.Op:
		low := none
		switch {
		case e.Kind == schema.Union || e.Kind == schema.Intersection && s.e.Mutant == IntersectionAsUnion:
			for _, a := range e.Args {
				v, l := s.evalExpr(obj, a)
				low = min(low, l)
				if v {
					return true, low
				}
			}
			return false, low
		case e.Kind == schema.Intersection:
			for _, a := range e.Args {
				v, l := s.evalExpr(obj, a)
				low = min(low, l)
				if !v {
					return false, low
				}
			}
			return true, low
		default: // exclusion
			v, l := s.evalExpr(obj, e.Args[0])
			low = min(low, l)
			if !v {
				return false, low
			}
			// A stratified schema never reaches a goal on the current path
			// from here, so this answer is final.
			w, l := s.evalExpr(obj, e.Args[1])
			return !w, min(low, l)
		}
	}
	return false, none
}

// EvalExpr evaluates an expression on obj for the session's subject.
func (s *Session) EvalExpr(obj rel.Object, e schema.Expr) bool {
	if s.e.Mutant == VisitedNotPath {
		s.visited = map[goal]bool{}
	}
	v, _ := s.evalExpr(obj, e)
	return v
}

// LookupResources returns the objects of type t on which subject has name.
func (e *Engine) LookupResources(t, name string, subject rel.Object) []rel.Object {
	var out []rel.Object
	if !e.Schema.Has(t, name) {
		return nil
	}
	for _, o := range e.Store.Objects(t) {
		if e.Check(o, name, subject) {
			out = append(out, o)
		}
	}
	return out
}

// Subjects is the answer to LookupSubjects. If Wildcard is set, every
// object of the type has access except those in Except; otherwise exactly
// those in Objects do.
type Subjects struct {
	Objects  []rel.Object
	Wildcard bool
	Except   []rel.Object
}

// LookupSubjects returns the objects of type t that have name on resource.
func (e *Engine) LookupSubjects(resource rel.Object, name, t string) Subjects {
	var out Subjects
	for _, o := range rel.Universe([]string{t}, e.Store) {
		ok := e.Check(resource, name, o)
		switch {
		case o.ID == rel.Unseen:
			out.Wildcard = ok
		case ok:
			out.Objects = append(out.Objects, o)
		default:
			out.Except = append(out.Except, o)
		}
	}
	if !out.Wildcard {
		out.Except = nil
	}
	return out
}
