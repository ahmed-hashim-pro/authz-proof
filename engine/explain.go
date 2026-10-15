package engine

import (
	"strings"

	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

// Step is one link in a chain of access: the subject is a member of
// Object#Name. Via names the arrow that led here ("parent"); Wildcard
// marks membership through type:*; Also holds the other chains an
// intersection needed; Unless names what an exclusion checked was empty.
type Step struct {
	Object   rel.Object
	Name     string
	Via      string
	Wildcard bool
	Also     []Proof
	Unless   string
}

// Proof is a chain of steps from the subject to the resource.
type Proof struct {
	Subject rel.Object
	Steps   []Step
}

// maxProofDepth bounds the search; no real chain is longer.
const maxProofDepth = 64

// Explain returns the shortest chain of relationships that gives subject
// name on resource, or false if there is none.
func (e *Engine) Explain(resource rel.Object, name string, subject rel.Object) (Proof, bool) {
	s := e.Session(subject)
	if !s.Check(resource, name) {
		return Proof{}, false
	}
	for depth := 1; depth <= maxProofDepth; depth++ {
		p := &prover{s: s, onPath: map[goal]bool{}}
		if steps, ok := p.prove(goal{resource, name}, depth); ok {
			return Proof{subject, steps}, true
		}
	}
	return Proof{}, false
}

// ExplainExpr is Explain for an expression on obj rather than a named
// relation or permission.
func (e *Engine) ExplainExpr(obj rel.Object, x schema.Expr, subject rel.Object) (Proof, bool) {
	s := e.Session(subject)
	if !s.EvalExpr(obj, x) {
		return Proof{}, false
	}
	for depth := 1; depth <= maxProofDepth; depth++ {
		p := &prover{s: s, onPath: map[goal]bool{}}
		if steps, _, ok := p.proveExpr(obj, x, depth); ok {
			return Proof{subject, steps}, true
		}
	}
	return Proof{}, false
}

type prover struct {
	s      *Session
	onPath map[goal]bool
}

// prove finds a chain for g using at most depth goals in a row. It is only
// called on goals that hold, and it checks each branch with the session
// before descending, so it only searches where a chain exists.
func (p *prover) prove(g goal, depth int) ([]Step, bool) {
	if depth == 0 || p.onPath[g] {
		return nil, false
	}
	if !p.s.Check(g.obj, g.name) {
		return nil, false
	}
	p.onPath[g] = true
	defer delete(p.onPath, g)
	d := p.s.e.Schema.Def(g.obj.Type)
	if d.Relation(g.name) != nil {
		var later []rel.Subject
		for _, sub := range p.s.e.Store.Subjects(g.obj, g.name) {
			switch {
			case sub.Wildcard() && sub.Type == p.s.subject.Type:
				return []Step{{Object: g.obj, Name: g.name, Wildcard: true}}, true
			case sub.Relation == "" && sub.Object == p.s.subject:
				return []Step{{Object: g.obj, Name: g.name}}, true
			case sub.Relation != "":
				later = append(later, sub)
			}
		}
		for _, sub := range later {
			if steps, ok := p.prove(goal{sub.Object, sub.Relation}, depth-1); ok {
				return append(steps, Step{Object: g.obj, Name: g.name}), true
			}
		}
		return nil, false
	}
	steps, via, ok := p.proveExpr(g.obj, d.Permission(g.name).Expr, depth-1)
	if !ok {
		return nil, false
	}
	last := Step{Object: g.obj, Name: g.name, Via: via}
	// An intersection or exclusion at the top of the expression leaves its
	// notes on the step it produced; move them to this permission's step.
	if n := len(steps); n > 0 && steps[n-1].Object == g.obj && steps[n-1].Name == "" {
		last.Also, last.Unless = steps[n-1].Also, steps[n-1].Unless
		steps = steps[:n-1]
	}
	return append(steps, last), true
}

func (p *prover) proveExpr(obj rel.Object, x schema.Expr, depth int) ([]Step, string, bool) {
	if !p.s.EvalExpr(obj, x) {
		return nil, "", false
	}
	switch x := x.(type) {
	case schema.Ref:
		steps, ok := p.prove(goal{obj, x.Name}, depth)
		return steps, "", ok
	case schema.Arrow:
		for _, sub := range p.s.e.Store.Subjects(obj, x.Tupleset) {
			if !p.s.e.Schema.Has(sub.Type, x.Target) {
				continue
			}
			if steps, ok := p.prove(goal{sub.Object, x.Target}, depth); ok {
				return steps, x.Tupleset, true
			}
		}
		return nil, "", false
	case *schema.Op:
		switch x.Kind {
		case schema.Union:
			for _, a := range x.Args {
				if steps, via, ok := p.proveExpr(obj, a, depth); ok {
					return steps, via, true
				}
			}
			return nil, "", false
		case schema.Intersection:
			var first []Step
			var via string
			var also []Proof
			for i, a := range x.Args {
				steps, v, ok := p.proveExpr(obj, a, depth)
				if !ok {
					return nil, "", false
				}
				if i == 0 {
					first, via = steps, v
				} else {
					also = append(also, Proof{p.s.subject, steps})
				}
			}
			return note(first, obj, also, ""), via, true
		default:
			steps, via, ok := p.proveExpr(obj, x.Args[0], depth)
			if !ok {
				return nil, "", false
			}
			return note(steps, obj, nil, x.Args[1].String()), via, true
		}
	}
	return nil, "", false
}

// note records an intersection's other chains or an exclusion's empty
// part on a placeholder step (no Name) for obj, merging with one already
// there, so a permission with several operations gets one set of notes.
func note(steps []Step, obj rel.Object, also []Proof, unless string) []Step {
	if n := len(steps); n > 0 && steps[n-1].Object == obj && steps[n-1].Name == "" {
		last := &steps[n-1]
		last.Also = append(last.Also, also...)
		if unless != "" {
			if last.Unless != "" {
				last.Unless += ", " + unless
			} else {
				last.Unless = unless
			}
		}
		return steps
	}
	return append(steps, Step{Object: obj, Also: also, Unless: unless})
}

// Blocker is an exclusion that took access away: on Object, the subject
// was in the base but also in Subtracted, by Proof.
type Blocker struct {
	Object     rel.Object
	Subtracted string
	Proof      Proof
}

// WhyNot looks for an exclusion that denied subject name on resource:
// one whose base held and whose subtracted part held too. It returns
// false if access was not denied by an exclusion (there was simply no
// chain to begin with).
func (e *Engine) WhyNot(resource rel.Object, name string, subject rel.Object) (Blocker, bool) {
	w := &whyNot{e: e, s: e.Session(subject), seen: map[goal]bool{}}
	return w.goal(goal{resource, name})
}

type whyNot struct {
	e    *Engine
	s    *Session
	seen map[goal]bool
}

func (w *whyNot) goal(g goal) (Blocker, bool) {
	if w.seen[g] {
		return Blocker{}, false
	}
	w.seen[g] = true
	d := w.e.Schema.Def(g.obj.Type)
	if d == nil {
		return Blocker{}, false
	}
	if d.Relation(g.name) != nil {
		for _, sub := range w.e.Store.Subjects(g.obj, g.name) {
			if sub.Relation != "" {
				if b, ok := w.goal(goal{sub.Object, sub.Relation}); ok {
					return b, true
				}
			}
		}
		return Blocker{}, false
	}
	if p := d.Permission(g.name); p != nil {
		return w.expr(g.obj, p.Expr)
	}
	return Blocker{}, false
}

func (w *whyNot) expr(obj rel.Object, x schema.Expr) (Blocker, bool) {
	switch x := x.(type) {
	case schema.Ref:
		return w.goal(goal{obj, x.Name})
	case schema.Arrow:
		for _, sub := range w.e.Store.Subjects(obj, x.Tupleset) {
			if w.e.Schema.Has(sub.Type, x.Target) {
				if b, ok := w.goal(goal{sub.Object, x.Target}); ok {
					return b, true
				}
			}
		}
	case *schema.Op:
		if x.Kind == schema.Exclusion && w.s.EvalExpr(obj, x.Args[0]) {
			if pr, ok := w.e.ExplainExpr(obj, x.Args[1], w.s.subject); ok {
				return Blocker{obj, x.Args[1].String(), pr}, true
			}
		}
		for i, a := range x.Args {
			if x.Kind == schema.Exclusion && i == 1 {
				break
			}
			if b, ok := w.expr(obj, a); ok {
				return b, true
			}
		}
	}
	return Blocker{}, false
}

// Lines renders a proof one object per line, with notes aligned:
//
//	user:bob
//	  → team:contractors#member
//	  → folder:company#viewer → #view
//	  → folder:hr#view               via parent
func (p Proof) Lines(indent string) []string {
	type row struct {
		text  string
		notes []string
		also  []Proof
	}
	var rows []row
	for i, st := range p.Steps {
		var notes []string
		if st.Wildcard {
			notes = append(notes, "as "+p.Subject.Type+":*")
		}
		if st.Via != "" {
			notes = append(notes, "via "+st.Via)
		}
		if st.Unless != "" {
			notes = append(notes, "and not in "+st.Unless)
		}
		if i > 0 && st.Object == p.Steps[i-1].Object && len(rows) > 0 {
			r := &rows[len(rows)-1]
			r.text += " → #" + st.Name
			r.notes = append(r.notes, notes...)
			r.also = append(r.also, st.Also...)
			continue
		}
		rows = append(rows, row{st.Object.String() + "#" + st.Name, notes, st.Also})
	}
	width := 0
	for _, r := range rows {
		width = max(width, len(r.text))
	}
	out := []string{indent + p.Subject.Display()}
	for _, r := range rows {
		line := indent + "  → " + r.text
		if len(r.notes) > 0 {
			line += strings.Repeat(" ", width-len(r.text)+3) + strings.Join(r.notes, ", ")
		}
		out = append(out, line)
		for _, also := range r.also {
			out = append(out, indent+"      and also:")
			out = append(out, also.Lines(indent+"        ")...)
		}
	}
	return out
}

// Inline renders a proof on one line.
func (p Proof) Inline() string {
	parts := []string{p.Subject.Display()}
	for _, st := range p.Steps {
		parts = append(parts, st.Object.String()+"#"+st.Name)
	}
	return strings.Join(parts, " → ")
}
