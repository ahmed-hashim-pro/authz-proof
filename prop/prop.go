// Package prop checks the engine against the reference evaluator on
// random schemas and relationships. The tests, `authz-proof hunt` and
// `authz-proof mutants` all use it.
package prop

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ahmed-hashim-pro/authz-proof/diff"
	"github.com/ahmed-hashim-pro/authz-proof/engine"
	"github.com/ahmed-hashim-pro/authz-proof/gen"
	"github.com/ahmed-hashim-pro/authz-proof/ref"
	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

// Built is a parsed random model.
type Built struct {
	Gen    *gen.Model
	Schema *schema.Schema
	Store  *rel.Store
}

// Build parses a generated model. It returns false if the schema is not
// stratified, which the generator does not avoid on purpose.
func Build(m *gen.Model) (Built, bool, error) {
	s, err := schema.Parse(m.Schema)
	if err != nil {
		if strings.Contains(err.Error(), "through an exclusion") || strings.Contains(err.Error(), "in a loop") ||
			strings.Contains(err.Error(), "wildcards to be included") {
			return Built{}, false, nil
		}
		return Built{}, false, fmt.Errorf("generated schema does not parse: %w\n%s", err, m.Schema)
	}
	st, err := rel.Parse(s, strings.Join(m.Relationships, "\n"))
	if err != nil {
		return Built{}, false, fmt.Errorf("generated relationships do not parse: %w", err)
	}
	return Built{m, s, st}, true, nil
}

// Pair finds the valid model pair for a seed: a model and a changed copy
// of it, both stratified. The k-th attempt uses sub-seed seed*1000+k, so
// the pair is a pure function of the seed.
func Pair(seed int64) (Built, Built, error) {
	for k := int64(0); k < 1000; k++ {
		m := gen.New(seed*1000 + k)
		a, ok, err := Build(m)
		if err != nil {
			return Built{}, Built{}, err
		}
		if !ok {
			continue
		}
		for j := int64(0); j < 50; j++ {
			b, ok, err := Build(m.Changed(seed*1000 + k + j*7919))
			if err != nil {
				return Built{}, Built{}, err
			}
			if ok {
				return a, b, nil
			}
		}
	}
	return Built{}, Built{}, fmt.Errorf("seed %d: no stratified model found", seed)
}

// Failure is a disagreement between the engine and the reference.
type Failure struct {
	Seed  int64
	Check string // which property: check, lookup-resources, ...
	Msg   string
	Model *gen.Model
}

func (f *Failure) Error() string {
	return fmt.Sprintf("seed %d: %s: %s", f.Seed, f.Check, f.Msg)
}

// Run checks every property for one seed with the given engine variant.
func Run(seed int64, mut engine.Mutant) error {
	a, b, err := Pair(seed)
	if err != nil {
		return err
	}
	fail := func(check, format string, args ...any) error {
		return &Failure{seed, check, fmt.Sprintf(format, args...), a.Gen}
	}
	subjects := rel.Universe(a.Schema.DirectTypes(), a.Store)
	want := ref.Compute(a.Schema, a.Store, subjects)
	e := engine.New(a.Schema, a.Store)
	e.Mutant = mut
	for _, d := range a.Schema.Defs {
		for _, obj := range a.Store.Objects(d.Name) {
			for _, name := range d.Names() {
				for _, sub := range subjects {
					got, w := e.Check(obj, name, sub), want.Has(obj, name, sub)
					if got != w {
						return fail("check", "%s#%s@%s: engine says %v, reference says %v", obj, name, sub.Display(), got, w)
					}
					if got {
						if _, ok := e.Explain(obj, name, sub); !ok {
							return fail("explain", "%s#%s@%s holds but no chain was found", obj, name, sub.Display())
						}
					}
				}
				tree, err := e.Expand(obj, name)
				if err != nil {
					return fail("expand", "%s#%s: %v", obj, name, err)
				}
				for _, sub := range subjects {
					if got, w := tree.Has(sub), want.Has(obj, name, sub); got != w {
						return fail("expand", "%s#%s@%s: tree says %v, reference says %v", obj, name, sub.Display(), got, w)
					}
				}
			}
		}
		for _, name := range d.Names() {
			for _, sub := range subjects {
				got := e.LookupResources(d.Name, name, sub)
				var w []rel.Object
				for _, obj := range a.Store.Objects(d.Name) {
					if want.Has(obj, name, sub) {
						w = append(w, obj)
					}
				}
				if fmt.Sprint(got) != fmt.Sprint(w) {
					return fail("lookup-resources", "%s#%s@%s: engine %v, reference %v", d.Name, name, sub.Display(), got, w)
				}
			}
			for _, obj := range a.Store.Objects(d.Name) {
				for _, t := range a.Schema.DirectTypes() {
					got := e.LookupSubjects(obj, name, t)
					for _, sub := range rel.Universe([]string{t}, a.Store) {
						in := sub.ID == rel.Unseen && got.Wildcard ||
							sub.ID != rel.Unseen && (has(got.Objects, sub) || got.Wildcard && !has(got.Except, sub))
						if in != want.Has(obj, name, sub) {
							return fail("lookup-subjects", "%s#%s, %s: engine %+v disagrees with reference on %s", obj, name, t, got, sub.Display())
						}
					}
				}
			}
		}
	}
	return checkDiff(seed, a, b, mut)
}

func has(xs []rel.Object, o rel.Object) bool {
	for _, x := range xs {
		if x == o {
			return true
		}
	}
	return false
}

// checkDiff compares the engine's diff with one computed from two full
// reference models.
func checkDiff(seed int64, a, b Built, mut engine.Mutant) error {
	ea, eb := engine.New(a.Schema, a.Store), engine.New(b.Schema, b.Store)
	ea.Mutant, eb.Mutant = mut, mut
	got := diff.Compute(ea, eb)
	types := map[string]bool{}
	var direct []string
	for _, s := range []*schema.Schema{a.Schema, b.Schema} {
		for _, t := range s.DirectTypes() {
			if !types[t] {
				types[t] = true
				direct = append(direct, t)
			}
		}
	}
	sort.Strings(direct)
	subjects := rel.Universe(direct, a.Store, b.Store)
	ra := ref.Compute(a.Schema, a.Store, subjects)
	rb := ref.Compute(b.Schema, b.Store, subjects)
	var want []string
	for f := range ra.Facts {
		if !rb.Facts[f] {
			want = append(want, fmt.Sprintf("lost %s#%s@%s", f.Resource, f.Name, f.Subject.Display()))
		}
	}
	for f := range rb.Facts {
		if !ra.Facts[f] {
			want = append(want, fmt.Sprintf("gained %s#%s@%s", f.Resource, f.Name, f.Subject.Display()))
		}
	}
	var have []string
	for _, c := range got.Changes {
		verb := "lost"
		if c.Gained {
			verb = "gained"
		}
		have = append(have, fmt.Sprintf("%s %s#%s@%s", verb, c.Resource, c.Name, c.Subject.Display()))
		if len(c.Proof.Steps) == 0 {
			return &Failure{seed, "diff", fmt.Sprintf("%s has no chain", have[len(have)-1]), a.Gen}
		}
	}
	sort.Strings(want)
	sort.Strings(have)
	if strings.Join(want, "\n") != strings.Join(have, "\n") {
		return &Failure{seed, "diff", fmt.Sprintf("engine found %d changes %v, reference %d %v", len(have), first(have), len(want), first(want)), a.Gen}
	}
	return nil
}

func first(xs []string) []string {
	if len(xs) > 4 {
		return append(xs[:4:4], "…")
	}
	return xs
}

// Coverage counts what the random models contained, so a clean run can
// be read for what it covered.
type Coverage struct {
	Models, Checks                                    int
	Cyclic, Wildcard, Exclusion, Intersection, Arrows int
	DiffChanges                                       int
}

// Add counts a pair of models.
func (c *Coverage) Add(a, b Built) {
	for _, m := range []Built{a, b} {
		c.Models++
		text := m.Gen.Schema
		if cyclic(m.Store) {
			c.Cyclic++
		}
		for _, t := range m.Store.Tuples() {
			if t.Subject.Wildcard() {
				c.Wildcard++
				break
			}
		}
		if strings.Contains(text, " - ") {
			c.Exclusion++
		}
		if strings.Contains(text, " & ") {
			c.Intersection++
		}
		if strings.Contains(text, "->") {
			c.Arrows++
		}
	}
}

func pct(n, d int) int {
	if d == 0 {
		return 0
	}
	return n * 100 / d
}

func (c Coverage) String() string {
	return fmt.Sprintf("models: %d, with cyclic relationships %d%%, wildcard relationships %d%%, exclusions %d%%, intersections %d%%, arrows %d%%",
		c.Models, pct(c.Cyclic, c.Models), pct(c.Wildcard, c.Models), pct(c.Exclusion, c.Models), pct(c.Intersection, c.Models), pct(c.Arrows, c.Models))
}

// cyclic reports whether some object can reach itself through
// relationships, which is where cycle handling matters.
func cyclic(st *rel.Store) bool {
	edges := map[rel.Object][]rel.Object{}
	for _, t := range st.Tuples() {
		if !t.Subject.Wildcard() {
			edges[t.Resource] = append(edges[t.Resource], t.Subject.Object)
		}
	}
	state := map[rel.Object]int{}
	var visit func(o rel.Object) bool
	visit = func(o rel.Object) bool {
		switch state[o] {
		case 1:
			return true
		case 2:
			return false
		}
		state[o] = 1
		for _, n := range edges[o] {
			if visit(n) {
				return true
			}
		}
		state[o] = 2
		return false
	}
	for o := range edges {
		if visit(o) {
			return true
		}
	}
	return false
}
