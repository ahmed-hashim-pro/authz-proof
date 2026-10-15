// Package diff works out exactly who gains and who loses access when a
// schema or its relationships change, and why.
package diff

import (
	"bufio"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/ahmed-hashim-pro/authz-proof/engine"
	"github.com/ahmed-hashim-pro/authz-proof/rel"
)

// Change is one grant that exists on one side only.
type Change struct {
	Resource rel.Object
	Name     string
	Subject  rel.Object
	Gained   bool
	// Proof is the chain that grants access: in the new model for a gain,
	// in the old one for a loss.
	Proof engine.Proof
	// Blocker, if set, is the exclusion that denies access on the other
	// side.
	Blocker *engine.Blocker
	// NameOnlyOneSide is set when the relation or permission exists in
	// only one of the two schemas.
	NameOnlyOneSide bool
	// Allowed is the allowlist entry that covers this change, if any.
	Allowed *Rule
}

// Result is the outcome of a comparison.
type Result struct {
	Changes  []Change
	Checks   int
	Objects  int
	Subjects int
	Names    int
}

// Gained and Lost count the changes.
func (r Result) Gained() int { return r.count(true) }
func (r Result) Lost() int   { return r.count(false) }

func (r Result) count(g bool) int {
	n := 0
	for _, c := range r.Changes {
		if c.Gained == g {
			n++
		}
	}
	return n
}

// Compute compares every relation and permission of every object for
// every subject a check could succeed for, under old and under new.
// Subjects include one stand-in per type for objects that appear in no
// relationship, so a gain through a wildcard is found even for users the
// data has never heard of.
func Compute(old, new *engine.Engine) Result {
	var res Result
	types := map[string]bool{}
	var typeOrder []string
	for _, s := range []*engine.Engine{old, new} {
		for _, d := range s.Schema.Defs {
			if !types[d.Name] {
				types[d.Name] = true
				typeOrder = append(typeOrder, d.Name)
			}
		}
	}
	sort.Strings(typeOrder)
	var direct []string
	seen := map[string]bool{}
	for _, e := range []*engine.Engine{old, new} {
		for _, t := range e.Schema.DirectTypes() {
			if !seen[t] {
				seen[t] = true
				direct = append(direct, t)
			}
		}
	}
	sort.Strings(direct)
	subjects := rel.Universe(direct, old.Store, new.Store)
	if new.Mutant == engine.DiffKnownSubjectOnly {
		var known []rel.Object
		for _, s := range subjects {
			if s.ID != rel.Unseen {
				known = append(known, s)
			}
		}
		subjects = known
	}
	res.Subjects = len(subjects)
	for _, t := range typeOrder {
		names := namesOf(old, t, new)
		res.Names += len(names)
		objs := objectsOf(t, old.Store, new.Store)
		res.Objects += len(objs)
		for _, obj := range objs {
			for _, name := range names {
				inOld, inNew := old.Schema.Has(t, name), new.Schema.Has(t, name)
				for _, sub := range subjects {
					res.Checks++
					o := inOld && old.Check(obj, name, sub)
					n := inNew && new.Check(obj, name, sub)
					if o == n {
						continue
					}
					c := Change{Resource: obj, Name: name, Subject: sub, Gained: n, NameOnlyOneSide: inOld != inNew}
					grant, deny := new, old
					if !n {
						grant, deny = old, new
					}
					c.Proof, _ = grant.Explain(obj, name, sub)
					if deny.Schema.Has(t, name) {
						if b, ok := deny.WhyNot(obj, name, sub); ok {
							c.Blocker = &b
						}
					}
					res.Changes = append(res.Changes, c)
				}
			}
		}
	}
	sort.SliceStable(res.Changes, func(i, j int) bool {
		return res.Changes[i].Gained && !res.Changes[j].Gained
	})
	return res
}

func namesOf(old *engine.Engine, t string, new *engine.Engine) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range []*engine.Engine{old, new} {
		if d := e.Schema.Def(t); d != nil {
			for _, n := range d.Names() {
				if !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
	}
	return out
}

func objectsOf(t string, stores ...*rel.Store) []rel.Object {
	seen := map[rel.Object]bool{}
	var out []rel.Object
	for _, st := range stores {
		for _, o := range st.Objects(t) {
			if !seen[o] {
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Rule is one allowlist entry: a pattern over resource#name@subject, with
// shell-style globs in each part, and the reason it is expected.
type Rule struct {
	Pattern string
	Reason  string
	Line    int
	parts   [5]string // resource type, id, name, subject type, id
}

// ParseAllowlist reads one rule per line: a pattern, then the reason.
// Each part of the pattern may use shell globs and one {a,b} group.
// Blank lines and lines starting with // are skipped.
//
//	document:{roadmap,design-*}#edit@user:carol   SEC-142: carol edits engineering docs
func ParseAllowlist(text string) ([]Rule, error) {
	var out []Rule
	sc := bufio.NewScanner(strings.NewReader(text))
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		pat, reason, _ := strings.Cut(line, " ")
		r := Rule{Pattern: pat, Reason: strings.TrimSpace(reason), Line: n}
		res, sub, ok := strings.Cut(pat, "@")
		obj, name, ok2 := strings.Cut(res, "#")
		rt, rid, ok3 := strings.Cut(obj, ":")
		st, sid, ok4 := strings.Cut(sub, ":")
		if !ok || !ok2 || !ok3 || !ok4 {
			return nil, fmt.Errorf("allowlist line %d: %q is not of the form type:id#name@type:id", n, pat)
		}
		r.parts = [5]string{rt, rid, name, st, sid}
		for _, p := range r.parts {
			for _, alt := range alternatives(p) {
				if _, err := path.Match(alt, ""); err != nil {
					return nil, fmt.Errorf("allowlist line %d: bad pattern %q", n, p)
				}
			}
		}
		if r.Reason == "" {
			return nil, fmt.Errorf("allowlist line %d: say why %s is expected", n, pat)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Matches reports whether the rule covers a change.
func (r *Rule) Matches(c Change) bool {
	sid := c.Subject.ID
	if sid == rel.Unseen {
		sid = "*"
	}
	vals := [5]string{c.Resource.Type, c.Resource.ID, c.Name, c.Subject.Type, sid}
	for i, p := range r.parts {
		matched := false
		for _, alt := range alternatives(p) {
			if ok, _ := path.Match(alt, vals[i]); ok {
				matched = true
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// alternatives expands one {a,b,c} group: "doc-{a,b}" is doc-a or doc-b.
func alternatives(p string) []string {
	open := strings.Index(p, "{")
	end := strings.Index(p, "}")
	if open < 0 || end < open {
		return []string{p}
	}
	var out []string
	for _, a := range strings.Split(p[open+1:end], ",") {
		out = append(out, p[:open]+a+p[end+1:])
	}
	return out
}

// Apply marks each change covered by a rule.
func (r *Result) Apply(rules []Rule) {
	for i := range r.Changes {
		for j := range rules {
			if rules[j].Matches(r.Changes[i]) {
				r.Changes[i].Allowed = &rules[j]
				break
			}
		}
	}
}
