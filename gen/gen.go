// Package gen makes random schemas and relationships for property tests
// and for cross-checking against SpiceDB. Everything it makes is valid
// SpiceDB schema text and relationship text, and a pure function of the
// seed.
package gen

import (
	"fmt"
	"math/rand"
	"strings"
)

// Model is a random schema and relationships, as text.
type Model struct {
	Schema        string
	Relationships []string
	types         []*typ
	rng           *rand.Rand
	acyclic       bool
	cur           int // index of the permission being generated
}

type typ struct {
	name  string
	rels  []*relation
	perms []*perm
	ids   []string
}

type relation struct {
	name     string
	allowed  []string // user, user:*, ty1#rel0, ty1
	tupleset bool     // only direct object types: usable left of an arrow
}

type perm struct {
	name string
	expr string
}

// New returns the model for a seed. The schema may be one authz-proof
// refuses (a permission depending on itself through an exclusion, say);
// callers skip those. The relationships may form cycles.
func New(seed int64) *Model { return build(seed, false) }

// NewAcyclic is New with relationships that never lead from an object
// back to itself, so no question recurses through the data.
func NewAcyclic(seed int64) *Model { return build(seed, true) }

func build(seed int64, acyclic bool) *Model {
	r := rand.New(rand.NewSource(seed))
	m := &Model{rng: r, acyclic: acyclic}
	m.types = append(m.types, &typ{name: "user", ids: []string{"alice", "bob", "carol"}[:1+r.Intn(3)]})
	nt := 1 + r.Intn(3)
	for i := 0; i < nt; i++ {
		t := &typ{name: fmt.Sprintf("ty%d", i)}
		for j := 0; j < 2+r.Intn(3); j++ {
			t.ids = append(t.ids, fmt.Sprintf("o%d", j))
		}
		nr := 1 + r.Intn(3)
		for j := 0; j < nr; j++ {
			t.rels = append(t.rels, &relation{name: fmt.Sprintf("rel%d", j), tupleset: nt > 1 && r.Intn(4) == 0})
		}
		np := r.Intn(4)
		for j := 0; j < np; j++ {
			t.perms = append(t.perms, &perm{name: fmt.Sprintf("perm%d", j)})
		}
		m.types = append(m.types, t)
	}
	nonterm := m.types[1:]
	for _, t := range nonterm {
		for _, rl := range t.rels {
			if rl.tupleset {
				rl.allowed = pickTypes(r, nonterm)
				continue
			}
			if r.Intn(5) > 0 {
				rl.allowed = append(rl.allowed, "user")
			}
			if r.Intn(6) == 0 {
				rl.allowed = append(rl.allowed, "user:*")
			}
			for k := 0; k < 2; k++ {
				if r.Intn(5) < 2 {
					o := nonterm[r.Intn(len(nonterm))]
					names := o.names()
					s := o.name + "#" + names[r.Intn(len(names))]
					if !contains(rl.allowed, s) {
						rl.allowed = append(rl.allowed, s)
					}
				}
			}
			if len(rl.allowed) == 0 {
				rl.allowed = []string{"user"}
			}
		}
	}
	for _, t := range nonterm {
		for j, p := range t.perms {
			m.cur = j
			p.expr = m.expr(t, 0)
		}
	}
	m.render()
	m.Relationships = m.relationships(nil, 3+r.Intn(18))
	return m
}

func pickTypes(r *rand.Rand, ts []*typ) []string {
	var out []string
	for _, t := range ts {
		if r.Intn(2) == 0 {
			out = append(out, t.name)
		}
	}
	if len(out) == 0 {
		out = []string{ts[r.Intn(len(ts))].name}
	}
	return out
}

func (t *typ) names() []string {
	var out []string
	for _, r := range t.rels {
		out = append(out, r.name)
	}
	for _, p := range t.perms {
		out = append(out, p.name)
	}
	return out
}

func (m *Model) typ(name string) *typ {
	for _, t := range m.types {
		if t.name == name {
			return t
		}
	}
	return nil
}

// expr makes a random expression on t. Nested operations are usually
// parenthesised, but not always, so SpiceDB's precedence gets exercised.
func (m *Model) expr(t *typ, depth int) string {
	r := m.rng
	if depth >= 2 || r.Intn(3) == 0 {
		return m.leaf(t)
	}
	ops := []string{"+", "&", "-"}
	op := ops[r.Intn(3)]
	n := 2
	if op != "-" && r.Intn(3) == 0 {
		n = 3
	}
	parts := make([]string, n)
	for i := range parts {
		sub := m.expr(t, depth+1)
		if strings.ContainsAny(sub, "+&-") && strings.Contains(sub, " ") && r.Intn(4) > 0 {
			sub = "(" + sub + ")"
		}
		parts[i] = sub
	}
	return strings.Join(parts, " "+op+" ")
}

func (m *Model) leaf(t *typ) string {
	r := m.rng
	var arrows []string
	for _, rl := range t.rels {
		if !rl.tupleset {
			continue
		}
		var targets []string
		for _, a := range rl.allowed {
			targets = append(targets, m.typ(a).names()...)
		}
		if len(targets) > 0 {
			arrows = append(arrows, rl.name+"->"+targets[r.Intn(len(targets))])
		}
	}
	if len(arrows) > 0 && r.Intn(3) == 0 {
		return arrows[r.Intn(len(arrows))]
	}
	names := t.names()
	if m.acyclic {
		// Only relations and earlier permissions, so nothing recurses.
		names = names[:len(t.rels)+m.cur]
	}
	return names[r.Intn(len(names))]
}

func (m *Model) render() {
	var b strings.Builder
	for _, t := range m.types {
		if len(t.rels) == 0 {
			fmt.Fprintf(&b, "definition %s {}\n\n", t.name)
			continue
		}
		fmt.Fprintf(&b, "definition %s {\n", t.name)
		for _, rl := range t.rels {
			fmt.Fprintf(&b, "\trelation %s: %s\n", rl.name, strings.Join(rl.allowed, " | "))
		}
		for _, p := range t.perms {
			fmt.Fprintf(&b, "\tpermission %s = %s\n", p.name, p.expr)
		}
		b.WriteString("}\n\n")
	}
	m.Schema = b.String()
}

// relationships adds up to n random relationships to existing ones. In an
// acyclic model it skips any that would let an object reach itself.
func (m *Model) relationships(existing []string, n int) []string {
	r := m.rng
	out := append([]string(nil), existing...)
	seen := map[string]bool{}
	edges := map[string][]string{}
	for _, line := range out {
		seen[line] = true
		res, sub := objectsOf(line)
		edges[res] = append(edges[res], sub)
	}
	reaches := func(from, to string) bool {
		visited := map[string]bool{}
		stack := []string{from}
		for len(stack) > 0 {
			x := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if x == to {
				return true
			}
			if !visited[x] {
				visited[x] = true
				stack = append(stack, edges[x]...)
			}
		}
		return false
	}
	for i := 0; i < n; i++ {
		t := m.types[1+r.Intn(len(m.types)-1)]
		rl := t.rels[r.Intn(len(t.rels))]
		a := rl.allowed[r.Intn(len(rl.allowed))]
		var sub string
		switch {
		case a == "user:*":
			sub = "user:*"
		case strings.Contains(a, "#"):
			on, rn, _ := strings.Cut(a, "#")
			o := m.typ(on)
			sub = fmt.Sprintf("%s:%s#%s", on, o.ids[r.Intn(len(o.ids))], rn)
		default:
			o := m.typ(a)
			sub = fmt.Sprintf("%s:%s", a, o.ids[r.Intn(len(o.ids))])
		}
		line := fmt.Sprintf("%s:%s#%s@%s", t.name, t.ids[r.Intn(len(t.ids))], rl.name, sub)
		if seen[line] {
			continue
		}
		res, so := objectsOf(line)
		if m.acyclic && reaches(so, res) {
			continue
		}
		seen[line] = true
		edges[res] = append(edges[res], so)
		out = append(out, line)
	}
	return out
}

// objectsOf returns the resource and subject objects of a relationship.
func objectsOf(line string) (string, string) {
	res, sub, _ := strings.Cut(line, "@")
	res, _, _ = strings.Cut(res, "#")
	sub, _, _ = strings.Cut(sub, "#")
	return res, sub
}

// Changed returns a second model over the same types and relations: some
// permissions rewritten and some relationships added or removed, as a
// schema change or a data change would.
func (m *Model) Changed(seed int64) *Model {
	r := rand.New(rand.NewSource(seed))
	c := &Model{rng: r, acyclic: m.acyclic}
	for _, t := range m.types {
		ct := &typ{name: t.name, rels: t.rels, ids: t.ids}
		for _, p := range t.perms {
			ct.perms = append(ct.perms, &perm{name: p.name, expr: p.expr})
		}
		c.types = append(c.types, ct)
	}
	for _, t := range c.types[1:] {
		for j, p := range t.perms {
			if r.Intn(3) == 0 {
				c.cur = j
				p.expr = c.expr(t, 0)
			}
		}
	}
	c.render()
	c.Relationships = append([]string(nil), m.Relationships...)
	if r.Intn(2) == 0 {
		for k := 0; k < 2 && len(c.Relationships) > 1; k++ {
			i := r.Intn(len(c.Relationships))
			c.Relationships = append(c.Relationships[:i], c.Relationships[i+1:]...)
		}
		c.Relationships = c.relationships(c.Relationships, 1+r.Intn(5))
	}
	return c
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
