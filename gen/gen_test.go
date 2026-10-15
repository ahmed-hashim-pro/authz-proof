package gen

import (
	"strings"
	"testing"
)

func TestDeterministic(t *testing.T) {
	for seed := int64(1); seed < 50; seed++ {
		a, b := New(seed), New(seed)
		if a.Schema != b.Schema || strings.Join(a.Relationships, ",") != strings.Join(b.Relationships, ",") {
			t.Fatalf("seed %d is not reproducible", seed)
		}
		c, d := a.Changed(seed), b.Changed(seed)
		if c.Schema != d.Schema || strings.Join(c.Relationships, ",") != strings.Join(d.Relationships, ",") {
			t.Fatalf("seed %d: Changed is not reproducible", seed)
		}
	}
}

func TestAcyclicHasNoCycles(t *testing.T) {
	for seed := int64(1); seed < 500; seed++ {
		for _, m := range []*Model{NewAcyclic(seed), NewAcyclic(seed).Changed(seed)} {
			edges := map[string][]string{}
			for _, line := range m.Relationships {
				r, s := objectsOf(line)
				edges[r] = append(edges[r], s)
			}
			state := map[string]int{}
			var visit func(string) bool
			visit = func(o string) bool {
				if state[o] == 1 {
					return true
				}
				if state[o] == 2 {
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
					t.Fatalf("seed %d: cycle through %s in %v", seed, o, m.Relationships)
				}
			}
		}
	}
}
