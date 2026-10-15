package prop

import (
	"testing"

	"github.com/ahmed-hashim-pro/authz-proof/engine"
)

func TestEngineMatchesReference(t *testing.T) {
	n := int64(2000)
	if testing.Short() {
		n = 200
	}
	for seed := int64(1); seed <= n; seed++ {
		if err := Run(seed, engine.Correct); err != nil {
			if f, ok := err.(*Failure); ok {
				t.Fatalf("%v\nschema:\n%s\nrelationships:\n%v", f, f.Model.Schema, f.Model.Relationships)
			}
			t.Fatal(err)
		}
	}
}

// Every deliberate bug must be caught within 300 seeds.
func TestMutantsAreCaught(t *testing.T) {
	for _, m := range engine.Mutants {
		caught := false
		for seed := int64(1); seed <= 300 && !caught; seed++ {
			caught = Run(seed, m) != nil
		}
		if !caught {
			t.Errorf("%s: not caught in 300 seeds", m)
		}
	}
}
