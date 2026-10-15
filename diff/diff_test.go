package diff

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ahmed-hashim-pro/authz-proof/engine"
	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

func load(t *testing.T, schemaFile, relFile string) *engine.Engine {
	t.Helper()
	sb, err := os.ReadFile("../examples/drive/" + schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := schema.Parse(string(sb))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := os.ReadFile("../examples/drive/" + relFile)
	if err != nil {
		t.Fatal(err)
	}
	st, err := rel.Parse(s, string(rb))
	if err != nil {
		t.Fatal(err)
	}
	return engine.New(s, st)
}

func summary(r Result) string {
	var parts []string
	for _, c := range r.Changes {
		v := "-"
		if c.Gained {
			v = "+"
		}
		parts = append(parts, v+c.Resource.String()+"#"+c.Name+"@"+c.Subject.Display())
	}
	return strings.Join(parts, " ")
}

func TestRefactorGivesContractorsRestrictedDocuments(t *testing.T) {
	r := Compute(load(t, "schema.zed", "relationships.txt"), load(t, "schema-refactor.zed", "relationships.txt"))
	want := "+document:budget#view@user:bob +document:budget#view@user:carol " +
		"+document:offer-letters#view@user:bob +document:offer-letters#view@user:carol " +
		"+document:payroll#view@user:bob +document:payroll#view@user:carol"
	if got := summary(r); got != want {
		t.Errorf("changes\n %s\nwant\n %s", got, want)
	}
	for _, c := range r.Changes {
		if c.Blocker == nil || c.Blocker.Subtracted != "restricted->contractor" {
			t.Errorf("%v: the old schema's blocker should be named", c)
		}
	}
}

func TestReorderingChangesNothing(t *testing.T) {
	r := Compute(load(t, "schema.zed", "relationships.txt"), load(t, "schema-reordered.zed", "relationships.txt"))
	if len(r.Changes) != 0 {
		t.Errorf("reordering a union changed access: %s", summary(r))
	}
}

func TestDroppedParenthesesLoseInheritedAccess(t *testing.T) {
	r := Compute(load(t, "schema.zed", "relationships.txt"), load(t, "schema-no-parens.zed", "relationships.txt"))
	if r.Gained() != 0 || r.Lost() != 30 {
		t.Errorf("gained %d, lost %d; want 0 and 30", r.Gained(), r.Lost())
	}
}

func TestAllowlist(t *testing.T) {
	old := load(t, "schema.zed", "relationships.txt")
	rules, err := ParseAllowlist(mustRead(t, "allow-pr213.txt"))
	if err != nil {
		t.Fatal(err)
	}
	r := Compute(old, load(t, "schema.zed", "relationships-pr213.txt"))
	r.Apply(rules)
	if r.Gained() != 8 {
		t.Errorf("PR 213 gained %d, want 8", r.Gained())
	}
	for _, c := range r.Changes {
		if c.Allowed == nil {
			t.Errorf("%s#%s@%s should be allowed", c.Resource, c.Name, c.Subject)
		}
	}
	r = Compute(old, load(t, "schema.zed", "relationships-pr213-slip.txt"))
	r.Apply(rules)
	unexpected := 0
	for _, c := range r.Changes {
		if c.Allowed == nil {
			unexpected++
		}
	}
	if unexpected != 16 {
		t.Errorf("the slip has %d unexpected gains, want 16", unexpected)
	}
}

func TestAllowlistParsing(t *testing.T) {
	for text, want := range map[string]string{
		"document:x#view@user:bob":         "say why",
		"document:x#view user:bob  reason": "not of the form",
		"document:[#view@user:bob  reason": "bad pattern",
	} {
		if _, err := ParseAllowlist(text); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", text, err, want)
		}
	}
	rules, err := ParseAllowlist("// comment\n\ndocument:{a,b*}#view@user:*  ok\n")
	if err != nil || len(rules) != 1 {
		t.Fatal(rules, err)
	}
	for id, want := range map[string]bool{"a": true, "bee": true, "c": false} {
		c := Change{Resource: rel.Object{Type: "document", ID: id}, Name: "view", Subject: rel.Object{Type: "user", ID: rel.Unseen}}
		if rules[0].Matches(c) != want {
			t.Errorf("%s: match %v", id, !want)
		}
	}
}

func TestRendering(t *testing.T) {
	r := Compute(load(t, "schema.zed", "relationships.txt"), load(t, "schema-refactor.zed", "relationships.txt"))
	var b bytes.Buffer
	Text(&b, r, TextOptions{})
	out := b.String()
	for _, want := range []string{
		"6 grants gained, 0 lost",
		"GAINED  document:payroll#view        user:bob, user:carol",
		"before: removed on document:payroll by `restricted->contractor`, because",
		"GAINED document:payroll#view @ user:bob   (1 more subject; --all-paths shows each)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
	b.Reset()
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"blocked_by": "document:payroll: restricted->contractor: user:bob`) {
		t.Errorf("json:\n%s", b.String())
	}
}

func mustRead(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../examples/drive/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
