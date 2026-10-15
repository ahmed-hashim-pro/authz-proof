package engine

import (
	"os"
	"strings"
	"testing"

	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

func drive(t *testing.T, schemaFile string) *Engine {
	t.Helper()
	sb, err := os.ReadFile("../examples/drive/" + schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	s, err := schema.Parse(string(sb))
	if err != nil {
		t.Fatal(err)
	}
	rb, err := os.ReadFile("../examples/drive/relationships.txt")
	if err != nil {
		t.Fatal(err)
	}
	st, err := rel.Parse(s, string(rb))
	if err != nil {
		t.Fatal(err)
	}
	return New(s, st)
}

func obj(s string) rel.Object {
	t, id, _ := strings.Cut(s, ":")
	return rel.Object{Type: t, ID: id}
}

func TestDriveChecks(t *testing.T) {
	e := drive(t, "schema.zed")
	cases := []struct {
		res, name, sub string
		want           bool
	}{
		{"document:payroll", "view", "user:alice", true}, // HR edits the hr folder
		{"document:payroll", "view", "user:erin", true},  // staff see the company folder
		{"document:payroll", "view", "user:bob", false},  // contractor, restricted document
		{"document:handbook", "view", "user:bob", true},  // contractor, unrestricted
		{"document:payroll", "edit", "user:alice", true}, // edit is not restricted
		{"document:payroll", "edit", "user:erin", false}, // erin edits eng only
		{"document:design-review", "view", "user:carol", true},
		{"document:status-page", "view", "user:zed", true}, // user:* covers users never mentioned
		{"document:status-page", "view", "team:eng", false},
		{"team:staff", "member", "user:dana", true}, // nested team
	}
	for _, c := range cases {
		if got := e.Check(obj(c.res), c.name, obj(c.sub)); got != c.want {
			t.Errorf("%s#%s@%s = %v, want %v", c.res, c.name, c.sub, got, c.want)
		}
	}
}

func TestExplainFindsTheShortestChain(t *testing.T) {
	e := drive(t, "schema-refactor.zed")
	p, ok := e.Explain(obj("document:payroll"), "view", obj("user:bob"))
	if !ok {
		t.Fatal("bob should have view on payroll under the refactor")
	}
	want := "user:bob → team:contractors#member → organization:acme#member → folder:company#viewer → folder:company#view → folder:hr#view → document:payroll#view"
	if got := p.Inline(); got != want {
		t.Errorf("chain\n %s\nwant\n %s", got, want)
	}
	lines := strings.Join(p.Lines(""), "\n")
	if !strings.Contains(lines, "folder:hr#view") || !strings.Contains(lines, "via parent") {
		t.Errorf("lines:\n%s", lines)
	}
	if _, ok := e.Explain(obj("document:payroll"), "view", obj("user:nobody")); ok {
		t.Error("explained a check that fails")
	}
}

func TestWhyNotNamesTheExclusion(t *testing.T) {
	e := drive(t, "schema.zed")
	b, ok := e.WhyNot(obj("document:payroll"), "view", obj("user:bob"))
	if !ok {
		t.Fatal("no blocker found")
	}
	if b.Subtracted != "restricted->contractor" || b.Object != obj("document:payroll") {
		t.Errorf("blocker %+v", b)
	}
	if got := b.Proof.Inline(); got != "user:bob → team:contractors#member → organization:acme#contractor" {
		t.Errorf("blocker chain %s", got)
	}
	if _, ok := e.WhyNot(obj("document:payroll"), "edit", obj("user:erin")); ok {
		t.Error("erin simply has no chain to edit payroll; nothing was subtracted")
	}
}

func TestLookups(t *testing.T) {
	e := drive(t, "schema.zed")
	var got []string
	for _, o := range e.LookupResources("document", "view", obj("user:bob")) {
		got = append(got, o.ID)
	}
	if strings.Join(got, ",") != "design-review,handbook,roadmap,status-page" {
		t.Errorf("bob can view %v", got)
	}
	subs := e.LookupSubjects(obj("document:status-page"), "view", "user")
	if !subs.Wildcard || len(subs.Except) != 0 {
		t.Errorf("status-page is public: %+v", subs)
	}
	subs = e.LookupSubjects(obj("document:payroll"), "view", "user")
	if subs.Wildcard || len(subs.Objects) != 4 {
		t.Errorf("payroll viewers %+v", subs)
	}
}

func TestExpandAgreesWithCheck(t *testing.T) {
	e := drive(t, "schema.zed")
	tree, err := e.Expand(obj("document:payroll"), "view")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob", "carol", "dana", "erin", "frank", "zed"} {
		sub := obj("user:" + u)
		if tree.Has(sub) != e.Check(obj("document:payroll"), "view", sub) {
			t.Errorf("expand and check disagree on %s", u)
		}
	}
	r := tree.Render()
	for _, want := range []string{"document:payroll#view", "exclusion", "restricted->contractor", "team:contractors#member  user:bob, user:carol"} {
		if !strings.Contains(r, want) {
			t.Errorf("expansion lacks %q:\n%s", want, r)
		}
	}
}

// A cycle of teams must neither loop forever nor invent members.
func TestCycles(t *testing.T) {
	s, err := schema.Parse(`definition user {}
definition team {
	relation member: user | team#member
}
`)
	if err != nil {
		t.Fatal(err)
	}
	st, err := rel.Parse(s, "team:a#member@team:b#member\nteam:b#member@team:a#member\nteam:b#member@user:carol\nteam:c#member@team:c#member")
	if err != nil {
		t.Fatal(err)
	}
	e := New(s, st)
	if !e.Check(obj("team:a"), "member", obj("user:carol")) {
		t.Error("carol is in b, and b is in a")
	}
	if e.Check(obj("team:c"), "member", obj("user:carol")) {
		t.Error("team c contains only itself")
	}
	if e.Check(obj("team:a"), "member", obj("user:dave")) {
		t.Error("dave is in no team")
	}
}
