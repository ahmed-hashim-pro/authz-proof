package schema

import (
	"strings"
	"testing"
)

func perm(t *testing.T, src, def, name string) *Permission {
	t.Helper()
	s, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	return s.Def(def).Permission(name)
}

const doc = `definition user {}

definition doc {
	relation aaa: user
	relation bbb: user
	relation ccc: user
	permission ppp = %s
}
`

// SpiceDB binds + before & before -, all left-associative. These are the
// readings SpiceDB v1.56.2 gave when asked the same questions.
func TestPrecedenceMatchesSpiceDB(t *testing.T) {
	cases := map[string]string{
		"aaa + bbb - ccc":       "(aaa + bbb) - ccc",
		"aaa - bbb + ccc":       "aaa - (bbb + ccc)",
		"aaa & bbb + ccc":       "aaa & (bbb + ccc)",
		"aaa + bbb & ccc":       "(aaa + bbb) & ccc",
		"aaa - bbb & ccc":       "aaa - (bbb & ccc)",
		"aaa - bbb - ccc":       "(aaa - bbb) - ccc",
		"(aaa - bbb) + ccc":     "(aaa - bbb) + ccc",
		"aaa + bbb + ccc":       "aaa + bbb + ccc",
		"aaa - (bbb - ccc)":     "aaa - (bbb - ccc)",
		"((aaa))":               "aaa",
		"aaa & bbb & ccc - aaa": "(aaa & bbb & ccc) - aaa",
	}
	for in, want := range cases {
		p := perm(t, strings.Replace(doc, "%s", in, 1), "doc", "ppp")
		if got := p.Expr.String(); got != want {
			t.Errorf("%s: parsed as %s, want %s", in, got, want)
		}
	}
}

func TestMixedOperatorsWarn(t *testing.T) {
	s, err := Parse(strings.Replace(doc, "%s", "aaa - bbb + ccc", 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "`aaa - bbb + ccc` means `aaa - (bbb + ccc)`") {
		t.Errorf("warnings %q", s.Warnings)
	}
	for _, ok := range []string{"aaa + bbb + ccc", "(aaa - bbb) + ccc", "aaa - (bbb + ccc)"} {
		s, err := Parse(strings.Replace(doc, "%s", ok, 1))
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Warnings) != 0 {
			t.Errorf("%s: unexpected warning %q", ok, s.Warnings)
		}
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]string{
		"definition us {}": "must match",
		"definition user {}\ndefinition doc {\n\trelation ab: user\n}":                                                                                             "must match",
		"definition user {}\ndefinition doc {\n\trelation viewer: group\n}":                                                                                        "not defined",
		"definition user {}\ndefinition doc {\n\trelation viewer: user#member\n}":                                                                                  "has no member",
		"definition user {}\ndefinition doc {\n\trelation viewer: user\n\tpermission view = owner\n}":                                                              "does not have",
		"definition user {}\ndefinition doc {\n\trelation viewer: user }":                                                                                          "end of line",
		"definition user {}\ndefinition doc {\n\trelation viewer: user with ip\n}":                                                                                 "caveats",
		"caveat ip(x int) { x == 1 }":                                                                                                                              "caveats",
		"definition user {}\ndefinition doc {\n\trelation viewer: user\n\tpermission view = viewer\n\tpermission xyz = view->viewer\n}":                            "left of an arrow",
		"definition user {}\ndefinition doc {\n\trelation parent: user:*\n\tpermission view = parent->view\n}":                                                     "wildcard relations cannot be used",
		"definition user {}\ndefinition grp {\n\trelation member: user\n}\ndefinition doc {\n\trelation parent: grp#member\n\tpermission view = parent->member\n}": "not supported",
		"definition user {}\ndefinition doc {\n\trelation viewer: user\n\tpermission aaa = bbb\n\tpermission bbb = aaa\n}":                                         "aliases of each other in a loop",
		"definition user {}\ndefinition doc {\n\trelation viewer: user\n\tpermission view = viewer - view\n}":                                                      "through an exclusion",
		"definition user {}\ndefinition doc {\n\trelation viewer: user\n\tpermission view = nil\n}":                                                                "nil is not supported",
		"definition user {}\ndefinition doc {\n\trelation parent: doc\n\tpermission view = parent.any(view)\n}":                                                    "not supported",
		"definition user {}\ndefinition grp {\n\trelation member: user:*\n}\ndefinition doc {\n\trelation viewer: grp#member\n}":                                   "wildcards",
		"definition user {}\ndefinition user {}":                                                                                                                   "defined twice",
		"definition user {}\ndefinition doc {\n\trelation viewer: user\n\tpermission viewer = viewer\n}":                                                           "defined twice",
	}
	for src, want := range cases {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error containing %q", src, err, want)
		}
	}
}

// SpiceDB accepts these, so authz-proof must too.
func TestAcceptsWhatSpiceDBAccepts(t *testing.T) {
	cases := []string{
		// A permission may refer to itself inside a larger expression.
		"definition user {}\ndefinition doc {\n\trelation viewer: user\n\tpermission view = view + viewer\n}",
		// Subject sets on the same definition may include a wildcard.
		"definition user {}\ndefinition doc {\n\trelation viewer: user | user:* | doc#viewer\n}",
		// A subject set may name a permission.
		"definition user {}\ndefinition grp {\n\trelation member: user | user:*\n\tpermission members = member\n}\ndefinition doc {\n\trelation viewer: grp#members\n}",
		// An arrow to a name no target type has: always empty, with a warning.
		"definition user {}\ndefinition doc {\n\trelation parent: user\n\tpermission view = parent->view\n}",
		// Comments, prefixes, line breaks inside parentheses.
		"/** users */\ndefinition acme/user {}\n// docs\ndefinition acme/doc {\n\trelation viewer: acme/user /* inline */\n\tpermission view = (\n\t\tviewer +\n\t\tviewer\n\t)\n}",
	}
	for _, src := range cases {
		if _, err := Parse(src); err != nil {
			t.Errorf("%q: %v", src, err)
		}
	}
	s, _ := Parse(cases[3])
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "always empty") {
		t.Errorf("warnings %q", s.Warnings)
	}
}

func TestOrderPutsDependenciesFirst(t *testing.T) {
	s, err := Parse(`definition user {}
definition grp {
	relation member: user | grp#member
}
definition doc {
	relation viewer: grp#member
	relation banned: user
	permission view = viewer - banned
}
`)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[Node]int{}
	for i, g := range s.Order {
		for _, n := range g {
			pos[n] = i
		}
	}
	for _, dep := range [][2]Node{
		{{"grp", "member"}, {"doc", "viewer"}},
		{{"doc", "viewer"}, {"doc", "view"}},
		{{"doc", "banned"}, {"doc", "view"}},
	} {
		if pos[dep[0]] >= pos[dep[1]] {
			t.Errorf("%s should come before %s in %v", dep[0], dep[1], s.Order)
		}
	}
}
