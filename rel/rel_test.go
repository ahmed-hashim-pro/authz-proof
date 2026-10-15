package rel

import (
	"strings"
	"testing"

	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

const src = `definition user {}
definition team {
	relation member: user | team#member
}
definition doc {
	relation viewer: user | user:* | team#member
	permission view = viewer
}
`

func TestParse(t *testing.T) {
	s, err := schema.Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Parse(s, `
// comment
team:eng#member@user:alice
doc:readme#viewer@team:eng#member   // trailing comment
doc:readme#viewer@user:*
doc:readme#viewer@user:*
`)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(st.Tuples()); n != 3 {
		t.Errorf("%d tuples, want 3 (duplicates dropped)", n)
	}
	if got := st.Objects("doc"); len(got) != 1 || got[0].ID != "readme" {
		t.Errorf("objects %v", got)
	}
	if got := Universe([]string{"user"}, st); len(got) != 2 || got[1].ID != Unseen {
		t.Errorf("universe %v", got)
	}
}

func TestRefusals(t *testing.T) {
	s, _ := schema.Parse(src)
	cases := map[string]string{
		"doc:readme#view@user:alice":      "is a permission",
		"doc:readme#owner@user:alice":     "has no relation",
		"page:readme#viewer@user:alice":   "not defined",
		"team:eng#member@user:*":          "allows user | team#member, not user:*",
		"doc:readme#viewer@team:eng":      "not team",
		"doc:readme viewer user:alice":    "not of the form",
		"doc:read me#viewer@user:alice":   "not of the form",
		"doc:a$b#viewer@user:alice":       "not allowed",
		"doc:readme#viewer@user:*#member": "wildcard subject cannot have a relation",
		"doc:readme#viewer@user:_unseen_": "reserved",
	}
	for line, want := range cases {
		_, err := Parse(s, line)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", line, err, want)
		}
	}
}
