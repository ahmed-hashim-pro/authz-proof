package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// TextOptions controls the text report.
type TextOptions struct {
	// AllPaths prints the chain for every subject, not only the first of
	// each resource#name.
	AllPaths bool
}

type group struct {
	gained   bool
	resource string
	changes  []Change
}

func groups(r Result) []group {
	var out []group
	idx := map[string]int{}
	for _, c := range r.Changes {
		k := fmt.Sprintf("%v %s#%s", c.Gained, c.Resource, c.Name)
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, group{gained: c.Gained, resource: c.Resource.String() + "#" + c.Name})
		}
		out[i].changes = append(out[i].changes, c)
	}
	return out
}

// Text writes the human-readable report.
func Text(w io.Writer, r Result, opt TextOptions) {
	fmt.Fprintf(w, "compared %d checks per side: every relation and permission of %d objects, for %d subjects\n",
		r.Checks, r.Objects, r.Subjects)
	if len(r.Changes) == 0 {
		fmt.Fprintln(w, "no access changes")
		return
	}
	fmt.Fprintf(w, "%d grants gained, %d lost\n", r.Gained(), r.Lost())
	gs := groups(r)
	width := 0
	for _, g := range gs {
		width = max(width, len(g.resource))
	}
	fmt.Fprintln(w)
	for _, g := range gs {
		subs := make([]string, len(g.changes))
		for i, c := range g.changes {
			subs[i] = c.Subject.Display()
			if c.Allowed != nil {
				subs[i] += " (allowed)"
			}
		}
		fmt.Fprintf(w, "%-7s %-*s  %s\n", verb(g.gained), width, g.resource, strings.Join(subs, ", "))
	}
	for _, g := range gs {
		for i, c := range g.changes {
			more := ""
			if !opt.AllPaths {
				if i > 0 {
					break
				}
				if n := len(g.changes) - 1; n == 1 {
					more = "   (1 more subject; --all-paths shows each)"
				} else if n > 1 {
					more = fmt.Sprintf("   (%d more subjects; --all-paths shows each)", n)
				}
			}
			fmt.Fprintln(w)
			why(w, c, more)
		}
	}
}

func verb(gained bool) string {
	if gained {
		return "GAINED"
	}
	return "LOST"
}

func why(w io.Writer, c Change, more string) {
	side := "now"
	if !c.Gained {
		side = "before"
	}
	fmt.Fprintf(w, "%s %s#%s @ %s%s\n", verb(c.Gained), c.Resource, c.Name, c.Subject.Display(), more)
	if c.NameOnlyOneSide {
		if c.Gained {
			fmt.Fprintf(w, "  %s#%s is new in this schema\n", c.Resource.Type, c.Name)
		} else {
			fmt.Fprintf(w, "  %s#%s no longer exists\n", c.Resource.Type, c.Name)
		}
	}
	fmt.Fprintf(w, "  %s:\n", side)
	for _, l := range c.Proof.Lines("    ") {
		fmt.Fprintln(w, l)
	}
	other := "before"
	if !c.Gained {
		other = "now"
	}
	if c.Blocker != nil {
		fmt.Fprintf(w, "  %s: removed on %s by `%s`, because\n    %s\n", other, c.Blocker.Object, c.Blocker.Subtracted, c.Blocker.Proof.Inline())
	} else if !c.NameOnlyOneSide {
		fmt.Fprintf(w, "  %s: no chain of relationships led there\n", other)
	}
	if c.Allowed != nil {
		fmt.Fprintf(w, "  allowed by line %d: %s\n", c.Allowed.Line, c.Allowed.Reason)
	}
}

type jsonChange struct {
	Change   string `json:"change"`
	Resource string `json:"resource"`
	Name     string `json:"name"`
	Subject  string `json:"subject"`
	Path     string `json:"path"`
	Blocked  string `json:"blocked_by,omitempty"`
	Allowed  string `json:"allowed,omitempty"`
}

// JSON writes the changes as a JSON array.
func JSON(w io.Writer, r Result) error {
	out := []jsonChange{}
	for _, c := range r.Changes {
		j := jsonChange{Change: strings.ToLower(verb(c.Gained)), Resource: c.Resource.String(), Name: c.Name,
			Subject: c.Subject.Display(), Path: c.Proof.Inline()}
		if c.Blocker != nil {
			j.Blocked = c.Blocker.Object.String() + ": " + c.Blocker.Subtracted + ": " + c.Blocker.Proof.Inline()
		}
		if c.Allowed != nil {
			j.Allowed = c.Allowed.Reason
		}
		out = append(out, j)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}
