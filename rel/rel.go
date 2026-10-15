// Package rel holds relationships in SpiceDB's text form,
// `document:readme#viewer@user:alice`, checked against a schema.
package rel

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

// Object is one object, such as user:alice.
type Object struct{ Type, ID string }

func (o Object) String() string { return o.Type + ":" + o.ID }

// Unseen is the ID of the stand-in object for "any object of this type
// that appears in no relationship". Every such object has exactly the
// same access, so one stand-in answers for all of them.
const Unseen = "_unseen_"

// Display prints an object, naming the stand-in for what it means.
func (o Object) Display() string {
	if o.ID == Unseen {
		return o.Type + ":*"
	}
	return o.String()
}

// Subject is the subject of a relationship: an object, every object of a
// type (ID "*"), or a subject set such as team:eng#member.
type Subject struct {
	Object
	Relation string
}

func (s Subject) Wildcard() bool { return s.ID == "*" }

func (s Subject) String() string {
	if s.Relation != "" {
		return s.Object.String() + "#" + s.Relation
	}
	return s.Object.String()
}

// Tuple is one relationship.
type Tuple struct {
	Resource Object
	Relation string
	Subject  Subject
}

func (t Tuple) String() string {
	return t.Resource.String() + "#" + t.Relation + "@" + t.Subject.String()
}

// SpiceDB's object ID rule.
var idRE = regexp.MustCompile(`^[a-zA-Z0-9/_|\-=+]+$`)

var lineRE = regexp.MustCompile(`^([^:#@\s]+):([^:#@\s]+)#([^:#@\s]+)@([^:#@\s]+):([^:#@\s]+)(?:#([^:#@\s]+))?$`)

// ParseTuple parses one relationship in SpiceDB's text form.
func ParseTuple(s string) (Tuple, error) {
	m := lineRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Tuple{}, fmt.Errorf("%q is not of the form type:id#relation@type:id[#relation]", s)
	}
	t := Tuple{Object{m[1], m[2]}, m[3], Subject{Object{m[4], m[5]}, m[6]}}
	if len(t.Resource.ID) > 1024 || len(t.Subject.ID) > 1024 {
		return t, fmt.Errorf("%q: object IDs are limited to 1024 characters", s)
	}
	if !idRE.MatchString(t.Resource.ID) {
		return t, fmt.Errorf("%q: object ID %q is not allowed", s, t.Resource.ID)
	}
	if !idRE.MatchString(t.Subject.ID) && !t.Subject.Wildcard() {
		return t, fmt.Errorf("%q: object ID %q is not allowed", s, t.Subject.ID)
	}
	if t.Resource.ID == Unseen || t.Subject.ID == Unseen {
		return t, fmt.Errorf("%q: the ID %s is reserved", s, Unseen)
	}
	if t.Subject.Wildcard() && t.Subject.Relation != "" {
		return t, fmt.Errorf("%q: a wildcard subject cannot have a relation", s)
	}
	return t, nil
}

// Store is a set of relationships, valid for one schema.
type Store struct {
	tuples  []Tuple
	byKey   map[key][]Subject
	objects map[string]map[string]bool
	seen    map[Tuple]bool
}

type key struct {
	obj Object
	rel string
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{byKey: map[key][]Subject{}, objects: map[string]map[string]bool{}, seen: map[Tuple]bool{}}
}

// Check reports why t is not allowed by s, if it isn't.
func Check(s *schema.Schema, t Tuple) error {
	d := s.Def(t.Resource.Type)
	if d == nil {
		return fmt.Errorf("%s: type %s is not defined", t, t.Resource.Type)
	}
	r := d.Relation(t.Relation)
	if r == nil {
		if d.Permission(t.Relation) != nil {
			return fmt.Errorf("%s: %s#%s is a permission; relationships can only be written to relations", t, d.Name, t.Relation)
		}
		return fmt.Errorf("%s: %s has no relation %s", t, d.Name, t.Relation)
	}
	want := schema.Allowed{Type: t.Subject.Type, Relation: t.Subject.Relation, Wildcard: t.Subject.Wildcard()}
	for _, a := range r.Allowed {
		if a == want {
			return nil
		}
	}
	allowed := make([]string, len(r.Allowed))
	for i, a := range r.Allowed {
		allowed[i] = a.String()
	}
	return fmt.Errorf("%s: %s#%s allows %s, not %s", t, d.Name, r.Name, strings.Join(allowed, " | "), want)
}

// Add adds t; adding the same relationship twice is a no-op.
func (st *Store) Add(t Tuple) {
	if st.seen[t] {
		return
	}
	st.seen[t] = true
	st.tuples = append(st.tuples, t)
	k := key{t.Resource, t.Relation}
	st.byKey[k] = append(st.byKey[k], t.Subject)
	st.note(t.Resource)
	if !t.Subject.Wildcard() {
		st.note(t.Subject.Object)
	}
}

func (st *Store) note(o Object) {
	if st.objects[o.Type] == nil {
		st.objects[o.Type] = map[string]bool{}
	}
	st.objects[o.Type][o.ID] = true
}

// Subjects returns the subjects of obj#relation.
func (st *Store) Subjects(obj Object, relation string) []Subject {
	return st.byKey[key{obj, relation}]
}

// Tuples returns every relationship, in the order added.
func (st *Store) Tuples() []Tuple { return st.tuples }

// Objects returns every object of type t that appears anywhere, sorted.
func (st *Store) Objects(t string) []Object {
	var out []Object
	for id := range st.objects[t] {
		out = append(out, Object{t, id})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Parse reads relationships, one per line; blank lines and lines starting
// with // or # are skipped. Every relationship must be valid for s.
func Parse(s *schema.Schema, text string) (*Store, error) {
	st := NewStore()
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " //"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		t, err := ParseTuple(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if err := Check(s, t); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		st.Add(t)
	}
	return st, sc.Err()
}

// Universe returns every object of the given types that appears in the
// stores, plus one stand-in per type for the objects that appear nowhere.
// Called with schema.DirectTypes, it is every subject a check could
// succeed for.
func Universe(types []string, stores ...*Store) []Object {
	var out []Object
	for _, t := range types {
		ids := map[string]bool{}
		for _, st := range stores {
			for _, o := range st.Objects(t) {
				ids[o.ID] = true
			}
		}
		var sorted []string
		for id := range ids {
			sorted = append(sorted, id)
		}
		sort.Strings(sorted)
		for _, id := range sorted {
			out = append(out, Object{t, id})
		}
		out = append(out, Object{t, Unseen})
	}
	return out
}
