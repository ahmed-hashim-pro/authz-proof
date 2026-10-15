// Package spicedb cross-checks the engine against a real SpiceDB, through
// SpiceDB's HTTP API: it writes the same schema and relationships, asks
// SpiceDB every question the engine can answer, and counts disagreements.
package spicedb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ahmed-hashim-pro/authz-proof/engine"
	"github.com/ahmed-hashim-pro/authz-proof/gen"
	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

// Client talks to SpiceDB's HTTP gateway.
type Client struct {
	base string
	key  string
	http *http.Client
}

// NewClient returns a client for the gateway at base, such as
// http://localhost:8443, using a preshared key.
func NewClient(base, key string) *Client {
	return &Client{strings.TrimRight(base, "/"), key, &http.Client{Timeout: 5 * time.Minute}}
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Client) post(path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		var e apiError
		if json.Unmarshal(b, &e) == nil && e.Message != "" {
			return &Error{e.Code, e.Message}
		}
		return fmt.Errorf("%s: HTTP %d: %s", path, resp.StatusCode, b)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

// Error is an error SpiceDB returned.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("SpiceDB: %s", e.Message) }

type objRef struct {
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
}

type subjRef struct {
	Object           objRef `json:"object"`
	OptionalRelation string `json:"optionalRelation,omitempty"`
}

var defRE = regexp.MustCompile(`(?m)^\s*definition\s+([a-z0-9_/]+)`)

// Reset deletes every relationship of every type in the current schema, so
// a new schema can be written over it.
func (c *Client) Reset() error {
	var out struct {
		SchemaText string `json:"schemaText"`
	}
	err := c.post("/v1/schema/read", map[string]any{}, &out)
	if e, ok := err.(*Error); ok && e.Code == 5 {
		return nil // no schema yet
	}
	if err != nil {
		return err
	}
	for _, m := range defRE.FindAllStringSubmatch(out.SchemaText, -1) {
		err := c.post("/v1/relationships/delete", map[string]any{
			"relationshipFilter": map[string]any{"resourceType": m[1]},
		}, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteSchema replaces the schema.
func (c *Client) WriteSchema(text string) error {
	return c.post("/v1/schema/write", map[string]any{"schema": text}, nil)
}

// WriteRelationships writes relationships in batches.
func (c *Client) WriteRelationships(ts []rel.Tuple) error {
	for len(ts) > 0 {
		n := min(len(ts), 500)
		var updates []any
		for _, t := range ts[:n] {
			updates = append(updates, map[string]any{
				"operation": "OPERATION_TOUCH",
				"relationship": map[string]any{
					"resource": objRef{t.Resource.Type, t.Resource.ID},
					"relation": t.Relation,
					"subject":  subjRef{objRef{t.Subject.Type, t.Subject.ID}, t.Subject.Relation},
				},
			})
		}
		if err := c.post("/v1/relationships/write", map[string]any{"updates": updates}, nil); err != nil {
			return err
		}
		ts = ts[n:]
	}
	return nil
}

// Query is one check.
type Query struct {
	Resource rel.Object
	Name     string
	Subject  rel.Object
}

// Answer is SpiceDB's answer to one check: Has, or an error message.
type Answer struct {
	Has bool
	Err string
}

// CheckBulk asks SpiceDB a batch of checks at full consistency.
func (c *Client) CheckBulk(qs []Query) ([]Answer, error) {
	var out []Answer
	for len(qs) > 0 {
		n := min(len(qs), 100)
		var items []any
		for _, q := range qs[:n] {
			items = append(items, map[string]any{
				"resource":   objRef{q.Resource.Type, q.Resource.ID},
				"permission": q.Name,
				"subject":    subjRef{Object: objRef{q.Subject.Type, q.Subject.ID}},
			})
		}
		var resp struct {
			Pairs []struct {
				Item *struct {
					Permissionship string `json:"permissionship"`
				} `json:"item"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			} `json:"pairs"`
		}
		err := c.post("/v1/permissions/checkbulk", map[string]any{
			"consistency": map[string]any{"fullyConsistent": true},
			"items":       items,
		}, &resp)
		if err != nil {
			return nil, err
		}
		if len(resp.Pairs) != n {
			return nil, fmt.Errorf("SpiceDB answered %d of %d checks", len(resp.Pairs), n)
		}
		for _, p := range resp.Pairs {
			switch {
			case p.Error != nil:
				out = append(out, Answer{Err: p.Error.Message})
			case p.Item != nil && p.Item.Permissionship == "PERMISSIONSHIP_HAS_PERMISSION":
				out = append(out, Answer{Has: true})
			case p.Item != nil && p.Item.Permissionship == "PERMISSIONSHIP_NO_PERMISSION":
				out = append(out, Answer{})
			default:
				out = append(out, Answer{Err: fmt.Sprintf("unexpected answer %+v", p.Item)})
			}
		}
		qs = qs[n:]
	}
	return out, nil
}

// Summary counts the outcome of a cross-check.
type Summary struct {
	Schemas  int
	Checks   int
	Yes      int // checks both sides answered yes
	Disagree int
	Errors   int // checks SpiceDB could not answer
	// ErrorsWhereYes counts SpiceDB errors on checks authz-proof answers
	// yes; the rest are on checks it answers no.
	ErrorsWhereYes int
	Examples       []string
	// Refusals compares schemas the generator made that one side refused.
	BothRefused     int
	OnlyWeRefused   map[string]int // by reason
	OnlyTheyRefused int
}

func (s Summary) String() string {
	out := fmt.Sprintf("%d checks (%d yes), %d disagreements", s.Checks, s.Yes, s.Disagree)
	if s.Errors > 0 {
		out += fmt.Sprintf(", %d SpiceDB errors (%d where authz-proof says yes)", s.Errors, s.ErrorsWhereYes)
	}
	if s.BothRefused+s.OnlyTheyRefused+len(s.OnlyWeRefused) > 0 {
		out += fmt.Sprintf("\n  schemas refused by both: %d, by SpiceDB only: %d", s.BothRefused, s.OnlyTheyRefused)
		for reason, n := range s.OnlyWeRefused {
			out += fmt.Sprintf("\n  refused by authz-proof only (%s): %d", reason, n)
		}
	}
	for _, e := range s.Examples {
		out += "\n  " + e
	}
	return out
}

// Add adds another summary into s.
func (s *Summary) Add(o Summary) {
	s.Schemas += o.Schemas
	s.Checks += o.Checks
	s.Yes += o.Yes
	s.Disagree += o.Disagree
	s.Errors += o.Errors
	s.ErrorsWhereYes += o.ErrorsWhereYes
	s.BothRefused += o.BothRefused
	s.OnlyTheyRefused += o.OnlyTheyRefused
	for k, v := range o.OnlyWeRefused {
		if s.OnlyWeRefused == nil {
			s.OnlyWeRefused = map[string]int{}
		}
		s.OnlyWeRefused[k] += v
	}
	for _, e := range o.Examples {
		if len(s.Examples) < 10 {
			s.Examples = append(s.Examples, e)
		}
	}
}

// Crosscheck loads a schema and relationships into SpiceDB and into the
// engine, and compares every check: each relation and permission of each
// object, for every subject a check could succeed for, including one
// object that appears in no relationship.
func Crosscheck(c *Client, schemaText string, lines []string) (Summary, error) {
	s, err := schema.Parse(schemaText)
	if err != nil {
		return Summary{}, err
	}
	st, err := rel.Parse(s, strings.Join(lines, "\n"))
	if err != nil {
		return Summary{}, err
	}
	if err := c.Reset(); err != nil {
		return Summary{}, fmt.Errorf("resetting SpiceDB: %w", err)
	}
	if err := c.WriteSchema(schemaText); err != nil {
		return Summary{}, fmt.Errorf("SpiceDB refused the schema: %w", err)
	}
	if err := c.WriteRelationships(st.Tuples()); err != nil {
		return Summary{}, fmt.Errorf("SpiceDB refused the relationships: %w", err)
	}
	e := engine.New(s, st)
	var qs []Query
	subjects := rel.Universe(s.DirectTypes(), st)
	for _, d := range s.Defs {
		for _, obj := range st.Objects(d.Name) {
			for _, name := range d.Names() {
				for _, sub := range subjects {
					qs = append(qs, Query{obj, name, sub})
				}
			}
		}
	}
	answers, err := c.CheckBulk(qs)
	if err != nil {
		return Summary{}, err
	}
	sum := Summary{Schemas: 1, Checks: len(qs)}
	for i, q := range qs {
		a := answers[i]
		mine := e.Check(q.Resource, q.Name, q.Subject)
		switch {
		case a.Err != "":
			sum.Errors++
			if mine {
				sum.ErrorsWhereYes++
			}
			if len(sum.Examples) < 5 {
				sum.Examples = append(sum.Examples, fmt.Sprintf("%s#%s@%s: SpiceDB error: %s", q.Resource, q.Name, q.Subject, a.Err))
			}
		case a.Has != mine:
			sum.Disagree++
			if len(sum.Examples) < 5 {
				sum.Examples = append(sum.Examples, fmt.Sprintf("%s#%s@%s: SpiceDB %v, authz-proof %v", q.Resource, q.Name, q.Subject, a.Has, mine))
			}
		case mine:
			sum.Yes++
		}
	}
	return sum, nil
}

// refusal reasons, by a phrase in authz-proof's error.
var reasons = []struct{ phrase, name string }{
	{"through an exclusion", "depends on itself through an exclusion"},
	{"in a loop", "permissions alias each other in a loop"},
	{"wildcards to be included", "wildcard through a subject set"},
}

// compareRefusal writes a schema authz-proof refused to SpiceDB, to see
// whether SpiceDB refuses it too.
func compareRefusal(c *Client, text string, ours error, sum *Summary) error {
	if err := c.Reset(); err != nil {
		return err
	}
	err := c.WriteSchema(text)
	if _, ok := err.(*Error); err != nil && !ok {
		return err
	}
	if err != nil {
		sum.BothRefused++
		return nil
	}
	reason := ours.Error()
	for _, r := range reasons {
		if strings.Contains(reason, r.phrase) {
			reason = r.name
		}
	}
	if sum.OnlyWeRefused == nil {
		sum.OnlyWeRefused = map[string]int{}
	}
	sum.OnlyWeRefused[reason]++
	return nil
}

// CrosscheckRandom cross-checks n random models, and for each seed also
// writes the schema gen.New makes, to see whether SpiceDB refuses the
// schemas authz-proof refuses. The models' relationships never lead from
// an object back to itself: on cyclic data SpiceDB answers "max depth
// exceeded" instead of no, and deep recursion can stall it.
func CrosscheckRandom(c *Client, n int, w io.Writer) (Summary, error) {
	var total Summary
	for seed := int64(1); seed <= int64(n); seed++ {
		// Schemas only: does SpiceDB refuse what authz-proof refuses?
		if m := gen.New(seed); true {
			if _, err := schema.Parse(m.Schema); err != nil {
				if err := compareRefusal(c, m.Schema, err, &total); err != nil {
					return total, err
				}
			} else if err := c.Reset(); err != nil {
				return total, err
			} else if err := c.WriteSchema(m.Schema); err != nil {
				total.OnlyTheyRefused++
				if len(total.Examples) < 10 {
					total.Examples = append(total.Examples, fmt.Sprintf("seed %d: SpiceDB refused a schema authz-proof accepts: %v", seed, err))
				}
			}
		}
		var models []*gen.Model
		for k := int64(0); len(models) == 0; k++ {
			m := gen.NewAcyclic(seed*1000 + k)
			if _, err := schema.Parse(m.Schema); err != nil {
				continue
			}
			models = append(models, m)
			for j := int64(0); j < 20; j++ {
				ch := m.Changed(seed*1000 + k + j*7919)
				if _, err := schema.Parse(ch.Schema); err == nil {
					models = append(models, ch)
					break
				}
			}
		}
		for _, m := range models {
			sum, err := Crosscheck(c, m.Schema, m.Relationships)
			if err != nil {
				return total, fmt.Errorf("seed %d: %w\nschema:\n%s", seed, err, m.Schema)
			}
			if sum.Disagree > 0 || sum.Errors > 0 {
				fmt.Fprintf(w, "seed %d: %s\nschema:\n%srelationships:\n  %s\n", seed, sum, m.Schema, strings.Join(m.Relationships, "\n  "))
			}
			total.Add(sum)
		}
	}
	return total, nil
}
