package engine

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
)

// Node is one node of an expansion tree. Kind is "relation",
// "permission", "arrow", "union", "intersection", "exclusion" or
// "cycle" (the same goal already appears higher up this branch, so it
// adds nothing here).
type Node struct {
	Kind     string
	Object   rel.Object
	Name     string
	Direct   []rel.Subject // relation: direct and wildcard subjects
	Children []*Node
}

// ErrTooBig is returned when an expansion passes its node budget.
var ErrTooBig = errors.New("expansion has more than 100,000 nodes")

// Expand returns the tree of everything that grants name on resource.
func (e *Engine) Expand(resource rel.Object, name string) (*Node, error) {
	x := &expander{e: e, onPath: map[goal]bool{}, budget: 100000}
	n := x.goal(goal{resource, name})
	if x.budget < 0 {
		return nil, ErrTooBig
	}
	return n, nil
}

type expander struct {
	e      *Engine
	onPath map[goal]bool
	budget int
}

func (x *expander) goal(g goal) *Node {
	x.budget--
	if x.budget < 0 {
		return &Node{Kind: "cycle", Object: g.obj, Name: g.name}
	}
	if x.onPath[g] {
		return &Node{Kind: "cycle", Object: g.obj, Name: g.name}
	}
	x.onPath[g] = true
	defer delete(x.onPath, g)
	d := x.e.Schema.Def(g.obj.Type)
	if d == nil || !d.Has(g.name) {
		return &Node{Kind: "union", Object: g.obj, Name: g.name}
	}
	if d.Relation(g.name) != nil {
		n := &Node{Kind: "relation", Object: g.obj, Name: g.name}
		for _, sub := range x.e.Store.Subjects(g.obj, g.name) {
			if sub.Relation == "" {
				n.Direct = append(n.Direct, sub)
			} else {
				n.Children = append(n.Children, x.goal(goal{sub.Object, sub.Relation}))
			}
		}
		return n
	}
	return &Node{Kind: "permission", Object: g.obj, Name: g.name,
		Children: []*Node{x.expr(g.obj, d.Permission(g.name).Expr)}}
}

func (x *expander) expr(obj rel.Object, e schema.Expr) *Node {
	switch e := e.(type) {
	case schema.Ref:
		return x.goal(goal{obj, e.Name})
	case schema.Arrow:
		n := &Node{Kind: "arrow", Object: obj, Name: e.String()}
		for _, sub := range x.e.Store.Subjects(obj, e.Tupleset) {
			if x.e.Schema.Has(sub.Type, e.Target) {
				n.Children = append(n.Children, x.goal(goal{sub.Object, e.Target}))
			}
		}
		return n
	case *schema.Op:
		n := &Node{Kind: e.Kind.Word(), Object: obj}
		for _, a := range e.Args {
			n.Children = append(n.Children, x.expr(obj, a))
		}
		return n
	}
	return &Node{Kind: "union", Object: obj}
}

// Has reports whether subject is in the set the tree describes.
func (n *Node) Has(subject rel.Object) bool {
	switch n.Kind {
	case "cycle":
		return false
	case "relation":
		for _, s := range n.Direct {
			if s.Object == subject || s.Wildcard() && s.Type == subject.Type {
				return true
			}
		}
		fallthrough
	case "permission", "arrow", "union":
		for _, c := range n.Children {
			if c.Has(subject) {
				return true
			}
		}
		return false
	case "intersection":
		for _, c := range n.Children {
			if !c.Has(subject) {
				return false
			}
		}
		return len(n.Children) > 0
	case "exclusion":
		return n.Children[0].Has(subject) && !n.Children[1].Has(subject)
	}
	return false
}

// Render draws the tree with box-drawing branches.
func (n *Node) Render() string {
	var b strings.Builder
	n.render(&b, "", "", "")
	return b.String()
}

func (n *Node) label() string {
	switch n.Kind {
	case "relation":
		parts := make([]string, len(n.Direct))
		for i, s := range n.Direct {
			parts[i] = s.String()
		}
		l := n.Object.String() + "#" + n.Name
		if len(parts) > 0 {
			l += "  " + strings.Join(parts, ", ")
		}
		return l
	case "permission":
		return n.Object.String() + "#" + n.Name
	case "arrow":
		return n.Name
	case "cycle":
		return n.Object.String() + "#" + n.Name + "  (already above; adds nothing)"
	}
	return fmt.Sprintf("%s", n.Kind)
}

func (n *Node) render(b *strings.Builder, first, rest, _ string) {
	b.WriteString(first + n.label() + "\n")
	for i, c := range n.Children {
		if i == len(n.Children)-1 {
			c.render(b, rest+"└─ ", rest+"   ", "")
		} else {
			c.render(b, rest+"├─ ", rest+"│  ", "")
		}
	}
}
