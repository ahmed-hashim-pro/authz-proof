// Command authz-proof checks permissions over a SpiceDB-style schema and
// relationships, and works out exactly who gains and loses access when
// either changes.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ahmed-hashim-pro/authz-proof/diff"
	"github.com/ahmed-hashim-pro/authz-proof/engine"
	"github.com/ahmed-hashim-pro/authz-proof/prop"
	"github.com/ahmed-hashim-pro/authz-proof/rel"
	"github.com/ahmed-hashim-pro/authz-proof/schema"
	"github.com/ahmed-hashim-pro/authz-proof/spicedb"
)

const usage = `authz-proof: permissions over a SpiceDB-style schema, and what a change does to them

usage:
  authz-proof validate SCHEMA [RELATIONSHIPS]
  authz-proof check SCHEMA RELATIONSHIPS RESOURCE#PERMISSION@SUBJECT
  authz-proof lookup-resources SCHEMA RELATIONSHIPS TYPE#PERMISSION@SUBJECT
  authz-proof lookup-subjects SCHEMA RELATIONSHIPS RESOURCE#PERMISSION SUBJECT_TYPE
  authz-proof expand SCHEMA RELATIONSHIPS RESOURCE#PERMISSION
  authz-proof diff OLD_SCHEMA NEW_SCHEMA RELATIONSHIPS [flags]
  authz-proof hunt [--seeds N]
  authz-proof mutants [--seeds N]
  authz-proof crosscheck --endpoint URL [--key KEY] [--random N] [SCHEMA RELATIONSHIPS]...

diff flags:
  --new-relationships FILE  compare against these relationships instead (a data change)
  --allow FILE              grants that are expected to change, one pattern and reason per line
  --fail-on-gain            exit 1 if any grant is gained that --allow does not cover
  --fail-on-loss            exit 1 if any grant is lost that --allow does not cover
  --all-paths               print the chain for every changed grant
  --json                    print the changes as JSON

check exits 0 if the subject has the permission and 1 if not.
Exit status 2 means bad input.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cmds := map[string]func([]string, io.Writer) (int, error){
		"validate":         cmdValidate,
		"check":            cmdCheck,
		"lookup-resources": cmdLookupResources,
		"lookup-subjects":  cmdLookupSubjects,
		"expand":           cmdExpand,
		"diff":             cmdDiff,
		"hunt":             cmdHunt,
		"mutants":          cmdMutants,
		"crosscheck":       cmdCrosscheck,
	}
	f := cmds[args[0]]
	if f == nil {
		fmt.Fprintf(stderr, "authz-proof: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	code, err := f(args[1:], stdout)
	if err != nil {
		fmt.Fprintf(stderr, "authz-proof %s: %v\n", args[0], err)
		var u usageError
		if errors.As(err, &u) {
			return 2
		}
		if code == 0 {
			code = 2
		}
	}
	return code
}

// parseArgs splits flags from positional arguments; flags may come
// anywhere. valued lists the flags that take a value.
func parseArgs(args []string, valued, boolean []string) (map[string]string, []string, error) {
	flags := map[string]string{}
	var pos []string
	isIn := func(xs []string, s string) bool {
		for _, x := range xs {
			if x == s {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		switch {
		case isIn(boolean, name):
			flags[name] = "true"
		case isIn(valued, name):
			if !hasVal {
				if i+1 >= len(args) {
					return nil, nil, usageError{"--" + name + " needs a value"}
				}
				i++
				val = args[i]
			}
			flags[name] = val
		default:
			return nil, nil, usageError{"unknown flag " + a}
		}
	}
	return flags, pos, nil
}

func loadSchema(path string) (*schema.Schema, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := schema.Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func loadStore(s *schema.Schema, path string) (*rel.Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	st, err := rel.Parse(s, string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return st, nil
}

func load(schemaPath, relPath string) (*engine.Engine, error) {
	s, err := loadSchema(schemaPath)
	if err != nil {
		return nil, err
	}
	st, err := loadStore(s, relPath)
	if err != nil {
		return nil, err
	}
	return engine.New(s, st), nil
}

func parseObject(s string) (rel.Object, error) {
	t, id, ok := strings.Cut(s, ":")
	if !ok || t == "" || id == "" {
		return rel.Object{}, usageError{fmt.Sprintf("%q is not an object (type:id)", s)}
	}
	return rel.Object{Type: t, ID: id}, nil
}

// parseQuery parses RESOURCE#NAME[@SUBJECT].
func parseQuery(q string, wantSubject bool) (res rel.Object, name string, sub rel.Object, err error) {
	left, right, hasSub := strings.Cut(q, "@")
	if hasSub != wantSubject {
		if wantSubject {
			return res, "", sub, usageError{fmt.Sprintf("%q: expected RESOURCE#PERMISSION@SUBJECT", q)}
		}
		return res, "", sub, usageError{fmt.Sprintf("%q: expected RESOURCE#PERMISSION", q)}
	}
	obj, name, ok := strings.Cut(left, "#")
	if !ok || name == "" {
		return res, "", sub, usageError{fmt.Sprintf("%q: expected RESOURCE#PERMISSION", left)}
	}
	if res, err = parseObject(obj); err != nil {
		return
	}
	if wantSubject {
		sub, err = parseObject(right)
	}
	return
}

func checkName(s *schema.Schema, t, name string) error {
	if s.Def(t) == nil {
		return usageError{fmt.Sprintf("type %s is not defined", t)}
	}
	if !s.Has(t, name) {
		return usageError{fmt.Sprintf("%s has no relation or permission %s", t, name)}
	}
	return nil
}

func cmdValidate(args []string, w io.Writer) (int, error) {
	_, pos, err := parseArgs(args, nil, nil)
	if err != nil {
		return 2, err
	}
	if len(pos) < 1 || len(pos) > 2 {
		return 2, usageError{"usage: authz-proof validate SCHEMA [RELATIONSHIPS]"}
	}
	s, err := loadSchema(pos[0])
	if err != nil {
		return 2, err
	}
	nrel, nperm := 0, 0
	for _, d := range s.Defs {
		nrel += len(d.Relations)
		nperm += len(d.Perms)
	}
	fmt.Fprintf(w, "%s: %d definitions, %d relations, %d permissions\n", pos[0], len(s.Defs), nrel, nperm)
	for _, warn := range s.Warnings {
		fmt.Fprintf(w, "warning: %s\n", warn)
	}
	if len(pos) == 2 {
		st, err := loadStore(s, pos[1])
		if err != nil {
			return 2, err
		}
		fmt.Fprintf(w, "%s: %d relationships, all valid\n", pos[1], len(st.Tuples()))
	}
	return 0, nil
}

func cmdCheck(args []string, w io.Writer) (int, error) {
	_, pos, err := parseArgs(args, nil, nil)
	if err != nil {
		return 2, err
	}
	if len(pos) != 3 {
		return 2, usageError{"usage: authz-proof check SCHEMA RELATIONSHIPS RESOURCE#PERMISSION@SUBJECT"}
	}
	e, err := load(pos[0], pos[1])
	if err != nil {
		return 2, err
	}
	res, name, sub, err := parseQuery(pos[2], true)
	if err != nil {
		return 2, err
	}
	if err := checkName(e.Schema, res.Type, name); err != nil {
		return 2, err
	}
	if p, ok := e.Explain(res, name, sub); ok {
		fmt.Fprintf(w, "yes: %s has %s on %s\n", sub, name, res)
		for _, l := range p.Lines("  ") {
			fmt.Fprintln(w, l)
		}
		return 0, nil
	}
	fmt.Fprintf(w, "no: %s does not have %s on %s\n", sub, name, res)
	if b, ok := e.WhyNot(res, name, sub); ok {
		fmt.Fprintf(w, "  removed on %s by `%s`, because\n", b.Object, b.Subtracted)
		for _, l := range b.Proof.Lines("    ") {
			fmt.Fprintln(w, l)
		}
	} else {
		fmt.Fprintln(w, "  no chain of relationships leads there")
	}
	return 1, nil
}

func cmdLookupResources(args []string, w io.Writer) (int, error) {
	_, pos, err := parseArgs(args, nil, nil)
	if err != nil {
		return 2, err
	}
	if len(pos) != 3 {
		return 2, usageError{"usage: authz-proof lookup-resources SCHEMA RELATIONSHIPS TYPE#PERMISSION@SUBJECT"}
	}
	e, err := load(pos[0], pos[1])
	if err != nil {
		return 2, err
	}
	left, subText, ok := strings.Cut(pos[2], "@")
	t, name, ok2 := strings.Cut(left, "#")
	if !ok || !ok2 {
		return 2, usageError{"expected TYPE#PERMISSION@SUBJECT, such as document#view@user:bob"}
	}
	sub, err := parseObject(subText)
	if err != nil {
		return 2, err
	}
	if err := checkName(e.Schema, t, name); err != nil {
		return 2, err
	}
	for _, o := range e.LookupResources(t, name, sub) {
		fmt.Fprintln(w, o)
	}
	return 0, nil
}

func cmdLookupSubjects(args []string, w io.Writer) (int, error) {
	_, pos, err := parseArgs(args, nil, nil)
	if err != nil {
		return 2, err
	}
	if len(pos) != 4 {
		return 2, usageError{"usage: authz-proof lookup-subjects SCHEMA RELATIONSHIPS RESOURCE#PERMISSION SUBJECT_TYPE"}
	}
	e, err := load(pos[0], pos[1])
	if err != nil {
		return 2, err
	}
	res, name, _, err := parseQuery(pos[2], false)
	if err != nil {
		return 2, err
	}
	if err := checkName(e.Schema, res.Type, name); err != nil {
		return 2, err
	}
	got := e.LookupSubjects(res, name, pos[3])
	if got.Wildcard {
		line := pos[3] + ":*"
		if len(got.Except) > 0 {
			ex := make([]string, len(got.Except))
			for i, o := range got.Except {
				ex[i] = o.String()
			}
			line += " except " + strings.Join(ex, ", ")
		}
		fmt.Fprintln(w, line)
		return 0, nil
	}
	for _, o := range got.Objects {
		fmt.Fprintln(w, o)
	}
	return 0, nil
}

func cmdExpand(args []string, w io.Writer) (int, error) {
	_, pos, err := parseArgs(args, nil, nil)
	if err != nil {
		return 2, err
	}
	if len(pos) != 3 {
		return 2, usageError{"usage: authz-proof expand SCHEMA RELATIONSHIPS RESOURCE#PERMISSION"}
	}
	e, err := load(pos[0], pos[1])
	if err != nil {
		return 2, err
	}
	res, name, _, err := parseQuery(pos[2], false)
	if err != nil {
		return 2, err
	}
	if err := checkName(e.Schema, res.Type, name); err != nil {
		return 2, err
	}
	tree, err := e.Expand(res, name)
	if err != nil {
		return 2, err
	}
	fmt.Fprint(w, tree.Render())
	return 0, nil
}

func cmdDiff(args []string, w io.Writer) (int, error) {
	flags, pos, err := parseArgs(args, []string{"new-relationships", "allow"}, []string{"fail-on-gain", "fail-on-loss", "all-paths", "json"})
	if err != nil {
		return 2, err
	}
	if len(pos) != 3 {
		return 2, usageError{"usage: authz-proof diff OLD_SCHEMA NEW_SCHEMA RELATIONSHIPS [--new-relationships FILE] [--allow FILE] [--fail-on-gain] [--fail-on-loss]"}
	}
	old, err := load(pos[0], pos[2])
	if err != nil {
		return 2, err
	}
	newRels := pos[2]
	if f := flags["new-relationships"]; f != "" {
		newRels = f
	}
	nw, err := load(pos[1], newRels)
	if err != nil {
		return 2, err
	}
	res := diff.Compute(old, nw)
	if f := flags["allow"]; f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return 2, err
		}
		rules, err := diff.ParseAllowlist(string(b))
		if err != nil {
			return 2, fmt.Errorf("%s: %w", f, err)
		}
		res.Apply(rules)
	}
	if flags["json"] != "" {
		if err := diff.JSON(w, res); err != nil {
			return 2, err
		}
	} else {
		diff.Text(w, res, diff.TextOptions{AllPaths: flags["all-paths"] != ""})
	}
	var badGain, badLoss int
	for _, c := range res.Changes {
		if c.Allowed != nil {
			continue
		}
		if c.Gained {
			badGain++
		} else {
			badLoss++
		}
	}
	code := 0
	var why []string
	if flags["fail-on-gain"] != "" && badGain > 0 {
		code = 1
		why = append(why, fmt.Sprintf("%d gained", badGain))
	}
	if flags["fail-on-loss"] != "" && badLoss > 0 {
		code = 1
		why = append(why, fmt.Sprintf("%d lost", badLoss))
	}
	gated := flags["fail-on-gain"] != "" || flags["fail-on-loss"] != ""
	if code != 0 && flags["json"] == "" {
		fmt.Fprintf(w, "\nFAIL: %s that no allowlist entry expects\n", strings.Join(why, " and "))
	} else if gated && len(res.Changes) > 0 && flags["json"] == "" {
		fmt.Fprintln(w, "\nOK: every change is one the allowlist expects")
	}
	return code, nil
}

func seedsFlag(flags map[string]string, def int) (int, error) {
	if v := flags["seeds"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 0, usageError{"--seeds must be a positive number"}
		}
		return n, nil
	}
	return def, nil
}

func cmdHunt(args []string, w io.Writer) (int, error) {
	flags, pos, err := parseArgs(args, []string{"seeds"}, nil)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 {
		return 2, usageError{"usage: authz-proof hunt [--seeds N]"}
	}
	n, err := seedsFlag(flags, 20000)
	if err != nil {
		return 2, err
	}
	start := time.Now()
	var cover prop.Coverage
	for seed := int64(1); seed <= int64(n); seed++ {
		if a, b, err := prop.Pair(seed); err == nil {
			cover.Add(a, b)
		}
		if err := prop.Run(seed, engine.Correct); err != nil {
			fmt.Fprintf(w, "FAILED: %v\n", err)
			var f *prop.Failure
			if errors.As(err, &f) {
				fmt.Fprintf(w, "\nschema:\n%s\nrelationships:\n  %s\n", f.Model.Schema, strings.Join(f.Model.Relationships, "\n  "))
			}
			return 1, nil
		}
	}
	fmt.Fprintf(w, "%d seeds, engine agrees with the reference on every check, lookup, expansion and diff (%.1fs)\n", n, time.Since(start).Seconds())
	fmt.Fprintf(w, "%s\n", cover)
	return 0, nil
}

func cmdMutants(args []string, w io.Writer) (int, error) {
	flags, pos, err := parseArgs(args, []string{"seeds"}, nil)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 {
		return 2, usageError{"usage: authz-proof mutants [--seeds N]"}
	}
	n, err := seedsFlag(flags, 500)
	if err != nil {
		return 2, err
	}
	start := time.Now()
	fmt.Fprintf(w, "%-26s %-8s %-11s %-13s %s\n", "variant", "result", "first seed", "seeds failed", "caught by")
	code := 0
	for _, m := range append([]engine.Mutant{engine.Correct}, engine.Mutants...) {
		first, failed := 0, 0
		var by []string
		for seed := 1; seed <= n; seed++ {
			err := prop.Run(int64(seed), m)
			if err == nil {
				continue
			}
			failed++
			if first == 0 {
				first = seed
			}
			var f *prop.Failure
			if errors.As(err, &f) && !contains(by, f.Check) {
				by = append(by, f.Check)
			}
		}
		name := string(m)
		if m == engine.Correct {
			name = "correct"
		}
		switch {
		case m == engine.Correct && failed == 0:
			fmt.Fprintf(w, "%-26s %-8s %-11s %-13s %s\n", name, "clean", "-", fmt.Sprintf("0 of %d", n), "every property held")
		case m == engine.Correct:
			code = 1
			fmt.Fprintf(w, "%-26s %-8s %-11d %-13s %s\n", name, "FAILED", first, fmt.Sprintf("%d of %d", failed, n), strings.Join(by, ", "))
		case failed == 0:
			code = 1
			fmt.Fprintf(w, "%-26s %-8s %-11s %-13s %s\n", name, "MISSED", "-", fmt.Sprintf("0 of %d", n), "not caught")
		default:
			fmt.Fprintf(w, "%-26s %-8s %-11d %-13s %s\n", name, "caught", first, fmt.Sprintf("%d%%", failed*100/n), strings.Join(by, ", "))
		}
	}
	fmt.Fprintf(w, "\n%.1fs\n", time.Since(start).Seconds())
	return code, nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func cmdCrosscheck(args []string, w io.Writer) (int, error) {
	flags, pos, err := parseArgs(args, []string{"endpoint", "key", "random"}, nil)
	if err != nil {
		return 2, err
	}
	if flags["endpoint"] == "" || len(pos)%2 != 0 {
		return 2, usageError{"usage: authz-proof crosscheck --endpoint URL [--key KEY] [--random N] [SCHEMA RELATIONSHIPS]..."}
	}
	c := spicedb.NewClient(flags["endpoint"], flags["key"])
	total := spicedb.Summary{}
	for i := 0; i < len(pos); i += 2 {
		sb, err := os.ReadFile(pos[i])
		if err != nil {
			return 2, err
		}
		rb, err := os.ReadFile(pos[i+1])
		if err != nil {
			return 2, err
		}
		sum, err := spicedb.Crosscheck(c, string(sb), strings.Split(string(rb), "\n"))
		if err != nil {
			return 2, fmt.Errorf("%s: %w", pos[i], err)
		}
		fmt.Fprintf(w, "%s + %s: %s\n", pos[i], pos[i+1], sum)
		total.Add(sum)
	}
	if v := flags["random"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return 2, usageError{"--random must be a positive number"}
		}
		sum, err := spicedb.CrosscheckRandom(c, n, w)
		if err != nil {
			return 2, err
		}
		fmt.Fprintf(w, "%d random models: %s\n", sum.Schemas, sum)
		total.Add(sum)
	}
	if total.Disagree > 0 {
		return 1, nil
	}
	return 0, nil
}
