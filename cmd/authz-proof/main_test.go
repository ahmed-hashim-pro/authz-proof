package main

import (
	"bytes"
	"strings"
	"testing"
)

const d = "../../examples/drive/"

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLI(t *testing.T) {
	cases := []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"validate", d + "schema.zed", d + "relationships.txt"}, 0,
			[]string{"5 definitions, 10 relations, 4 permissions", "30 relationships, all valid"}},
		{[]string{"validate", d + "schema-no-parens.zed"}, 0,
			[]string{"warning: line 31: document#view mixes operators without parentheses"}},
		{[]string{"check", d + "schema.zed", d + "relationships.txt", "document:payroll#view@user:alice"}, 0,
			[]string{"yes: user:alice has view on document:payroll", "team:hr#member"}},
		{[]string{"check", d + "schema.zed", d + "relationships.txt", "document:payroll#view@user:bob"}, 1,
			[]string{"no: user:bob does not have view", "removed on document:payroll by `restricted->contractor`"}},
		{[]string{"lookup-resources", d + "schema.zed", d + "relationships.txt", "document#view@user:bob"}, 0,
			[]string{"document:design-review\ndocument:handbook\ndocument:roadmap\ndocument:status-page\n"}},
		{[]string{"lookup-subjects", d + "schema.zed", d + "relationships.txt", "document:status-page#view", "user"}, 0,
			[]string{"user:*\n"}},
		{[]string{"expand", d + "schema.zed", d + "relationships.txt", "document:payroll#view"}, 0,
			[]string{"└─ ", "exclusion"}},
		{[]string{"diff", d + "schema.zed", d + "schema-refactor.zed", d + "relationships.txt", "--fail-on-gain"}, 1,
			[]string{"6 grants gained, 0 lost", "FAIL: 6 gained that no allowlist entry expects"}},
		{[]string{"diff", d + "schema.zed", d + "schema-refactor.zed", d + "relationships.txt"}, 0,
			[]string{"6 grants gained"}},
		{[]string{"diff", d + "schema.zed", d + "schema-reordered.zed", d + "relationships.txt", "--fail-on-gain", "--fail-on-loss"}, 0,
			[]string{"no access changes"}},
		{[]string{"diff", d + "schema.zed", d + "schema-no-parens.zed", d + "relationships.txt", "--fail-on-loss"}, 1,
			[]string{"0 grants gained, 30 lost", "FAIL: 30 lost"}},
		{[]string{"diff", d + "schema.zed", d + "schema.zed", d + "relationships.txt", "--new-relationships", d + "relationships-pr213.txt", "--allow", d + "allow-pr213.txt", "--fail-on-gain"}, 0,
			[]string{"8 grants gained", "OK: every change is one the allowlist expects"}},
		{[]string{"diff", "--fail-on-gain", d + "schema.zed", d + "schema.zed", d + "relationships.txt", "--new-relationships=" + d + "relationships-pr213-slip.txt", "--allow", d + "allow-pr213.txt"}, 1,
			[]string{"22 grants gained", "document:payroll#edit        user:bob, user:carol", "FAIL: 16 gained"}},
		{[]string{"diff", d + "schema.zed", d + "schema-refactor.zed", d + "relationships.txt", "--json"}, 0,
			[]string{`"change": "gained"`, `"subject": "user:bob"`}},
		{[]string{"hunt", "--seeds", "50"}, 0, []string{"50 seeds, engine agrees with the reference"}},
		{[]string{"mutants", "--seeds", "60"}, 0, []string{"correct                    clean", "intersection-as-union      caught"}},
		{[]string{"--help"}, 0, []string{"usage:"}},
	}
	for _, c := range cases {
		code, out, errs := runCLI(c.args...)
		if code != c.code {
			t.Errorf("%v: exit %d, want %d\n%s%s", c.args, code, c.code, out, errs)
		}
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: output lacks %q:\n%s%s", c.args, w, out, errs)
			}
		}
	}
}

func TestBadInput(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"nope"}, "unknown command"},
		{[]string{"check", d + "schema.zed", d + "relationships.txt", "document:payroll#view"}, "RESOURCE#PERMISSION@SUBJECT"},
		{[]string{"check", d + "schema.zed", d + "relationships.txt", "document:payroll#read@user:bob"}, "document has no relation or permission read"},
		{[]string{"diff", d + "schema.zed", d + "schema.zed"}, "usage"},
		{[]string{"diff", d + "schema.zed", d + "schema.zed", d + "relationships.txt", "--frobnicate"}, "unknown flag"},
		{[]string{"validate", d + "missing.zed"}, "no such file"},
		{[]string{"validate", d + "schema.zed", d + "allow-pr213.txt"}, "line 3"},
		{[]string{"mutants", "--seeds", "0"}, "positive"},
	}
	for _, c := range cases {
		code, out, errs := runCLI(c.args...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", c.args, code)
		}
		if !strings.Contains(out+errs, c.want) {
			t.Errorf("%v: %q lacks %q", c.args, out+errs, c.want)
		}
	}
}
