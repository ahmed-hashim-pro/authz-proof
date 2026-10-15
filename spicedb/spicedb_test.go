package spicedb

import (
	"io"
	"os"
	"strings"
	"testing"
)

// These run against a real SpiceDB when SPICEDB_ENDPOINT is set (CI starts
// one with its dispatch cache off; see the README for why).
func client(t *testing.T) *Client {
	ep := os.Getenv("SPICEDB_ENDPOINT")
	if ep == "" {
		t.Skip("SPICEDB_ENDPOINT not set")
	}
	return NewClient(ep, os.Getenv("SPICEDB_KEY"))
}

func TestExamplesAgree(t *testing.T) {
	c := client(t)
	rels, err := os.ReadFile("../examples/drive/relationships.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"schema.zed", "schema-refactor.zed", "schema-reordered.zed", "schema-no-parens.zed"} {
		sb, err := os.ReadFile("../examples/drive/" + f)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := Crosscheck(c, string(sb), strings.Split(string(rels), "\n"))
		if err != nil {
			t.Fatal(f, err)
		}
		if sum.Disagree != 0 || sum.Errors != 0 || sum.Checks != 966 {
			t.Errorf("%s: %s", f, sum)
		}
	}
}

func TestRandomAgree(t *testing.T) {
	c := client(t)
	sum, err := CrosscheckRandom(c, 40, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Disagree != 0 || sum.Errors != 0 || sum.OnlyTheyRefused != 0 {
		t.Errorf("%s", sum)
	}
}
