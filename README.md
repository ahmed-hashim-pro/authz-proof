# authz-proof

[![CI](https://github.com/ahmed-hashim-pro/authz-proof/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmed-hashim-pro/authz-proof/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A permission engine for SpiceDB-style schemas (Google Zanzibar's model),
built to answer the question a schema review can't answer by reading:
**if this change merges, who gains access and who loses it?**

It evaluates every relation and permission of every object for every
subject, once under the old schema and relationships and once under the
new ones. It lists each difference along with the chain of relationships
that causes it. In CI it fails the pull request when access changes in a
way an allowlist doesn't expect.

Authorization schemas are short, and they read as if they were obviously
right. Here is a refactor whose description says it changes nothing:

```diff
-	permission view = (viewer + edit + parent->view) - restricted->contractor
+	permission view = (viewer - restricted->contractor) + edit + parent->view
```

"Only explicit viewers need the contractor check; folder access is
already scoped to staff." It isn't, because the company folder is shared
with the whole organization, and contractors are members of it:

```
$ authz-proof diff schema.zed schema-refactor.zed relationships.txt --fail-on-gain
compared 966 checks per side: every relation and permission of 23 objects, for 14 subjects
6 grants gained, 0 lost

GAINED  document:budget#view         user:bob, user:carol
GAINED  document:offer-letters#view  user:bob, user:carol
GAINED  document:payroll#view        user:bob, user:carol
...
GAINED document:payroll#view @ user:bob   (1 more subject; --all-paths shows each)
  now:
    user:bob
      → team:contractors#member
      → organization:acme#member
      → folder:company#viewer → #view
      → folder:hr#view                    via parent
      → document:payroll#view             via parent
  before: removed on document:payroll by `restricted->contractor`, because
    user:bob → team:contractors#member → organization:acme#contractor

FAIL: 6 gained that no allowlist entry expects
```

![Terminal recording: the refactor diff lists six gained grants, contractors bob and carol on budget, offer-letters and payroll, each with the chain of relationships that now grants it and the exclusion that used to remove it, and fails; the same schema with the union reordered shows no access changes; validating the schema without parentheses warns that it means (viewer + edit) - (restricted->contractor + parent->view); a check shows why bob cannot view payroll; the mutant table shows the correct engine clean and all seven deliberate bugs caught](docs/demo.gif)

The example is in [`examples/drive`](examples/drive): five definitions,
30 relationships, and four versions of the schema.

## Is it right?

A tool that says "no access changes" is only useful if it would have
noticed a change. authz-proof is checked three ways.

**Against a reference evaluator.** [`ref`](ref/ref.go) is a deliberately
naive second implementation. It computes every fact for every subject by
repeating rounds until nothing changes, and shares no evaluation code with
the engine. The property tests generate random schemas and relationships
(cycles, wildcards, nested subject sets, arrows, intersections, exclusions,
and operators mixed without parentheses). They require the engine to agree
with the reference on every check, every lookup, every expansion and every
diff:

```
$ authz-proof hunt
20000 seeds, engine agrees with the reference on every check, lookup, expansion and diff (23.6s)
models: 40000, with cyclic relationships 64%, wildcard relationships 24%, exclusions 33%, intersections 47%, arrows 23%
```

**Against itself, broken on purpose.** A clean run means nothing unless
the tests would catch a broken engine. The engine carries seven known
mistakes behind a switch, and the property tests must catch every one:

```
$ authz-proof mutants --seeds 500
variant                    result   first seed  seeds failed  caught by
correct                    clean    -           0 of 500      every property held
intersection-as-union      caught   4           38%           diff, check
wildcard-any-type          caught   10          9%            check, diff
arrow-first-only           caught   7           3%            check, diff
subject-set-one-level      caught   8           16%           check, diff
memo-false-in-cycle        caught   8           4%            check, diff
visited-not-path           caught   6           22%           check, diff
diff-known-subjects-only   caught   27          9%            diff
```

`memo-false-in-cycle` and `visited-not-path` are the two classic ways to
get cycle handling wrong. The first remembers a "no" that depended on a
goal still being evaluated. The second cuts every repeated goal, not only
the ones on the current path. `diff-known-subjects-only` forgets the
users that appear in no relationship, so it misses a gain through
`user:*`.

**Against a real SpiceDB.** `authz-proof crosscheck` writes the same
schema and relationships to SpiceDB (v1.56.2, through its HTTP API) and
asks it every question the engine answers. CI does this on every push for
the four example schemas and 600 random models:

```
$ authz-proof crosscheck --endpoint http://localhost:8443 --key testkey --random 300 ...
examples/drive/schema.zed + examples/drive/relationships.txt: 966 checks (121 yes), 0 disagreements
examples/drive/schema-refactor.zed + examples/drive/relationships.txt: 966 checks (127 yes), 0 disagreements
examples/drive/schema-reordered.zed + examples/drive/relationships.txt: 966 checks (121 yes), 0 disagreements
examples/drive/schema-no-parens.zed + examples/drive/relationships.txt: 966 checks (91 yes), 0 disagreements
600 random models: 59110 checks (6110 yes), 0 disagreements
  schemas refused by both: 83, by SpiceDB only: 0
  refused by authz-proof only (depends on itself through an exclusion): 110
  refused by authz-proof only (wildcard through a subject set): 1
```

Between runs the last line reads 1 or 2, and the "both" count moves by
one with it (see "Schemas only authz-proof refuses" below).

It also writes every schema authz-proof refuses, to see if SpiceDB
refuses it too. SpiceDB never refused a schema that authz-proof
accepted. The schemas only authz-proof refuses are covered under
[What the cross-check found](#what-the-cross-check-found-in-spicedb).

The cross-check runs SpiceDB with `--dispatch-cache-enabled=false`.
With the cache on, SpiceDB's own answers depend on the order of the
questions. That's the first finding below.

## What the cross-check found in SpiceDB

These are behaviours of SpiceDB v1.56.2 with its in-memory datastore,
found by the cross-check and then reduced by hand. I haven't reported
them upstream, and I only searched SpiceDB's issue tracker briefly, so
some may already be known.

**With the dispatch cache on (the default), an earlier check can change a
later answer.** On the same random models, the default SpiceDB disagreed
with authz-proof on 14 of 59,110 checks, in 7 of 600 models, and a
second run disagreed on different seeds. With the cache off, every
answer agrees. Reduced to two permissions:

```
definition document {
	relation viewer: user
	relation editor: user
	permission view_only = viewer - (viewer & editor)
	permission view_and_edit = viewer & editor
}
```

Alice is a viewer of two documents and an editor of neither:

```
$ examples/spicedb-cache/repro.sh        # a fresh SpiceDB, default settings
alice is a viewer of documents one and two, and an editor of neither.
document:one#view_and_edit, asked first:          NO_PERMISSION
document:two#view_only:                           HAS_PERMISSION
document:two#view_and_edit, asked after view_only: HAS_PERMISSION
```

Asked first, `view_and_edit` is correctly denied. Asked after
`view_only` on the same document, it is granted, to someone who is not
an editor. With `--dispatch-cache-enabled=false` the last line is
`NO_PERMISSION`. The CI job `spicedb-cache` runs the script against both
configurations on every push. `make spicedb-cache-bug` runs it locally.

**Operator precedence.** SpiceDB binds `+` before `&` before `-`, all
left-associative, so `a - b + c` means `a - (b + c)`. authz-proof parses
the same way, and `validate` warns whenever a permission depends on it:

```
$ authz-proof validate schema-no-parens.zed
schema-no-parens.zed: 5 definitions, 10 relations, 4 permissions
warning: line 31: document#view mixes operators without parentheses: `viewer + edit - restricted->contractor + parent->view` means `(viewer + edit) - (restricted->contractor + parent->view)` (SpiceDB binds + before & before -)
```

That schema drops one pair of parentheses from the original. Every
document stops inheriting its folder's viewers, and editors lose `view`
too: `authz-proof diff` reports 30 lost grants and no gains. SpiceDB
agrees on all 966 checks.

**Recursive relationships.** If team a contains team b and b contains a,
and carol is in b, SpiceDB answers "is carol in a?" with yes. It answers
"is dave in a?" with `max depth exceeded` rather than no. authz-proof
answers no, the least fixed point. Random models with cycles often
produced such errors, a few of them on checks where a chain does exist,
and twice stalled SpiceDB until requests timed out. So the cross-check
uses relationships that never lead from an object back to itself, while
the property tests against the reference use cycles freely (64% of
models).

**Schemas only authz-proof refuses.**
- A permission that depends on itself through an exclusion, such as
  `permission view = viewer - view`, has no single meaning. SpiceDB
  accepts it, then answers `max depth exceeded` for the users it matters
  to. authz-proof refuses it when it loads the schema.
- A relation that allows a subject set on another definition, where the
  set can include a wildcard. SpiceDB refuses most of these ("wildcard
  relations cannot be transitively included"), but accepted one or two of
  the random ones in each run, apparently depending on unrelated
  relations elsewhere in the schema. authz-proof refuses them all.

## Quickstart

Go 1.22 or newer, or only Docker.

```bash
git clone https://github.com/ahmed-hashim-pro/authz-proof
cd authz-proof
go build -o authz-proof ./cmd/authz-proof
# without Go: docker run --rm -u $(id -u):$(id -g) -e HOME=/tmp -v "$PWD":/w -w /w golang:1.25 go build -buildvcs=false -o authz-proof ./cmd/authz-proof

cd examples/drive
../../authz-proof diff schema.zed schema-refactor.zed relationships.txt --fail-on-gain   # the refactor above
../../authz-proof diff schema.zed schema-reordered.zed relationships.txt                 # no access changes
../../authz-proof check schema.zed relationships.txt document:payroll#view@user:bob      # no, and why
../../authz-proof lookup-subjects schema.zed relationships.txt document:payroll#view user
../../authz-proof expand schema.zed relationships.txt document:payroll#view
cd ../..

go test ./...                 # about 10 s
make check                    # also the 20,000-seed hunt and the mutant table
make spicedb                  # the cross-check, against SpiceDB in Docker
```

The answers for the example:

```
$ authz-proof check schema.zed relationships.txt document:payroll#view@user:bob
no: user:bob does not have view on document:payroll
  removed on document:payroll by `restricted->contractor`, because
    user:bob
      → team:contractors#member
      → organization:acme#contractor

$ authz-proof lookup-subjects schema.zed relationships.txt document:payroll#view user
user:alice
user:dana
user:erin
user:frank
```

`check` exits 0 for yes and 1 for no. Every command exits 2 on bad
input.

## As a CI gate

A schema change and a data change are both access changes, so `diff`
takes either: two schemas, or one schema with `--new-relationships`. The
allowlist says which changes are expected, one pattern and reason per
line. Each part of a pattern can use globs and one `{a,b}` group.

```
// What PR #213 is meant to change (SEC-142): contractors may edit the
// engineering folder and the documents in it. Nothing else.
folder:eng#{editor,edit}@user:{bob,carol}                 SEC-142: contractors edit engineering
document:{roadmap,design-review}#edit@user:{bob,carol}    SEC-142: contractors edit engineering
```

The intended change passes:

```
$ authz-proof diff schema.zed schema.zed relationships.txt \
    --new-relationships relationships-pr213.txt --allow allow-pr213.txt --fail-on-gain
8 grants gained, 0 lost

GAINED  document:design-review#edit  user:bob (allowed), user:carol (allowed)
GAINED  document:roadmap#edit        user:bob (allowed), user:carol (allowed)
GAINED  folder:eng#editor            user:bob (allowed), user:carol (allowed)
GAINED  folder:eng#edit              user:bob (allowed), user:carol (allowed)
...
OK: every change is one the allowlist expects
```

The same PR with one word wrong, `folder:company` for `folder:eng`, fails:

```
$ authz-proof diff ... --new-relationships relationships-pr213-slip.txt --allow allow-pr213.txt --fail-on-gain
22 grants gained, 0 lost

GAINED  document:budget#edit         user:bob, user:carol
GAINED  document:design-review#edit  user:bob (allowed), user:carol (allowed)
GAINED  document:handbook#edit       user:bob, user:carol
GAINED  document:offer-letters#edit  user:bob, user:carol
GAINED  document:payroll#edit        user:bob, user:carol
...
FAIL: 16 gained that no allowlist entry expects
```

The slip also exposes something the schema always allowed. Only `view`
excludes contractors, so a contractor who can edit the company folder
can edit payroll without being able to read it.

In a workflow:

```yaml
- run: git show origin/main:authz/schema.zed > /tmp/schema-main.zed
- run: >
    authz-proof diff /tmp/schema-main.zed authz/schema.zed authz/relationships.txt
    --allow authz/allow.txt --fail-on-gain --fail-on-loss
```

The relationships are a file you provide, in SpiceDB's text form
(`document:readme#viewer@user:alice`, `...@team:eng#member`,
`...@user:*`): a fixture like the example, or a snapshot exported from
staging or production. `--json` prints every change with its chain, for
a bot to post on the pull request.

## How it works

- **Semantics.** A relation holds its direct subjects, everyone of a type
  for `type:*`, and the members of each subject set such as
  `team:eng#member`. A permission is its expression, with `->` following
  the relation to each related object. Recursion is read as the least
  fixed point: teams that contain each other have exactly the members
  someone actually added. Exclusions make that ill-defined when a
  permission subtracts something that depends on itself. The schema
  check refuses those, and orders everything else so that what a node
  subtracts is always fully known first.
- **Checks** are a depth-first search that treats a goal already on the
  current path as false. The shortest derivation of a goal never passes
  through itself, so this is exact. A "no" that leaned on such a cut is
  only remembered once the goal it leaned on has finished. That's the
  invariant `memo-false-in-cycle` breaks.
- **Subjects that appear nowhere.** Every user who is in no relationship
  has exactly the same access, so one stand-in per type answers for all
  of them. That makes "everyone" a finite question: a diff reports a
  change through `user:*` as `user:*`, and `lookup-subjects` prints
  `user:* except user:bob`.
- **The diff** runs every check on both sides: objects × relations and
  permissions × subjects, including the stand-ins. Each change gets the
  shortest chain on the side that grants access, found by iterative
  deepening, plus the exclusion that removed it on the other side, if
  one did.

## What it supports, exactly

- `definition`, `relation` with allowed types `t`, `t:*` and `t#rel`
  (where `rel` may be a permission), and `permission` with `+`, `&`,
  `-`, `->` and parentheses, under SpiceDB's precedence. Type prefixes
  (`acme/document`), comments and line breaks inside parentheses are
  supported.
- SpiceDB's name rules and its schema errors:
  - permissions on the left of an arrow
  - wildcard relations on the left of an arrow
  - permissions that are aliases of each other in a loop
  - wildcards included through a subject set on another definition
- Not supported, and refused with a message:
  - caveats and `with`
  - `nil`
  - the `.any()` / `.all()` arrow functions
  - arrows over a relation that allows subject sets
- Checks take an object as the subject (`user:alice`). They do not take
  a subject set (`team:eng#member`).

## What this does not do

- **It is not an authorization server.** It loads a schema and a
  relationship file into memory and answers questions. It has no API, no
  storage, no consistency tokens and no watch.
- **The diff covers the relationships you give it.** "No access changes"
  means none for the objects and subjects in that file. Every subject in
  no relationship is covered by the stand-in, but objects in no
  relationship are not, and nor is data that will exist later. A
  snapshot of real data finds more than a fixture.
- **Cost grows with the data.** The diff runs objects × names × subjects
  checks per side, with each answer cached per subject. The example's
  966 checks take milliseconds. I have not measured it on a production
  snapshot.
- **The SpiceDB comparison is one version, one datastore and modest
  sizes**: v1.56.2, in memory, small random models with relationships
  that never lead from an object back to itself. On cyclic data SpiceDB
  answers `max depth exceeded` where authz-proof answers no, so those
  checks are not compared.
- **The SpiceDB findings above are observations on that version**, made
  with the scripts in this repository. They are not claims about other
  versions, datastores or deployments.

## Layout

```
schema/    lexer, parser (SpiceDB precedence), validation, stratification
rel/       relationships in text form, checked against a schema
engine/    check, lookup-resources, lookup-subjects, expand, explain, why-not, the mutants
ref/       the naive reference evaluator
diff/      who gains and loses access, the allowlist, text and JSON output
gen/       random schemas and relationships, as SpiceDB text
prop/      engine vs reference on one seed; hunt and mutants run it
spicedb/   the cross-check, over SpiceDB's HTTP API
cmd/authz-proof/
examples/drive/          the shared-drive example, its four schemas, PR #213
examples/spicedb-cache/  the cache reproducer and its CI check
```

## License

MIT
