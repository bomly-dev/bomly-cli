# ADR-0044: A guard must be able to fail, and must know what it covers

- **Date:** 2026-09-12
- **Status:** Accepted

## Context

A guard test is a test that enforces a rule about the code rather than a
behavior of the code: "no package under `internal/` imports the raw purl
library", "node insertion goes through the shared helper", "no golden carries
a host architecture". This repository leans on them (ADR-0038, ADR-0041,
`CLAUDE.md` "Add a guard when the rule can be bypassed by writing it out by
hand"), because a rule that has to be remembered is forgotten, and the next
occurrence is found by a reviewer or a user instead of by the tree.

Over one day of the SDK maturity program, automated review raised more than
twenty findings across six pull requests and two repositories. Nearly all of
them were the same defect wearing different clothes: **a rule that covers the
paths someone enumerated.** The purl-type guard went through five rounds, and
each fix opened the next hole:

| Round | What the rule enumerated | What escaped |
|---|---|---|
| 1 | field names | a field nobody listed |
| 2 | type names | a type nobody listed |
| 3 | the mint call site | `purlkit.Build`, a signposted second route |
| 4 | composite literals | the same literal reached through a variable |
| 5 | the authority's name | a local function wearing that name |

The wire-schema guard in bomly-sdk went through the same progression
independently: field names, then type names, then untagged fields, then
structs a custom codec emits. In two cases a fix was itself the thing the next
round found. Four separate guards in this repository passed while the thing
they forbade was present, and three mutation attempts proved nothing: two
broke the build, and one reported `FAIL` at the 600-second test timeout,
which looks the same at a glance as a catch.

What eventually worked was not a sharper enumeration. This record exists so
the next guard starts from that conclusion instead of rediscovering it.

## Decision

A guard in this repository is written to the following rules, and a guard
that cannot meet them is not merged as a guard.

1. **Key on where a decision is made, not where it is used.** The purl rule
   stopped watching `Build` calls and watched `purlkit.PURL` literals; the
   hop between the two stopped mattering and the rule got shorter. A rule
   over call sites is a list of call sites.

2. **Ask the thing itself.** bomly-sdk's
   `TestWireV1ZeroValuesEmitOnlyDeclaredKeys` stopped reading struct tags and
   marshalled a zero value through the real encoder; custom codecs, untagged
   fields and mistyped options fell out for free, and three earlier rounds
   became unnecessary rather than fixed. When the question is "what reaches
   the wire", run the wire.

3. **Prefer removing the capability to inspecting its arguments.** Detectors
   cannot import `purlkit` at all (`TestDetectorsDoNotReachPURLKitDirectly`),
   and `sdk.BuildPackageURLFor` has no type parameter, so
   `TestDetectorPURLTypesComeFromTheSDK` bans two callee names instead of
   reasoning about four argument shapes (#452 collapsed exactly that, and
   closed a gap that had been filed as needing `go/types`). A capability
   that does not exist needs no guard against its misuse.

4. **A guard must know its own reach.** A guard that walks a tree and
   reports offenders is silent when the tree is clean and silent when the
   tree is empty, moved, or renamed, and the two are indistinguishable. So a
   guard fails when it reached nothing, or less than it must:
   `TestWireV1ZeroValuesEmitOnlyDeclaredKeys` fails under fifty types, after
   two earlier versions looked healthy while covering a sixth of the wire;
   `TestGoldensCarryNoHostArchitecture` fails at zero goldens
   (`test/smoke/golden_arch_test.go`). The shared walkers in
   `internal/detectors/guards_test.go` and the flat read in
   `TestExportNeverReadsResolvedURL` gained the same check with this ADR.

5. **Exemption lists invert.** A list of what is checked is a list someone
   must remember to extend; a list of what is exempt is a list a reviewer
   watches grow. Every exemption carries its reason in the source, and a stale
   one fails: `guardFiles` in `internal/detectors/guards_test.go` names, per
   path and per module, what a guard file may mention, and
   `TestGuardExemptionIsByPathAndPerModule` reports an entry that names a file
   which no longer exists or a module no rule forbids. The doc comment on that
   map records three earlier ways the exemption itself was the hole.

6. **Mutation is the acceptance criterion, and it has its own traps.** A guard
   is proven by making it fail: put the forbidden shape in and watch the red.
   `TestPURLTypeGuardSeesTheShapesItForbids` pins that proof permanently, in
   both directions, over the shapes that escaped earlier rounds. A mutation
   that does not compile proves nothing about the guard; neither does a red
   result that is really the test timeout. Read the failure message, not the
   color.

7. **Two correct rules pulling against each other means the frame is wrong,
   not the tuning.** Dropping the package qualifier defeats import aliasing
   *and* enables name shadowing; exempting self-marshalling types kills twenty
   false positives *and* creates a blind spot. When that happens the fix is
   one of rules 1 to 3, not a fourth clause.

## Consequences

- The guards in `internal/detectors/guards_test.go`,
  `internal/output/registry_lookup_guard_test.go`,
  `internal/detectors/python/roots_guard_test.go` and
  `test/smoke/golden_arch_test.go` were the strongest form when this record
  was written; where each rule lives now is the amendment below. Each new
  guard is reviewed against the seven rules above, and a pull request that
  adds one says which rule it keys on and how it was mutated.
- Rule 4 was enforced, not stated: the walkers under `internal/detectors`
  failed when they visited no Go files, so a moved package could not turn a
  guard into a no-op. Their successors assert reach as the amendment below
  describes.
- The cost is accepted knowingly: a guard written this way is sometimes
  blunter than a hand-tuned one, and a capability removed under rule 3 is a
  capability nobody gets, including the one caller who had a good reason.
  That trade was made in #452 and it held, which is the evidence this record
  rests on.
- `CLAUDE.md` and `AGENTS.md` point here from their guard bullet, so the
  reasoning outlives the session that produced it.

> **Amended 2026-09-13 (issue #464):** the guards named in the first bullet,
> `test/smoke/golden_arch_test.go` excepted, no longer exist as tests. Each
> rule moved to the tool that owns its kind: import bans are `depguard` rules
> and identifier bans are `forbidigo` patterns in `.golangci.yml`; the shapes
> no linter expresses -- a lookup followed by an insert, a package URL pasted
> from a literal, a detection result returned without its attribution -- are
> `go/analysis` analyzers in `internal/tools/guardcheck`, run by `make lint`
> through `go vet -vettool`. Rule 6 is permanent rather than performed: each
> analyzer has a fixture under `testdata` with a `// want` comment on every
> forbidden shape, and it runs in `make test`; that supersedes
> `TestPURLTypeGuardSeesTheShapesItForbids` and the hand-run mutation in
> #460, and the migration itself was proved by one mutation per rule,
> recorded in the pull request. Rule 5 takes its native form: an exemption is
> a `//nolint:forbidigo` line carrying its reason at the one permitted call,
> or the typed `detectors.Unattributed(result, reason)`, whose reason the
> analyzer requires and whose staleness it reports; `guardFiles` and the
> three tests that audited it are gone, because a rule no longer has to spell
> the module it forbids. Rule 4 is the go command's for the analyzers -- the
> Makefile asserts each package pattern is non-empty before vet runs, since
> an empty pattern is only a warning to `go vet` -- and is a stated residual
> for the golangci scopes: a directory renamed out from under a `path-except`
> silently empties that scope, and `warn-unused` only warns. Generated files
> are not exempt: `linters.exclusions.generated` is `disable`, because a
> generator's output is shipped code and the walkers never skipped it. The
> export layer's rule stays a *name* ban rather than an identifier ban: the
> `resolvedurl` analyzer reports `ResolvedURL` as an identifier, inside a
> string, or in a comment, because a linter that resolves identifiers cannot
> see a field reached by reflection through a string, and "cannot name it"
> was the point (ADR-0033). One narrowing was accepted: depguard bans the
> import, where the old rule banned naming the module string anywhere under
> `internal/`. The import is the hazard, and the old file itself argued that
> naming is not importing.
>
> **Amended 2026-09-15 (ADR-0045):** the `resolvedurl` analyzer is deleted.
> The export layer it policed moved to `bomly-sdk/sbom`, and the rule lives
> there as a test that fails when it scans no file (rule 4). The narrowing is
> recorded in ADR-0033's amendment of the same date.
