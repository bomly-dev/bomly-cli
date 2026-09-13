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
  `test/smoke/golden_arch_test.go` are the current strongest form, and each
  new guard is reviewed against the seven rules above. A pull request that
  adds a guard says which rule it keys on and how it was mutated.
- Rule 4 is enforced, not stated: the walkers under `internal/detectors`
  fail when they visit no Go files, so a moved package cannot turn a guard
  into a no-op.
- The cost is accepted knowingly: a guard written this way is sometimes
  blunter than a hand-tuned one, and a capability removed under rule 3 is a
  capability nobody gets, including the one caller who had a good reason.
  That trade was made in #452 and it held, which is the evidence this record
  rests on.
- `CLAUDE.md` and `AGENTS.md` point here from their guard bullet, so the
  reasoning outlives the session that produced it.
