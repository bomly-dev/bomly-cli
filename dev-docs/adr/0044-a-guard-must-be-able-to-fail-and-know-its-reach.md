# ADR-0044: A guard must be able to fail and know its reach

- **Date:** 2026-09-12
- **Revised:** 2026-10-19
- **Status:** Accepted

## Context

A guard enforces a rule about the code rather than a behavior of it: no
package imports the raw purl library, insertion goes through the shared
helper, no golden carries a host architecture. Review kept finding one
defect in them: a rule that covers the paths someone enumerated.
The purl-type guard went five rounds, each fix opening the next hole, and
four guards passed while the thing they forbade was present.

## Decision

A guard is written to these rules; one that cannot meet them is not merged
as a guard.

1. **Key on where a decision is made, not where it is used.** Watch the
   `purlkit.PURL` literal, not the `Build` calls. A rule over call sites is a
   list of call sites.
2. **Ask the thing itself.** When the question is "what reaches the wire",
   marshal a value through the real encoder instead of reading struct tags.
3. **Prefer removing the capability to inspecting its arguments.** A function
   with no type parameter needs no guard on the type argument.
4. **A guard must know its own reach.** It fails when it reached nothing, or
   less than it must, so a moved tree cannot turn it into a no-op.
5. **Exemption lists invert.** List what is exempt, with its reason at the
   site, never what is checked; a stale exemption fails.
6. **Mutation is the acceptance criterion.** Put the forbidden shape in and
   read the failure message, not the color: a mutation that does not compile,
   or a red that is the test timeout, proves nothing.
7. **Two correct rules pulling against each other means the frame is wrong.**
   Apply rules 1 to 3, not a fourth clause.

Guards live in the tool that owns their kind: import bans are `depguard`
rules and identifier bans `forbidigo` patterns in `.golangci.yml`; shapes no
linter expresses are analyzers in `internal/tools/guardcheck`, each with a
`testdata` fixture whose `// want` comments make rule 6 permanent. Generated
files are not exempt. An exemption is a `//nolint` line with its reason, or a
typed call such as `detectors.Unattributed(result, reason)`.

## Rejected

Sharper enumeration. Tree-walking guard tests: silent on an empty tree, and
their exemption maps were themselves the hole three times.

## Consequences

- A guard written this way is sometimes blunter than a hand-tuned one, and a
  capability removed under rule 3 is removed for the one caller with a good
  reason too.
- A pull request adding a guard says which rule it keys on and how it was
  mutated.

Enforced by: the Makefile asserts each vet package pattern is non-empty
before the analyzers run; `make test` runs the analyzer fixtures.
