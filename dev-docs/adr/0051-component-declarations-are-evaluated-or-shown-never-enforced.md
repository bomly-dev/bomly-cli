# ADR-0051: Component declarations are evaluated or shown, never enforced

- **Date:** 2026-10-25
- **Status:** Accepted

## Context

`Ready` and `Applicable` run only after selection, so an impossible plan (a
reachability analyzer on an SBOM document) failed late, and docs could not
say what a component needs. A managed plugin runs with the user's
authority, but its manifest could not say what access it expects.
bomly-sdk v0.16.0 added descriptor `Requires` (versioned data tokens) and a
manifest `Access` block.

## Decision

- The SDK owns the types, vocabulary, normalization and validation
  (`Requirements.Unsatisfied`, `ValidateAccess`). The CLI owns evaluation
  and presentation, and duplicates no validator.
- The host vouches for `source-tree-v1` when the target is a path or Git
  checkout not planned as an SBOM document. It vouches for
  `dependency-graph-v1` after detection, when the graph holds a dependency
  node. It vouches for `vulnerability-records-v1` at analyze and audit, when
  the registry carries a vulnerability record. That last one is observed,
  because no descriptor says which matcher produces records. A token the
  host cannot evaluate is never satisfied.
- Before any stage, an explicitly selected component fails the command
  (exit 4) when the plan can never meet its requirement: wrong target
  shape, unknown token, or data no earlier stage produces. Explicit means
  named in a plain selector list, or default-off and added with `+name`.
  The error names the component, the requirement and the remedy.
- At each stage, any component whose requirement the actual data misses is
  held back before `Ready`, with a warning on that stage's channel. This
  applies to explicit components too, since the input, not the selection,
  lacks the data.
- Passing components still face `Ready` and `Applicable`. An absent
  `Requires` is legacy and untouched.
- `Access` is shown as the publisher's unverified claim on install, on
  enable (before enabling), and in info, verify, doctor and JSON
  (`accessDisclosure`). An absent block is unknown and unrestricted.

## Rejected

Named provider dependencies with a scheduler: they make the fixed pipeline
a service graph, and a token shaped like a component name is only an unknown token. Failing an
explicit component on empty data would fail CI on a project with no
vulnerabilities. Enforcing access needs a sandbox, and a declaration is not
evidence of behavior.

## Consequences

- No built-in declares requirements yet, so current runs are unchanged.
- A new token needs an evaluator change here before it can ever pass.
- No output claims enforcement.

Enforced by: `internal/engine/preflight_test.go`,
`internal/plugin/access_test.go`, `internal/cli/plugin_access_test.go`.
