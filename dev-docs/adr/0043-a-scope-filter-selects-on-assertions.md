# ADR-0043: A scope filter selects on assertions; absence is not one

- **Date:** 2026-09-06
- **Revised:** 2026-10-19
- **Status:** Accepted

## Context

`--scope runtime` compared each dependency's effective scope to the
requested one, so a dependency that asserted no scope matched neither view.
SPDX has no scope concept, Go modules and OS packages have no development
distinction, and plugins may set none. A runtime view of a third-party SPDX
document therefore held nothing but structural nodes, and a scan could report
clean because the filter had emptied it. No specification defines what
Bomly's `--scope` returns; this is Bomly's policy.

## Decision

- A **runtime** view keeps every dependency not affirmatively
  development-only: a scope set that names runtime, or names nothing this
  build can read (no scope, or only unknown tokens from a newer Bomly). A set
  naming both runtime and development is kept.
- **Every other** view requires an affirmative match: the set names the
  requested scope and does not name runtime, so a package that might ship
  never appears in the list a user reads as deprioritizable.
- The rule is written on the set, not on the effective scope. `MergeScope`
  folds two non-runtime scopes to development, so an effective-scope test
  would drop two unknown tokens.
- One rule, `sdk.ScopeSetMatches`, and every site routes through it: the
  graph filter and the usage-level conjunctive filter.
- A narrowed view reports the dependencies it kept on absence, and the CLI
  warns, so a runtime view that narrowed nothing does not look narrowed.
- The rule belongs to the filter, not to ingest. CycloneDX instructs a
  consumer to assume `required` for an absent scope, and ingest does that
  because the specification says so. SPDX issues no such instruction, and
  stamping a scope at ingest would put a claim in the model that no document
  made.

## Rejected

Separating "could not determine" from "ecosystem has no concept": neither
asserts development, so both take the same answer. An effective-scope
comparison.

## Consequences

- `--scope runtime` returns more than before; the flag can no longer hide a
  vulnerable package behind a claim nobody made.
- `--scope development` is unchanged.

Enforced by: `TestAnUnassertedScopeStaysInARuntimeView` and
`TestScopeSetMatchesIsTheOneRule` in the SDK.
