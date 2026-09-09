# ADR-0043: A scope filter selects on assertions; absence is not one

- **Date:** 2026-09-06
- **Status:** Accepted

## Context

`--scope runtime` narrowed a graph by comparing each dependency's effective
scope to the requested one: `PrimaryScope() == scope`. A dependency that
asserted no scope had `ScopeUnknown` as its effective scope, matched neither
`runtime` nor `development`, and so was invisible to both views.

That is the wrong answer for the common case, not for an edge one. SPDX has
no scope concept at all — the CLI reads a scope only from the `bomly:scope`
package comment — so every package in a third-party SPDX document arrives
unscoped, and a runtime view of such a document held nothing but structural
nodes. A scan could report clean because the filter had silently emptied it.
Detectors that cannot determine a scope, plugins that do not set one, and
ecosystems with no development/runtime distinction at all (container and OS
packages, Go modules) land in the same place.

Nothing outside Bomly can settle this. No SBOM specification defines what
`--scope runtime` returns, because the vocabulary being filtered is Bomly's
own two values rather than any format's. Where a specification *does* speak —
CycloneDX instructs a consumer to assume `required` when scope is not
specified — that instruction is already honored at ingest (ADR-0037's
resolution, bomly-dev/bomly-sdk#63). This ADR is about the remaining cases,
where no document said anything and no specification says what to do.

`ScopeUnknown` on a dependency node was considered as two distinct meanings
worth separating — "the detector could not determine it" and "the ecosystem
has no such concept". They do not need separating: neither is an assertion
that the dependency is development-only, so both take the same answer. The
structural third case never arises, because manifest and module nodes are
retained by kind and never scope-filtered at all.

## Decision

A scope filter selects on assertions, and absence is not an assertion.

- A **runtime** view keeps every dependency that is not affirmatively
  development-only — precisely, one whose scope set either names runtime or
  names nothing this build can read. A set naming *both* runtime and
  development is kept, since it names runtime. A set naming nothing readable
  — no scope at all, or only scopes this build cannot know, which is what a
  newer Bomly's token looks like to an older one — states nothing that places
  the dependency outside what ships, so it is kept too.
- **Every other** view requires an affirmative match, so a package that might
  ship never appears in the list a user reads as the one they can
  deprioritize.

Deliberately, the runtime arm is *not* "the effective scope is not
development". Those read alike and are not the same rule: `MergeScope` folds
any two non-runtime scopes to development, so a set of two tokens this build
cannot read — neither of them development — has `PrimaryScope() ==
ScopeDevelopment` and an effective-scope test would drop it. That is the
false negative this ADR exists to close, arriving by a different door.

This is one rule applied twice, not two rules: an unasserted scope resolves
toward "may be in production", the only direction that cannot hide a finding.
`MergeScope` already prefers runtime in a mixed set for the same reason.

The rule lives in `sdk.ScopeSetMatches`, and every site routes through it —
`FilterGraphByScope` via `DependencyNode.MatchesScopeFilter`, and the
usage-level conjunctive filter in `SelectUsages`. Two copies of a rule about
absence is how the graph view and the usage view would come to disagree about
the same dependency.

A view narrowed by scope also reports what it could not narrow.
`FilterGraphByScopeWithReport` and `FilterDetectionResultByScopeWithReport`
return the IDs of the dependencies a runtime view kept on absence; the SDK
does not log, so the CLI raises the warning. A runtime view that narrowed
nothing must not look narrowed.

The rule belongs to the filter rather than to ingest. Defaulting an absent
CycloneDX scalar to runtime is correct because the CycloneDX specification
instructs a consumer to do exactly that; SPDX issues no such instruction, so
stamping a scope onto an SPDX package at ingest would put a claim in the model
that no document made — and it would round-trip back out into an exported
document as an assertion Bomly invented.

## Consequences

- `--scope runtime` returns more, not less. Every previously invisible
  unscoped dependency now appears, which for a third-party SPDX document is
  the difference between an empty result and a real one. The cost is a longer
  list where a detector could not determine scope; the benefit is that the
  flag can no longer hide a vulnerable package behind a claim nobody made.
- `--scope development` is unchanged, including for a dependency whose union
  holds both scopes: `PrimaryScope` says such a package ships, and it stays
  out of the development view.
- `MatchesScopeFilter` requires, for every view but runtime, that the set name
  the requested scope *and* not name runtime. `Scopes` is a union across
  declaration sites, so plain membership would put a package that also ships
  into the development view. The condition is spelled out rather than
  delegated to `PrimaryScope`, for the same reason the runtime arm is:
  `MergeScope` returns development for any two non-runtime scopes, so an
  effective-scope comparison would admit a dependency nobody scoped
  development into the one view that must be affirmative. A single
  declaration site is matched by membership alone — there, naming a scope is
  the whole question.
- Guards: `TestAnUnassertedScopeStaysInARuntimeView`,
  `TestScopeSetMatchesIsTheOneRule`, and
  `TestSelectUsagesAppliesTheAbsenceRule` in the SDK. The rule is also stated
  in both repositories' `AGENTS.md`, since the failure mode is a consumer
  writing its own comparison.
- `Scopes` is not gated on the wire: a plugin can send a scope token this
  build does not know, and it survives to the filter. That is why the rule is
  written as "not affirmatively development" rather than as an equality test
  on the effective scope — the latter would drop such a node from every view.
