# ADR-0038: PURL and SPDX behavior have one home in the SDK

- **Date:** 2026-08-26
- **Status:** Accepted

## Context

PURL and SPDX handling are re-derived across the CLI wherever a feature
needed them, and the copies disagree:

- The purl-type → ecosystem mapping exists twice —
  `internal/sbom/identity.go` deliberately refuses to map `pkg:hex` (Elixir
  and Erlang share it), while `internal/benchmark/summary.go` happily maps it
  to Elixir. Same input, different answer.
- `internal/cli/render/explain.go` extracts the purl type by string surgery
  (`TrimPrefix` + `SplitN`) and shows `golang` where every other surface
  shows `go`.
- Thirteen detectors hardcode purl type strings at `sdk.BuildPackageURL`
  call sites while six rely on SDK derivation — two paths to one field, with
  the literals unvalidated at each site.
- `internal/sbom/transform.go` hand-builds a `pkg:generic` PURL by string
  concatenation, and hand-maintains an 18-entry deprecated-SPDX-ID table that
  duplicates knowledge the vendored SPDX license list already has.
- The Org/Name split is inverted on SBOM ingest by prefix-matching
  heuristics (`ingestedCoordinateOrg`), re-deriving per-ecosystem rules that
  `EcosystemName()` and ADR-0021 already define in the forward direction —
  and getting them wrong enough that every `--sbom` ingest currently loses
  `Org` (the coordinates finding parked on issue #410).
- `internal/licenseexpr` correctly contains the SPDX expression parser's
  panics, but it is CLI-internal, so the deps.dev matcher and every external
  plugin that touches license strings cannot use it —
  `matcherkit.NormalizeLicenseSet` instead copies raw strings into
  `SPDXExpression` unvalidated, which is the exact field-versus-shape
  confusion ADR-0035 removed from export.

Per ADR-0029, shared behavior that both the CLI and external components need
belongs in `bomly-sdk` subpackages. PURL identity and SPDX license handling
are the two clearest cases in the codebase.

## Decision

The SDK is the single source of truth for PURL behavior and SPDX license
behavior. Two subpackages own them.

**`purlkit`** (with the existing root-package functions delegating to it or
deprecated onto it) owns: parse, build, and canonicalize — including
qualifiers and subpath, which the current builder cannot represent; the one
purl-type ↔ ecosystem/package-manager mapping table, recording the `pkg:hex`
ambiguity as an explicit non-mapping so no second table can quietly decide
otherwise; `SplitEcosystemName`, the per-ecosystem inverse of
`EcosystemName()` under ADR-0021's join rules, replacing the ingest
heuristics; and the single canonical-identity rewrite used by consolidation
(ADR-0036).

**`spdxkit`** absorbs `internal/licenseexpr` — the panic guards travel with
it, because license strings are untrusted everywhere, not just in the CLI —
and adds what the current consumers hand-roll: deprecated-identifier
canonicalization from the license list itself, classification-by-validation
as the one way a license value becomes an identifier, expression, or free
text (ADR-0035, now enforceable at write time in `NormalizeLicenseSet`
rather than repair time at export), and deterministic `LicenseRef-*` minting
with extracted-text pairing for unrecognized values (issue #410).

**The boundary is guarded, not remembered.** In each repo, a test in the
style of `TestNoDirectSPDXExpressionUse` fails when any package outside the
kit imports `github.com/anchore/packageurl-go` or `github.com/github/go-spdx`
directly, when a detector passes a purl-type string literal instead of
deriving it from its coordinates, or when a second mapping table appears.
The CLI keeps no shim copies: call sites migrate to the kit imports.

## Consequences

- The known divergences become impossible rather than fixed-until-next-time:
  one mapping table, one split rule, one classification rule, each with the
  edge-case reasoning (hex, OS-package namespaces, mixed-validity sets)
  recorded next to the code that enforces it.
- External matchers and plugins gain the same license-safety and PURL
  behavior built-ins have, which is a correctness fix for data they already
  write today.
- `internal/licenseexpr` is removed from the CLI once the kit lands; its
  guard test generalizes and moves with it. This follows the ADR-0029
  ordering: the SDK tags first, plugin repositories adopt, then the CLI
  updates its pin and deletes the internal copy.
- Kit APIs are additions to a v0 module; the removals (CLI-internal package,
  root-package duplicates) ride the same coordinated bumps as ADR-0036's
  identity change to keep the number of golden refreshes to one.
