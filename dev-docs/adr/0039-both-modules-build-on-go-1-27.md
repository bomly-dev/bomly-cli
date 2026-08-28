# ADR-0039: Both modules build on Go 1.27; untrusted JSON parses strictly

- **Date:** 2026-08-26
- **Status:** Accepted

## Context

`bomly-cli` and `bomly-sdk` both declare `go 1.26.3`. Go 1.27 (released
August 2026) carries several features that bear directly on the maturity
program, not just on staying current: `encoding/json/v2` with strict
rejection of duplicate object names and invalid UTF-8; a standard-library
`uuid` package; generic methods; `strings.CutLast`; new `go fix`
modernizers; and `go mod tidy` require-block consolidation for 1.27 modules.

The json/v2 point is a security posture question, not a convenience. Bomly
parses SBOM documents, plugin payloads, baselines, and lockfiles produced by
untrusted parties. Under `encoding/json` v1 semantics, a document with a
duplicated object name still parses: members are processed in input order,
and whether a later value replaces or merges with an earlier one depends on
the target Go type — replacement for scalars, merging for structs and maps —
with the documentation explicitly warning applications not to depend on the
outcome. That is precisely the problem: two consumers decoding the same SBOM
into different shapes can read two different license or PURL values from one
document — a classic smuggling vector against exactly the kind of tool Bomly
is.

## Decision

Both modules — and the nine `bomly-plugin-*` repositories that pin the
SDK — move to `go 1.27` in the same coordinated release train as the model
changes (ADR-0036/0037/0038). The ordering matters: a module's `go`
directive must be at least its dependencies', so each plugin repo bumps its
own toolchain (directive, CI, release builder) *before* adopting the first
SDK tag that declares 1.27; the SDK tags first per the pin ordering, and
the CLI moves with it.

**Strict parsing for untrusted documents.** Parsers of untrusted input —
SBOM ingest first, baseline and plugin-manifest codecs as they are touched —
move to `encoding/json/v2` with duplicate-name rejection and UTF-8 validity
enforced. The guarantee is exactly those two ambiguity classes — a document
with duplicate object names or invalid UTF-8 is rejected with an actionable
error. Other reader-divergence classes (case-variant field matching, for
one) are not covered by json/v2's defaults and are not claimed here; closing
any of them would be its own validation with its own decision. The change is
documented as deliberate behavior in `docs/SBOM.md`. The plugin wire (`bomly.plugin.v1`) keeps its current
decoding semantics: its compatibility contract is frozen fixtures, not
strictness, and tightening it is a protocol decision that would need its own
ADR.

**Standard library over dependencies where it now suffices.** The stdlib
`uuid` package takes over document serial-number generation. New language
features are adopted where they delete code, not decoratively: generic
methods where they replace package-level generic functions awkwardly bound
to a receiver, `strings.CutLast` in the name-splitting helpers `purlkit`
introduces, and one `go fix` modernizer pass per repo, reviewed like any
other change.

## Consequences

- `go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest` now requires
  a Go 1.27 toolchain. Users on Go 1.21 or later with the default
  `GOTOOLCHAIN=auto` get it automatically — the `go` directive triggers the
  toolchain download; users on older Go versions, or who set
  `GOTOOLCHAIN=local`, must upgrade by hand. CI matrices, release builders,
  and CONTRIBUTING move to 1.27 in the same PRs.
- Strict SBOM ingest can reject documents that previously parsed. That is
  the point, and it is bounded: rejection only fires on documents whose
  meaning was already ambiguous or whose encoding was already malformed. The
  error names the offending key or byte sequence so users can fix or
  re-generate the document.
- `go test` now runs the `stdversion` vet check by default and `go mod tidy`
  reshapes both go.mod files once; both are absorbed in the upgrade PRs.
- The `simd` packages and other experiments in 1.27 are out of scope; nothing
  in Bomly is allocation-bound enough to justify tracking unstable APIs.
