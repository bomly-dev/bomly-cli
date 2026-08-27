# ADR-0036: Dependency identity is content-addressable and SDK-derived

- **Date:** 2026-08-26
- **Status:** Accepted

## Context

Bomly has three notions of identity today, and none of them is strong enough
to key a node on its own:

- `Dependency.ID`, the graph key, defaults to `Coordinates.StableID()` —
  `org:name@version` with no ecosystem component. `left-pad@1.0.0` from npm
  and `left-pad@1.0.0` from PyPI produce the same ID inside one merged graph.
  Detectors may also mint IDs freely before consolidation, so the same
  package can enter the pipeline under several ID shapes.
- `Coordinates.IdentityKey()` is a versionless NUL-joined tuple used only for
  diff grouping.
- The canonical PURL keys the `PackageRegistry`, but a PURL is only derivable
  after normalization, cannot carry qualifiers or subpath today, and is
  reconstructed by three different rewrite sites with three different
  fallback chains (`internal/engine/consolidation/enrichment.go`,
  `internal/detectors/sbom/detector.go`, `internal/sbom/graph.go`).

The cost of this split is not hypothetical. PR #407 was a real dependency
silently vanishing because cargo workspace membership was resolved by name
alone; PR #406 was scopes lost when same-ID nodes folded; the coordinates
finding parked on issue #410 is SBOM ingest producing nodes whose `Org`/`Name`
split is non-canonical, which corrupts `QualifiedName()` and therefore
`StableID()` downstream. Each fix patched one site because no single place
owned the question "what makes two nodes the same node?".

A second pressure is forward-looking: if nodes are ever persisted outside a
single scan (a cloud graph store, cross-run caching, baseline attachment),
they need an identity that is stable across runs and machines, does not leak
resolution evidence such as source URLs, and can be compared without shipping
the whole node.

## Decision

Node identity is defined once, in the SDK, as a versioned set of identity
facets, and every identifier is derived from those facets by SDK code.

**The facets.** A node's identity is the pair (package identity, occurrence
qualifier). Package identity is the canonical PURL — including subpath and
identity-safe qualifiers once the SDK can carry them (ADR-0038): qualifiers
enter the identity form only through a `purlkit` allowlist of
identity-bearing keys, and URL-valued qualifiers pass the same
credential/local-path gates as every published URL (ADR-0033), because an
ingested PURL whose qualifier embeds a token must not become a published ID
by canonicalization alone. When no PURL is derivable, package identity is
the coordinate tuple `ecosystem, package manager, type, org, name, version`. The occurrence qualifier distinguishes contradicting
resolutions of the same package per ADR-0033, but with a stricter admission
rule than consolidation's current resolution key: only normalized,
machine-independent, credential-free values enter the facet — the first-party
sentinel or the normalized origin (ADR-0033's gates). The raw `ResolvedURL`
never enters the facet encoding: it can carry local paths and credentials, it
varies across machines and credential rotations for the same dependency, and
hashing does not protect a low-entropy secret from offline guessing. A node
whose resolution is distinguishable only by raw evidence still gets a
distinct readable ID within the run, but its discriminator is ephemeral and
content-free — a per-identity ordinal assigned deterministically during
consolidation, never a hash of the evidence — because readable IDs are
published in scan JSON and SBOMs, and a hash of a machine-specific path or
low-entropy credential would carry the same instability and offline-guessing
exposure into the published document. The persistent content address is
derived from the stable facets alone — such nodes share an address and are
disambiguated by the graph, not the address, and that limitation is stated
rather than papered over.

**The readable ID.** `Dependency.ID` remains human-readable, because node IDs
become CycloneDX bom-refs, SPDX element IDs, and `DependencyRefs` in scan
JSON: the canonical PURL where one exists, with an occurrence suffix when
the occurrence qualifier is non-default — a truncated hash of the admitted
occurrence facet, or the run-local ordinal where only raw evidence
distinguishes records. Neither form ever embeds the raw qualifier or a hash
of raw evidence, because these IDs are published and qualifiers can carry
credentials and local paths. The suffix delimiter also moves off `#`, which
PURL syntax already uses to introduce a subpath: once PURLs carry subpaths
(ADR-0038), `pkg:golang/example@v1#module#abc123` cannot be split reliably.
The occurrence marker is instead separated by a delimiter that cannot appear
in a canonical PURL (a single space serves: canonical PURLs percent-encode
spaces), so the package-identity substring is recovered by structure, not
guesswork, and the delimiter change rides the same one-time ID change as the
rest of this decision. What changes is who computes it: `NewDependency`
and one SDK rewrite entry point derive it; detectors and the CLI stop minting
IDs by string concatenation, and the three divergent rewrite sites collapse
into one.

**The content address.** The SDK additionally exposes a content address for
each node: a SHA-256 digest over a versioned canonical encoding of the
facets — the `bomly:node:v1` tag followed by each facet as a length-prefixed
field, so the encoding stays injective even when untrusted input contains
delimiter bytes (a NUL-joined tuple would let `("a\x00b", "c")` and
`("a", "b\x00c")` collide) — truncated to 128 bits and hex-encoded. The
version prefix means the facet set can evolve
by bumping to `v2` without silently changing every stored address. The digest
is deliberately derived, not stored as model state — it can always be
recomputed from the facets, so persisting it is an optimization, never a
source of truth.

**Ecosystem qualification.** `StableID()` is redefined to include the
ecosystem facet (or deprecated in favor of the facet API), removing the
cross-ecosystem collision. This is a v0 in-process API change; the wire shape
of `Dependency` is unchanged.

## Consequences

- Node IDs in scan JSON, bom-refs, and goldens change once, when the CLI
  adopts the SDK-derived identity. That is a one-time output-visible change
  shipped with regenerated schemas and a smoke-golden refresh, called out in
  release notes.
- The "what makes two nodes the same node?" question has one answer with one
  home. Bugs of the #406/#407 class become SDK bugs with SDK tests, not
  per-detector patches.
- A guard test in the CLI fails when a node ID is constructed outside the SDK
  entry points, in the spirit of `TestNodeInsertionGoesThroughTheSharedHelper`.
- The content address gives cloud persistence and cross-run comparison a key
  that is stable, collision-resistant, and free of resolution evidence — and
  because it is versioned and truncatable, the storage layer may shorten or
  re-derive it without a model change.
- Two hashing choices are deliberately conservative: SHA-256 (already the
  digest of record in `filecache` and `OccurrenceID`), and no use of
  `hash/maphash` (its seeds are per-process, which is exactly what a
  cross-run identity must not depend on).
