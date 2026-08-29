# ADR-0041: Identity is the canonical PURL on typed graph nodes

- **Date:** 2026-08-29
- **Status:** Accepted (supersedes ADR-0036)

## Context

ADR-0036 answered "what makes two nodes the same node?" with a bespoke
mechanism: a versioned facet pair, a byte-level readable-ID grammar with an
escaped coordinate-fallback family, hashed occurrence suffixes, and a
128-bit content address over a length-prefixed facet encoding. The first
implementation round (bomly-sdk PRs #13–#15, closed unmerged) proved the
mechanism could be made robust — and proved it should not exist. More than
ten review rounds of hardening (canonical escape spellings, UTF-8 wire
survival, suffix provenance, facet stability across the plugin codec) all
attached to the two pieces of hand-rolled surface: the fallback grammar and
the encode-then-hash address. Nothing in the pipeline consumes the content
address; its only prospective consumer is cloud persistence that does not
exist. Maintaining a private identity grammar beside the industry's
existing one is exactly the "second home for semantics" this repository's
own delegation principle forbids — this time self-inflicted rather than
inherited.

The problems ADR-0036 named are still real: `StableID()` collides across
ecosystems, occurrence identity was minted from hashed raw evidence at a
dozen call sites, and three rewrite sites disagreed. The mechanism changes;
the problem statement stands.

## Decision

**Package identity is the canonical package URL.** The PURL is the industry
standard and `purlkit` (backed by `package-url/packageurl-go`) is its one
home; identity introduces no second grammar beside it. A package node's
identity is valid only when a canonical PURL with at least a type and a
name is derivable; a node that cannot produce one is rejected at the
validation gate. A missing version is accepted with a recorded warning
rather than rejected — first-party roots and some imported SBOM components
legitimately lack one — so the strict triple (type, name, version) is the
norm and its absence is visible, not fatal.

**Graph nodes are a typed union.** The graph holds a sealed `GraphNode`
interface with two concrete types: a package node, which must carry a valid
canonical PURL and is the unit of matching and enrichment, and a manifest
node, which is a structural record identified by its path, is never
matched or enriched, and cannot masquerade as a package. The constructor is
the gate: building a package node from coordinates that cannot mint a valid
PURL is a compile-visible error path, not a silently empty ID. This is a
breaking in-process API change, allowed under the module's v0 policy; the
wire stays inside `bomly.plugin.v1` — nodes keep their flat JSON shape,
gaining one additive `omitempty` kind discriminator, and a legacy payload
without it infers the kind from its package-type field. (A generic
`Graph[N]` container was considered and rejected: detection graphs are
heterogeneous — a manifest root beside its package children — and Go's
generics are homogeneous with no sum types.)

**The occurrence qualifier is the normalized origin.** No new storage, no
facet renderings, no hashes: the occurrence half of identity is the
ADR-0033-normalized `Origin` already on the node — exactly the view the
JSON codec persists, so identity comparison is wire-stable by construction.

**Comparison is equals and key, never a published artifact.** The SDK
exposes the Java-style pair: an identity-equality predicate (canonical
PURLs equal and normalized origins equal) and an identity key for map
grouping. Consolidation folds records that compare equal and keeps records
that do not. The key is an in-process comparison value; it never appears in
scan JSON, SBOMs, or any published document.

**Readable IDs need no grammar of their own.** A package node's graph ID is
its canonical PURL. When contradicting occurrences of one PURL must coexist,
they are distinguished by a deterministic run-local ordinal suffix — a
single space and `o` plus a decimal, assigned per distinct identity key in
sorted order, never from arrival order and never from a hash of evidence.
Raw resolution evidence (the verbatim `ResolvedURL`, tokenized URLs) never
reaches an ID. Manifest nodes keep their path-based IDs. The insertion
entry point still parks contradicting records under an ephemeral in-process
discriminator (NUL-marked, structurally disjoint from every readable ID)
until consolidation finalizes them; the ephemeral form never reaches output.

**There is no content address.** Encode-then-hash identity is dropped
entirely. If cloud persistence ever materializes, an address can be derived
at that boundary from (canonical PURL, normalized origin) without new model
state — deferred until a consumer exists, recorded here so the option is
not lost.

## Consequences

- The bespoke identity surface — the coordinate-fallback grammar, the
  escape rules, the facet encodings, the golden byte vectors, the content
  address — is deleted. What remains delegates to purlkit and reuses the
  origin model that already exists.
- The typed node union is a one-time in-process break that every consumer
  absorbs at its own pin bump: the CLI in its phase-2 adoption train, the
  component repositories in the deferred plugin round. Matching and
  enrichment become simpler, iterating package nodes only.
- The review-hardened invariants from the closed first round survive as
  behavior and tests, not machinery: first-party ownership survives folds,
  ordinals are never recycled, identity comparison is stable across the
  plugin wire, and discriminator vocabularies fold before derivation.
- ADR-0036 is superseded; the identity phase of `SDK_MATURITY_PLAN.md`
  (item 1.3) is rescoped to this decision.
