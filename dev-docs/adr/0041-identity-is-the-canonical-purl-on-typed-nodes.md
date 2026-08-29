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
attached to the hand-rolled surface. Nothing in the pipeline consumes the
content address; its only prospective consumer is cloud persistence that
does not exist. Maintaining a private identity grammar beside the
industry's existing one is exactly the "second home for semantics" this
repository's own delegation principle forbids.

A second review round found the deeper root: most of the remaining
complexity — occurrence suffixes, ephemeral discriminators, contradiction
finalization, a three-way origin relation — existed to keep two records of
one package/version distinct when they claimed different sources *within a
single manifest*. That is a pathological corner, not a case: a lockfile is
a resolver's output, and resolvers pick one source per package and
version. The cross-manifest attribution that genuinely matters — which
manifest resolved this dependency from where — is already preserved
structurally by the container's per-manifest entry graphs. And the
industry is unanimous about the modeling: GitHub's dependency graph does
not model origin at all, Syft carries locations as a list on one package,
Snyk's dep-graph keys packages by name@version, and CycloneDX gives the
pattern a first-class shape in `component.evidence.occurrences` — one
component, a list of observations. Origin is evidence about an identity,
never identity itself.

The problems ADR-0036 named are still real: `StableID()` collides across
ecosystems, identity was minted by string concatenation at a dozen call
sites, and three rewrite sites disagreed. A second, older problem joins
them: one untyped `Dependency` struct plays every role — the project's own
root, a workspace module, a manifest file, a resolved third-party package —
distinguished only by convention (a type string, a boolean), so nothing
stops a structural record from masquerading as a package or a first-party
fold from being decided by insertion order. The mechanism changes; the
problem statements stand.

## Decision

**Graph nodes are a sealed typed union of three kinds.** The graph holds a
sealed `GraphNode` interface with three concrete types, named for what the
CLI actually models (a "package" in Bomly vocabulary is the registry
artifact produced by matching, so graph records deliberately avoid that
word):

- a **manifest node** — a structural file record (a `package.json`, a
  lockfile, a build script), identified by its path, never matched or
  enriched;
- a **module node** — one of the scanned project's own artifacts: the root
  project itself and every workspace or reactor module. First-party
  ownership stops being a boolean convention and becomes the node's kind,
  so it cannot be dropped by a fold or asserted by an imported document;
- a **dependency node** — one resolved third-party package, the unit of
  matching and enrichment.

The two shapes the CLI deals with today are both plain edge patterns over
these kinds, with no fourth kind needed: a single-project scan is
`manifest → module (the root) → dependency…`, and a workspace is
`manifest → module → child manifest → child module → … → dependency…`,
nesting as deep as the build does. Constructors are the gate: building a
dependency node from coordinates that cannot mint a valid PURL is a
compile-visible error path, not a silently empty ID. This is a breaking
in-process API change, allowed under the module's v0 policy. (A generic
`Graph[N]` container was considered and rejected: detection graphs are
heterogeneous — a manifest beside its module beside its dependencies — and
Go's generics are homogeneous with no sum types.)

**Dependency identity is the canonical package URL — all of it, and only
it.** The PURL is the industry standard and `purlkit` (backed by
`package-url/packageurl-go`) is its one home; identity introduces no
second grammar and no Bomly-invented validity rule. A dependency node is
valid exactly when the library accepts its PURL under the specification:
scheme, type, and name at minimum, plus each type's own requirements
(Maven's group ID as the namespace, for example) — the library, not
Bomly, decides. The one Bomly policy layered on top is about versions,
which the specification leaves optional: a dependency node without a
version is accepted with a recorded warning rather than rejected, because
first-party-adjacent records and some imported SBOM components
legitimately lack one, and their absence should be visible, not fatal.
Module nodes derive a PURL when their coordinates allow one, under the
same warning policy; a module that cannot mint one falls back to
path-based identity like a manifest, because it is the project's own
record, not a registry lookup key.

Qualifiers are part of identity, as the specification says they are
(`arch`, `distro`, `upstream`, `epoch`, `classifier`, …): container scans
genuinely carry one package/version under two architectures, and dropping
qualifiers would collide identities the spec keeps distinct. The
exception is the specification's URL-valued evidence keys —
`repository_url`, `download_url`, and `vcs_url` — whose values are
resolution evidence: identity normalization strips them from the PURL and
redirects their content through the ADR-0033 origin constructors, which
reject a query-carrying artifact URL outright — a signed or tokenized
link is discarded entirely, not sanitized into something publishable — so
a credential embedded in a qualifier can reach neither a published ID nor
an exported origin field. Where an ecosystem genuinely treats source as
part of package identity (Cargo's lockfile does), its detector expresses
that in the PURL it mints — identity stays in the PURL, where the
standard puts it.

**Origin is metadata, not identity.** A dependency node carries
`Origins []DependencyOrigin` — ADR-0033-normalized, union-merged, almost
always zero or one element. There are no occurrence suffixes, no
ordinals, no ephemeral discriminators, no contradiction finalization, and
no origin term in identity comparison: all of that machinery served the
same-manifest different-sources corner that resolvers do not produce.
What each rule used to protect is preserved more simply:

- *Which manifest resolved this from where* lives where it always did —
  the container's per-manifest entry graphs. Consolidation unions
  per-entry origins into the node's list; the entries keep the
  attribution.
- *A package claiming two different sources* is still visible — it is a
  node whose origins list has more than one element. That is a fact to
  display and, one day, for an auditor to flag (it is the shape of a
  dependency-confusion signal), not a reason to split identity.
- *Gap semantics dissolve*: an absent origin is an empty list, a known
  origin appends to it, and there is nothing to fill, fold, or
  contradict. Ecosystem detectors remain free to attach whatever origins
  their manifests assert.

**Identity comparison is the kind-scoped equals/key pair.** Two nodes are
the same node exactly when their kinds match and their identities match:
dependency nodes by canonical PURL; module nodes by declaring manifest
path beside the PURL (or the name, when no PURL is derivable) — a
recursive scan can discover two unrelated projects with identical
coordinates, and the path keeps those roots apart; manifest nodes by
path. Keys are in-process comparison values, kind-prefixed, and never
appear in published documents. Merging is folding: records that compare
equal union their scopes, locations, and origins; records that do not
compare equal are different nodes.

**Readable IDs are the identity itself.** A dependency node's graph ID is
its canonical PURL — unique within a graph by construction, because
identity is the PURL and the graph holds one node per identity. Module
and manifest nodes use their path-derived identities. No suffix grammar
exists. This matches the reference semantics the major SBOM formats
define: CycloneDX `bom-ref` and SPDX element IDs are document-local
handles, with cross-document identity carried by the data fields — here
the handle and the identity coincide, which is the most readable form a
handle can take.

**The wire stays inside `bomly.plugin.v1`, with a specified
discriminator.** Nodes keep their flat JSON shape and gain one additive
`omitempty` `kind` field with exactly three values: `manifest`, `module`,
and `dependency`. An explicit `kind` is authoritative and wins when it
disagrees with the legacy package-type field; a payload without one —
every pre-union binary — infers its kind deterministically: package-type
manifest → manifest, first-party or package-type application → module,
everything else → dependency. An unrecognized `kind` value is a decode
error, not a guess: a v1 payload can only carry v1 kinds, and a future
kind means a v2 negotiation, per the additive-forever rule. The origins
list is likewise an additive `omitempty` field beside the existing
singular origin field, which remains readable for legacy payloads. Frozen
wire fixtures pin the discriminator cases — explicit, legacy-inferred,
conflicting, and unknown.

**There is no content address.** Encode-then-hash identity is dropped
entirely. If cloud persistence ever materializes, an address can be
derived at that boundary from the canonical PURL without new model state —
deferred until a consumer exists, recorded here so the option is not
lost.

## Consequences

- The bespoke identity surface is deleted twice over: the ADR-0036
  grammar, encodings, and content address, and then the occurrence
  machinery itself — suffixes, ordinals, ephemeral discriminators,
  contradiction finalization, the origin term of comparison. Identity is
  one line: kind plus canonical PURL (path-scoped for the project's own
  records). Insertion is fold-by-identity with a union of scopes,
  locations, and origins.
- The model matches the industry: origin as evidence on one identity is
  how GitHub, Syft, Snyk, and CycloneDX's `evidence.occurrences` all
  model it. The usefulness-to-complexity test drives the shape — the
  same-manifest multi-source corner did not justify an identity
  dimension, and the information it carried survives as the origins list.
- A same-version registry package and git fork share a node unless the
  ecosystem's detector expresses the source in the PURL. Matching is
  PURL-keyed, so this costs no advisory precision — it never had any —
  and the origins list retains the observable difference.
- The typed node union is a one-time in-process break that every consumer
  absorbs at its own pin bump: the CLI in its phase-2 adoption train, the
  component repositories in the deferred plugin round. Matching and
  enrichment become simpler, iterating dependency nodes only, and
  first-party suppression stops being a flag check.
- ADR-0033 is narrowed where it described consolidation-time origin
  reconciliation: origins no longer reconcile because they no longer
  compete — they accumulate. Its publication gates (what a publishable
  origin URL is) are untouched and remain the only door into the origins
  list.
- ADR-0036 is superseded; the identity phase of `SDK_MATURITY_PLAN.md`
  (item 1.3) and every other identity reference in that plan are rescoped
  to this decision.
