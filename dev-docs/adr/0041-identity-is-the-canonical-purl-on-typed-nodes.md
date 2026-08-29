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
dozen call sites, and three rewrite sites disagreed. A second, older
problem joins them: one untyped `Dependency` struct plays every role — the
project's own root, a workspace module, a manifest file, a resolved
third-party package — distinguished only by convention (a type string, a
boolean), so nothing stops a structural record from masquerading as a
package or a first-party fold from being decided by insertion order. The
mechanism changes; the problem statements stand.

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
- a **dependency node** — one resolved third-party occurrence, the unit of
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

**Dependency identity is the canonical package URL, valid by the PURL
specification's own rules.** The PURL is the industry standard and
`purlkit` (backed by `package-url/packageurl-go`) is its one home; identity
introduces no second grammar and no Bomly-invented validity rule. A
dependency node is valid exactly when the library accepts its PURL under
the specification: scheme, type, and name at minimum, plus each type's own
requirements (Maven's group ID as the namespace, for example) — the
library, not Bomly, decides. The one Bomly policy layered on top is about
versions, which the specification leaves optional: a dependency node
without a version is accepted with a recorded warning rather than
rejected, because first-party-adjacent records and some imported SBOM
components legitimately lack one, and their absence should be visible, not
fatal. Module nodes derive a PURL when their coordinates allow one, under
the same warning policy; a module that cannot mint a PURL falls back to
path-based identity like a manifest, because it is the project's own
record, not a registry lookup key.

**The occurrence qualifier is the normalized origin, and an unknown origin
is its own occurrence.** The occurrence half of identity is the
ADR-0033-normalized `Origin` already on the node — no new storage, no
facet renderings — which makes comparison wire-stable by construction,
since it uses exactly the view the JSON codec persists. The SDK exposes
the Java-style pair — an identity-equality predicate and an identity key
for map grouping — with a three-way origin relation:

- both records carry normalized origins and they are equal → the same
  occurrence; witnesses fold;
- both carry origins and they differ → distinct occurrences that coexist;
- exactly one record carries an origin → distinct occurrences. An absent
  origin means "resolution unknown", which is a claim of its own, not a
  gap for consolidation to fill: folding it into whichever origin-bearing
  record appeared first would manufacture provenance the witness never
  asserted. This deliberately narrows ADR-0033's consolidation-time
  fill rule; where an ecosystem's semantics genuinely justify filling —
  one lockfile entry split across records — that ecosystem's detector
  fills the gap at detection time, before consolidation, where the
  context to justify it exists. Two records that both lack origins fold
  when nothing else distinguishes them, and stay distinct when raw
  resolution evidence proves they differ (raw evidence is legal for
  comparison, never for identity or publication).

Comparison is kind-scoped: nodes of different kinds are never equal, so a
module node and a dependency node sharing a PURL — or sharing the absence
of an origin — can never fold into each other, whatever the insertion
order. Module nodes always compare with their declaring manifest path as
part of the identity — beside the canonical PURL when one exists, beside
the module name otherwise — because a recursive scan can legitimately
discover two unrelated projects carrying the same ecosystem, name, and
version, and a PURL-only comparison would fold those separate roots and
union their dependency edges. Manifest nodes compare by path.
Keys are in-process comparison values, kind-prefixed, and never appear in
scan JSON, SBOMs, or any published document.

**Readable IDs need no grammar of their own.** A dependency node's graph ID
is its canonical PURL — qualifiers and subpath included, because the PURL
specification defines qualifiers as qualifying data (`arch`, `distro`,
`upstream`, `epoch`, `classifier`, …) and container scans genuinely carry
one package/version under two architectures: dropping qualifiers would
collide identities the spec keeps distinct. The exception is the
specification's URL-valued evidence keys — `repository_url`,
`download_url`, and `vcs_url` — whose values are resolution evidence that
can embed credentials and signed links: identity normalization strips them
from the PURL and their content belongs in `Origin`, behind the ADR-0033
gates, so they shape the occurrence, never a published ID. Redirection
means passing the value through the ADR-0033 origin constructors, never
stapling it on: those constructors reject a query-carrying artifact URL
outright — a signed or tokenized download link is discarded entirely, not
sanitized into something publishable — so a credential embedded in a
qualifier can reach neither a published ID nor an exported origin field. When distinct
occurrences of one canonical PURL must coexist, each origin-bearing
occurrence carries a deterministic suffix — a single space and a short
lowercase-hex hash of its kind-prefixed normalized origin. Deriving the
suffix from the occurrence's own origin means a contested occurrence keeps
one suffix for as long as it is contested — adding or removing a sibling
never renumbers the others, which positional ordinals could not promise —
and the normalized origin is already credential-free, so the hash
publishes nothing the origin field does not. A singleton keeps the bare
PURL, and gaining a first sibling does change its rendered ID; that is
deliberate, because readable IDs carry the reference semantics the major
SBOM formats define: CycloneDX `bom-ref` and SPDX element IDs are
document-local handles required only to be unique within one document,
with cross-document identity carried by the data fields (the PURL,
external references) rather than the handle. Bomly follows that industry
contract — IDs are unique within a run's outputs and as human-meaningful
as uniqueness allows, while cross-run identity lives in the identity
fields (canonical PURL, normalized origin) that diff, baselines, and
matching already join on. Suffixing every origin-bearing occurrence
unconditionally was considered and rejected: it would trade the common
case's readability for stability of a handle the formats define as
document-local. Occurrences distinguishable only by raw evidence
have nothing publishable to hash; they carry run-local ordinal suffixes
(`o1`, `o2`, … in sorted raw-key order) with the stated caveat that this
rare class is run-scoped and not stable across evidence changes — never a
hash of raw evidence, because raw resolution strings (the verbatim
`ResolvedURL`, tokenized URLs) never reach an ID in any form. Module and
manifest nodes use their path-derived identities. The insertion entry
point still parks contradicting records under an ephemeral in-process
discriminator (NUL-marked, structurally disjoint from every readable ID)
until consolidation finalizes them; the ephemeral form never reaches
output. Golden tests pin the suffix derivation and ordinal assignment when
the implementation lands.

**The wire stays inside `bomly.plugin.v1`, with a specified discriminator.**
Nodes keep their flat JSON shape and gain one additive `omitempty` `kind`
field with exactly three values: `manifest`, `module`, and `dependency`.
An explicit `kind` is authoritative and wins when it disagrees with the
legacy package-type field; a payload without one — every pre-union binary
— infers its kind deterministically: package-type manifest → manifest,
first-party or package-type application → module, everything else →
dependency. An unrecognized `kind` value is a decode error, not a guess: a
v1 payload can only carry v1 kinds, and a future kind means a v2
negotiation, per the additive-forever rule. Frozen wire fixtures pin all
four cases — explicit, legacy-inferred, conflicting, and unknown — so
independent implementations cannot classify one payload two ways.

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
  enrichment become simpler, iterating dependency nodes only, and
  first-party suppression stops being a flag check.
- The review-hardened invariants from the closed first round survive as
  behavior and tests, not machinery: ownership survives folds (now by
  construction — kinds never cross-fold, and the cross-entry merge helper
  must preserve module identity the same way), origin-derived suffixes are
  stable under occurrence-set changes, identity comparison is stable
  across the plugin wire, raw evidence is never provenance for a
  published suffix, and discriminator vocabularies fold before
  derivation.
- ADR-0036 is superseded; the identity phase of `SDK_MATURITY_PLAN.md`
  (item 1.3) and every other identity reference in that plan are rescoped
  to this decision.
