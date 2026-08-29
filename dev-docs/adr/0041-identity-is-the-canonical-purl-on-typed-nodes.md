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

**The occurrence qualifier is the normalized origin, and comparison
preserves the gap-fill rule.** The occurrence half of identity is the
ADR-0033-normalized `Origin` already on the node — no new storage, no
facet renderings, no hashes — which makes comparison wire-stable by
construction, since it uses exactly the view the JSON codec persists. The
SDK exposes the Java-style pair — an identity-equality predicate and an
identity key for map grouping — with a three-way origin relation rather
than naive equality, so ADR-0033's folding semantics survive:

- both records carry normalized origins and they are equal → the same
  occurrence; witnesses fold;
- exactly one record carries an origin → a gap; the gap witness folds into
  the origin-bearing record (ADR-0033's fill rule, unchanged);
- both carry origins and they differ → distinct occurrences that coexist.

Comparison is kind-scoped: nodes of different kinds are never equal, so a
module node and a dependency node sharing a PURL — or sharing the absence
of an origin — can never fold into each other, whatever the insertion
order. Module nodes compare by canonical PURL when both carry one and by
(declaring manifest path, name) otherwise; manifest nodes compare by path.
Keys are in-process comparison values, kind-prefixed, and never appear in
scan JSON, SBOMs, or any published document.

**Readable IDs need no grammar of their own.** A dependency node's graph ID
is its canonical PURL in identity form: qualifiers pass only through
purlkit's identity-qualifier allowlist — empty today, so all are dropped —
and the subpath is preserved. That gate exists because imported PURLs can
carry resolution evidence and credentials in qualifiers
(`repository_url=…`, signed download links), and node IDs are published as
SBOM component identifiers; admitting the first allowlist key is a
reviewed act that ships the ADR-0033 credential gates with it. When
distinct occurrences of one canonical PURL must coexist, every one of them
carries a deterministic run-local ordinal suffix — a single space and `o`
plus a decimal. Numbering starts at 1, is scoped per canonical PURL, and
is assigned in the sorted order of the occurrences' identity keys — never
arrival order, never a hash of evidence; golden tests pin the assignment
when the implementation lands. Raw resolution evidence (the verbatim
`ResolvedURL`, tokenized URLs) never reaches an ID. Module and manifest
nodes use their path-derived identities. The insertion entry point still
parks contradicting records under an ephemeral in-process discriminator
(NUL-marked, structurally disjoint from every readable ID) until
consolidation finalizes them; the ephemeral form never reaches output.

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
  must preserve module identity the same way), ordinals are never
  recycled, identity comparison is stable across the plugin wire, raw
  evidence is never provenance for a suffix, and discriminator
  vocabularies fold before derivation.
- ADR-0036 is superseded; the identity phase of `SDK_MATURITY_PLAN.md`
  (item 1.3) and every other identity reference in that plan are rescoped
  to this decision.
