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
same warning policy; a module that cannot mint one is identified by its
declaring manifest path plus its name, because it is the project's own
record, not a registry lookup key.

Qualifiers are part of identity, as the specification says they are
(`arch`, `distro`, `upstream`, `epoch`, `classifier`, …): container scans
genuinely carry one package/version under two architectures, and dropping
qualifiers would collide identities the spec keeps distinct. Which
qualifiers, exactly, is still the specification's call, not an open door:
identity keeps the qualifier keys the specification knows — its
registered keys and each type's documented keys — and an unrecognized
custom key is dropped from identity with a recorded warning, because an
imported document can invent a qualifier whose value embeds a token, and
node IDs are published. The list is spec-derived, never Bomly-invented.
Two of the spec's known keys are excluded by role rather than obscurity:
the URL-valued evidence keys — `repository_url`, `download_url`, and
`vcs_url` — carry resolution evidence, so identity normalization strips
them from the PURL and redirects their content through the ADR-0033
origin constructors — a relocation, not a deletion: consumers that read
these qualifiers today (the Scorecard matcher resolves a package's
repository from exactly these keys) receive the vetted origin signal
instead, projected onto the match request when the registry package is
seeded from the graph, so no lookup silently loses its input. The
constructors reject a query-carrying artifact URL outright
— a signed or tokenized link is discarded entirely, not sanitized into
something publishable — so a credential embedded in a qualifier can reach
neither a published ID nor an exported origin field. (ADR-0033's prose
spelled the query-strip rule only for repository URLs; this ADR amends it
to record what the gate ships: the artifact form rejects query-carrying
URLs rather than retaining them.) Where an ecosystem genuinely treats
source as part of package identity (Cargo's lockfile does), its detector
expresses that in the PURL it mints — identity stays in the PURL, where
the standard puts it.

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
path. Every path that participates in identity is the canonical
repository-relative, slash-separated form, enforced by the SDK
constructors — an absolute checkout path or a backslash spelling would
split one module into two nodes and make IDs vary across machines. Keys
are in-process comparison values, kind-prefixed, and never appear in
published documents. Merging is folding: records that compare
equal union their scopes, locations, and origins; records that do not
compare equal are different nodes.

**Readable IDs are the identity itself.** A dependency node's graph ID is
its canonical PURL — unique within a graph by construction, because
identity is the PURL and the graph holds one node per identity. Module
and manifest nodes use their path-derived identities, rendered
kind-qualified so a PURL-less module and the manifest that declares it —
two nodes under the equality rule — can never share a published ID. No
suffix grammar exists. Reference semantics follow the formats: CycloneDX
`bom-ref` accepts the PURL directly, so there handle and identity
coincide; SPDX element IDs have their own idstring grammar (no `:`, `/`,
or `@`), so the SPDX encoder keeps its existing projection — sanitized
`SPDXRef-` handles with a collision map — as a format-local rendering of
the graph ID, never a second identity.

**The wire stays inside `bomly.plugin.v1`, with a specified
discriminator.** Nodes keep their flat JSON shape and gain one additive
`omitempty` `kind` field with exactly three values: `manifest`, `module`,
and `dependency`. An explicit `kind` is authoritative and wins when it
disagrees with the legacy package-type field; a payload without one —
every pre-union binary — infers its kind deterministically: package-type
manifest → manifest, the first-party marker → module, everything else —
including an application-typed component without the marker — →
dependency. Application type alone is not an ownership signal (ADR-0015's
rule): an imported SBOM's application component stays a dependency node,
matchable and enrichable, rather than being silently promoted to a
never-matched module. An unrecognized `kind` value is a decode
error, not a guess: a v1 payload can only carry v1 kinds, and a future
kind means a v2 negotiation, per the additive-forever rule. The origins
list is likewise an additive `omitempty` field beside the existing
singular origin field, which remains readable for legacy payloads; when a
payload carries both, decoders union them and deduplicate by normalized
value, so no combination drops or double-counts origin evidence. Frozen
wire fixtures pin the discriminator cases — explicit, legacy-inferred,
conflicting, and unknown — plus the both-origin-fields payload.

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
  and the origins list retains the observable difference. Registry-match
  eligibility folds toward eligible: the folded node is matchable when any
  folded witness was, because withholding enrichment from a PURL that a
  registry release genuinely uses would hide vulnerabilities, while the
  reverse direction merely enriches a PURL the registry also serves. This
  narrows ADR-0015's occurrence-level eligibility to the node level with
  an any-witness rule — the per-source observations stay readable in the
  origins list.
- Folding by PURL also unions dependency edges: when a lockfile carries
  one canonical PURL at two positions with different child sets (npm's
  duplicate-path corner), the folded node holds both edge sets, and path
  traversal becomes PURL-granular rather than position-granular. That is
  the granularity GitHub, Snyk, and CycloneDX operate at, and it is
  accepted deliberately; the test pinning position-distinct duplicates
  changes expectation at adoption, and an ecosystem that considers such
  records genuinely different packages expresses that difference in the
  PURLs its detector mints.
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

## Clarifications (2026-08-29, recorded at implementation)

Three points sharpened while building bomly-sdk v0.6.0 (PRs #16–#18):

- **What "the library decides" means.** packageurl-go v0.1.7 — the latest
  release — validates purl syntax and canonical form plus seven types'
  structural rules; it enforces no Maven-namespace rule and models no
  qualifier registry, and upstream is trending looser. So the library owns
  *syntactic and canonical-form* validity, while *type-profile* validity
  (namespace required or prohibited per type, required qualifiers) lives in
  a purlkit table transcribed from the purl specification's own
  machine-readable per-type definitions — spec-derived, never
  Bomly-invented, and applied only to types the table knows.
- **The open type vocabulary is the extensibility contract.** The purl type
  grammar is open and unknown types validate on syntax alone — never
  rejected for being unknown — so any ecosystem a detector author can
  imagine expresses itself as a purl type and flows through registry,
  matching, and SBOM export untouched. Relatedly, the earlier
  drop-unknown-qualifiers sentence is corrected: the specification's
  per-type qualifier lists are documentation, not closed sets (the apk
  definition's own prose references a distro key its list omits), and
  container purls legitimately carry arch/distro identity — so every
  qualifier is identity except the three universal URL-valued evidence keys,
  which relocate through the origin gates. Retaining the rest is not a new
  exposure and is deliberately not guarded by a secret heuristic: a
  qualifier value is identity data the producing document already published
  in the very purl Bomly reproduces, so the reproduction discloses nothing
  the source did not (the evidence keys differ in kind — the specification
  designates them as resolution links, which is why they relocate); and a
  "reject sensitive-looking values" gate is exactly the credential-prefix
  list and secret-shape heuristic ADR-0033 deliberately eliminated —
  hand-rolled secret detection is a second home for security semantics
  with false positives on identity data and false confidence everywhere
  else. A producer that embeds a credential in its own published package
  identity has disclosed it at the source; the fix belongs there.
- **Identity well-formedness is enforced at the wire decoder too.** A
  dependency payload that cannot mint a well-formed package URL — custom
  types included — is a decode error, per the maintainer's strict ruling:
  legacy payloads keep decoding exactly when they are valid.
