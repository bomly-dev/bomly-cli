# ADR-0037: SBOM assertions are typed SDK model fields, not metadata keys

- **Date:** 2026-08-26
- **Status:** Accepted

## Context

Bomly's name comes from SBOM, yet the SDK model cannot carry most of what the
two major SBOM formats say about a component. Relative to SPDX 2.3 and
CycloneDX 1.5/1.6, `Dependency` and `Package` have no supplier, no
originator/author, no description, no homepage, no generic external
references, no declared-versus-concluded license distinction (`LicenseType`
has exactly one value), and graph edges carry no relationship type. Document
level assertions — provenance, lifecycle, serial number, the primary
component's own facts — have no model home at all.

The consequences are measurable. `ToGraph` (`internal/sbom/graph.go`)
discards CPEs, digests, vulnerabilities, EOL, and every origin URL on ingest
because the graph hop has nowhere to put per-assertion data it cannot trust
blindly; `bomly scan --sbom --format spdx` therefore silently drops most of
what the source document asserted (issue #396). PR #391 tried to close that
gap by smuggling assertions through `Dependency.Metadata` under ad-hoc
`bomly.sbom.*` keys and did not survive review: twenty rounds kept finding
the same two structural defects — untyped metadata values cross the plugin
trust boundary without re-clearing any publication gate, and merge semantics
re-decided at every call site drift apart. The metadata map also does not
survive the JSON wire as typed values, so plugins see `[]any` where the CLI
wrote structs.

## Decision

Every SBOM assertion Bomly preserves is a typed, validated field on the SDK
model. The SDK model is the intermediate representation between SPDX,
CycloneDX, the CLI, detectors, and plugins — rich enough that the format
codecs are projections of it, not extensions to it.

**Component-level fields.** `Dependency` and `Package` (or `Coordinates`
where identity-adjacent) gain optional `omitempty` fields for supplier,
originator, description, homepage, and a typed
`ExternalReference{Category, Type, Locator, Comment, Hashes}` list whose
vocabulary covers both formats' reference categories — `Category` preserves
SPDX's `referenceCategory` alongside the type, so the SPDX triple
(category, type, locator) round-trips without re-derivation. Reference
hashes round-trip natively in CycloneDX; SPDX 2.3 has no slot for them, so
on SPDX export they ride the existing `bomly:` comment channel, and codec
fixtures cover every supported category and reference hashes in both
directions. The locator is typed,
not assumed to be a web URL: both formats carry non-URL locators — Bomly
itself emits `pkg:` PURLs and `cpe:` values as SPDX external references
today, and advisory references may be bare identifiers. Validation
dispatches on an explicit locator kind (url, purl, cpe, bounded
identifier) that the SDK derives from the normalized format/category/type
tuple — never from `Category` alone, which is an SPDX-only axis with no
CycloneDX source value: url-kind locators pass the ADR-0033 gate family,
purl and cpe locators their own grammars, and everything else — SPDX
`OTHER` references included — the bounded-identifier form. `PackageLicense` grows to
distinguish declared from concluded and to carry extracted license text for
`LicenseRef-*` identifiers (issue #410). The digest algorithm set is a
registry aligned with both formats' hash vocabularies rather than two string
constants. Scope gains an SDK-owned mapping to and from the CycloneDX
vocabulary (`required`/`optional`/`excluded`), so the mapping exists in
exactly one place and is exercised in both directions — and it is defined
for the scope *set*, not just a scalar. Both native fields hold one value
(CycloneDX `scope` is a scalar, and the neutral component model mirrors it),
so the SDK also defines the scalar projection rule for a multi-scope node
and the lossless side channel that carries the full set — a namespaced
`bomly:scopes` CycloneDX property and the existing `bomly:scope` SPDX
comment field, both read back on ingest — so the scope union PR #406
established survives the round trip instead of being flattened. The rules
are complete, not illustrative: the scalar projection is any-runtime →
`required`, otherwise `excluded`; the carrier is the lexicographically
sorted, deduplicated, comma-joined list of SDK scope tokens; on ingest the
carrier wins over the scalar when both are present, unknown tokens are
dropped with a warning, and a bare scalar maps `required` → runtime and
`optional`/`excluded` → development for Bomly's own filtering semantics —
while the ingested scalar itself is preserved as a source assertion and
re-emitted verbatim on a single-source export unless Bomly's own scope set
changed, so `optional` and `excluded` never collapse across a round trip
that asserted neither.

**Usage facts carry their attribution.** Scope, relationship, and
reachability answer questions about a *usage*, and filters compose them
conjunctively — "reachable, runtime, and direct" must hold of one usage, not
of three different usages summarized onto the same node. Today each is a
lossy summary: `Scopes` is a node-level union with no record of which
declaration site contributed which scope, `Relationship` is a merged scalar,
and `Reachability` annotates the vulnerability with no link to the node or
module whose analysis established it. So the model records usage facts where
they are observed: `PackageLocation` gains the scopes and relationship
observed at that declaration site (the node-level union becomes derived
rather than primary), and reachability becomes repeatable evidence — each
analysis contributes an evidence record keyed by the module root it was
established in, and the vulnerability-level annotation becomes the derived
summary of that list. A package present in several module roots is analyzed
per root, so a singular annotation with one root field could retain at most
one analysis after vulnerability consolidation; the evidence list keeps
every record. The conjunctive join is evidence-to-location within the same
module root — never the summary joined to every location. The join key is
explicit: the usage unit is (module root, declaration site), and the
location record carries its module root as a field — two modules can share
one lockfile or declaration path, so the site alone cannot identify the
owning module, and without the stored key consolidation would discard the
entry ownership the evidence join needs. Scope and
relationship attach per site and are never combined across sites; a
conjunctive filter must find its scope and relationship conjuncts on a
single site, and its reachability on that site's module root — legitimate,
because reachability is a fact about the module's own code and so covers
every site within its root. Evidence records may additionally carry
`DependencyRefs` — the IDs of the exact graph nodes the analysis involved,
final by analysis time because analyzers run after consolidation. The
module root is the mandatory attribution floor (every analyzer knows its
root; it arrives in the request), and node references are the optional
precision ceiling for analyzers that can attribute to a specific
occurrence: govulncheck knows the exact module version in the build,
jsreach can distinguish nested `node_modules` copies through their
locations, while others resolve one copy per environment and speak only at
module granularity. Display follows the evidence honestly: with node
references, the exact occurrence is highlighted; without them, the
occurrences in the establishing root show "reachable via this module" and
every other occurrence shows "not established here" — never "unreachable,"
which no one asserted. The package → nodes direction needed for these joins
stays derived, not stored: the stored truth is `Dependency.PackageRef`, and
the SDK provides a reverse-index helper built from the graph — a stored
back-reference list on `Package` would break the registry's position-free
design (ADR-0006) and go stale on every consolidation rename. A conjunctive
filter then selects usages, and the display shows the dependency path whose
attribution satisfies every conjunct — instead of a node that satisfies
each conjunct somewhere.

**Typed edges.** `DependencyEdge` gains an optional relationship kind
(default depends-on; contains, describes, and the other members both formats
need). Absence means depends-on, so the wire stays additive. Kinds must
also survive graph reconstruction: consolidation rebuilds edges during
identity rewrites and renames via `AddEdge(fromID, toID)`, which would
silently flatten every ingested kind back to depends-on. The SDK therefore
provides a kind-preserving edge-copy/rename primitive, every reconstruction
site routes through it, and a guard test fails on kind-blind edge rebuilding
in copy paths.

**A document-level carrier.** Document assertions (provenance, lifecycle,
serial identity, primary-component assertions) attach to `GraphEntry`, next
to the manifest metadata that already identifies each entry's source — not
to `GraphContainer`, which is explicitly multi-entry: consolidation combines
entries from several documents, and a container-level block would have to
merge or discard per-document identity. What a source document says about
*itself* thereby survives ingest → graph → re-export per document, and a
merged export states its own aggregate identity rather than inheriting one
source's. The carrier must also survive the export call path: today the
pipeline merges entries into one `sdk.Graph` and the SBOM codec is handed
only that graph, which would discard entry-level assertions before export
ever sees them. The export surface therefore takes the prepared entries (or
a consolidated view that retains them) rather than a bare merged graph, and
a single document exported from several entries follows the stated rule
above — the document asserts its own aggregate identity while preserved
per-source assertions ride the entries they came from. That projection is
defined, not implied: both formats give one document exactly one identity
and one primary component, so a merged document *links* each source's
identity rather than re-asserting it — SPDX `externalDocumentRefs`,
CycloneDX an external reference of type `bom` carrying the source serial —
while component-level assertions are preserved in full. The carrier retains
what the link forms require, captured at ingest while the original bytes
are still in hand — namespace or serial, document version, and a checksum
over the original bytes, for every ingested document regardless of its
format. The projection is then defined per output format. SPDX has no
primary-component field, so the aggregate document `DESCRIBES` each root
(the existing ADR-0032 mechanism, one relationship per root) and links each
source via `externalDocumentRef` — the source's namespace, or its serial
URN when the source was CycloneDX, plus the ingest-computed checksum, since
the ref is invalid without both. CycloneDX links each source via an
external reference of type `bom`: a BOM-Link `urn:cdx:<serial>/<version>`
when the source has a serial (version captured at ingest, defaulting to 1),
or the source namespace URI when it does not. Merged fixtures for both
formats are validated through the codecs and the official format validators
as part of the adoption phase. The fixed-point
round-trip promise is correspondingly scoped to single-source flows: one
ingested document re-exported reproduces its own assertions; a merged
export preserves component assertions and references its sources.

**Validation lives with the type.** Every field that carries untrusted input
validates at the model boundary the way `DependencyOrigin` already does:
custom JSON codecs re-run normalization on both marshal and unmarshal, so a
value that bypassed a call-site gate is still caught at the wire. URL fields
share the credential/local-path gate family from ADR-0033, with asserted
semantics where the source declared the value. Every new parser of untrusted
input ships with a registered fuzz target from its first commit.

**Merge semantics are declared per field class, once.** Scalars fill gaps,
sets union, and contradictions keep distinct occurrences under ADR-0033's
rule — implemented in the SDK's fold/merge helpers, never re-decided at call
sites. The precedence among sources is stated once: detection classifies,
ingest corrects, enrichment fills gaps.

**Metadata becomes an escape hatch again.** The `Metadata` map remains for
genuinely component-private data, with the `bomly.` prefix documented as
reserved. No new user-visible feature may ship its data as a metadata key;
the migration path for a metadata key is a typed field.

## Resolution (2026-09-06): the `optional` scalar maps to development

The rule above says a bare CycloneDX scalar maps `optional` → development.
The SDK shipped the opposite — `optional` → runtime — arguing in
`scope_cyclonedx.go` that an optional component provides additional
functionality at runtime and so is not a development-only dependency.
Neither document referenced the other, and a test added in PR #431 pinned
the shipped behavior, which would have ratified the deviation in passing.

**The CycloneDX specification settles it, and outranks both documents.**
Bomly does not get to decide what a word means in a format it does not own.
The 1.6 and 1.7 schemas define the vocabulary normatively in their
`meta:enum` descriptions (`schema/bom-1.6.schema.json`, vendored inside the
pinned `cyclonedx-go`): `required` is the component required for runtime;
`excluded` documents test and other non-runtime usage; and an `optional`
component is one "not capable of being called due to them not being
installed or otherwise accessible by any means", with the spec adding that a
component which *is* installed but is merely prohibited from being called
"must be scoped as 'required'".

So `optional` asserts that a component is absent from what runs — the
opposite of the SDK's reading, which was the pre-1.6 gloss of the word
rather than anything the format says. Only `required` describes a component
present at runtime; `optional` and `excluded` both describe one that is not,
which is Bomly's development scope for filtering purposes. **This ADR's
clause stands as written, and the SDK changed to match**
(bomly-dev/bomly-sdk#63).

The earlier note recorded a false-negative worry, and it is answered rather
than dismissed: a producer that spells an installed conditional dependency
`optional` — npm `optionalDependencies` are the common case — now has that
component dropped by `--scope runtime`. That producer is contradicting the
specification, which tells it to spell such a component `required`. Reading
the vocabulary loosely to accommodate it would mean misreading every
conforming document instead, so the remedy is a producer-side bug report,
not a Bomly-side redefinition. If the risk later warrants action here, it
takes the shape of a warning or a documented Bomly-owned policy knob that
says plainly that it departs from the specification — not a quiet remapping.

The scope carrier (`bomly:scopes`) bounds the blast radius: the scalar
mapping is consulted only for documents Bomly did not write, since its own
documents round-trip the full scope set. Source scalars are still preserved
and re-emitted verbatim per the rule above — a component ingested as
`optional` now carries {development} and still exports as `optional`.

### A second deviation, found by the same reading

Reading the specification properly also settled something this ADR never
addressed and nobody had argued about: `scope` is an optional attribute, and
CycloneDX says what an absent one means — scope "SHOULD be assumed" to be
`required` when it is not specified, restated in the schema as a `required`
default. The SDK read an absent scalar as no scope at all, so an unscoped
component reached the graph unscoped and was dropped by `--scope runtime`.
Most documents Bomly did not write omit the attribute entirely, which made
that a false negative on the common case rather than on an edge one — wider
than the `optional` question it was found beside.

So the ingest rule above gains a clause: an absent scalar reads as runtime.
A scalar that is *present* but unreadable — spelled in another format's
vocabulary, say — is still not defaulted and still yields no scope, because
"not specified" is the only case the specification assigns a default to and
an unreadable value has an unknown meaning rather than a defaulted one.

One consequence is visible in written documents: a component that stated no
scope now exports as an explicit `required`. There is no source word to
re-emit, and `required` is what the specification says an unspecified scope
means, so writing it states the reading Bomly applied rather than leaving the
next consumer to re-derive it. Golden SBOM fixtures gain that line when the
SDK pin moves.

### What absence means after ingest

Resolving the ingest side raised the matching question on the filter side:
what a *filter* should do with a dependency that asserted no scope at all,
which is what SPDX ingest always produces because SPDX has no scope concept.
That is Bomly policy rather than any specification's, so it is recorded
separately as [ADR-0043](0043-a-scope-filter-selects-on-assertions.md): a
filter selects on assertions, absence is not one, and a runtime view keeps
everything not affirmatively development.

### The general rule

Recorded in `AGENTS.md` under Non-Negotiable: a format's specification
outranks any Bomly document about that format's meaning, accepted ADRs
included, and such a question is resolved by citing the specification rather
than by arguing the merits. Both defects above were found by reading the spec
text once; neither was going to be found by another round of arguing the
merits on a pull request.

## Consequences

- Issue #396 becomes implementable: preservation is adding codec projections
  for fields that already exist, carry their own gates, and merge by declared
  rules — not smuggling and re-gating at every site.
- The wire stays `bomly.plugin.v1`: all additions are optional `omitempty`
  fields, enforced by the existing wire-compatibility tests in the SDK.
  Plugins that ignore the new fields keep working; plugins that want to
  assert supplier or references now can, through the same contract built-ins
  use.
- The model grows. That is the accepted trade-off, and it is bounded: fields
  are admitted because SPDX or CycloneDX defines them, not speculatively, and
  each admission names its validation gate and merge class in the SDK doc
  comment.
- `ToGraph`/`FromDepGraph` shrink from lossy translations into projections,
  and the export-only joins (packages reaching back through `PackageRef` for
  location and origin data) stop being special cases.
- The deliberately deferred items from #396 stay deferred until their own
  adversarial review: ssh VCS locators, metadata-only primary components,
  and supplier-contact privacy.
