# ADR-0042: A conversion restates its source; a merge links its sources

- **Date:** 2026-09-05
- **Status:** Accepted

## Context

ADR-0037 gave document-level assertions a model home on `GraphEntry` and
stated the shape of the export projection: a merged document asserts its own
aggregate identity and links each source, while a single ingested document
re-exported "reproduces its own assertions". Implementing that (issue #396,
phase 2.5) turned two of its sentences into decisions that had to be made
concretely, because both formats give a document exactly one identity and the
model can hold several.

The first is what a *conversion* does — one source document in, one document
out. Minting a fresh identity is the safe-looking answer, and it is the wrong
one: the source identity then has to be carried as a link, and on the next
ingest that link has nowhere to live, because `DocumentAssertions` describes
what a document says about *itself* and has no field for the documents behind
it. Each hop would therefore differ from the last, and the fixed point #396
requires — Bomly's own export, re-ingested and re-exported, byte-identical —
would be unreachable by construction.

The second is what the export surface receives. The pipeline merges entries
into one `sdk.Graph` before formatting, and that merge is exactly the step
that discards which document each part came from.

## Decision

**The export surface takes the prepared entries alongside the graph.**
`FromGraphEntries(graph, entries, opts)` and `MarshalGraphEntriesJSON` are the
entry points; `FromDepGraph` and `MarshalDepGraphJSON` remain as the no-source
form. Both arguments are passed and neither is derived from the other: the
graph is the one already selected for output — consolidation renamed its
identities and the scope filter decided what stays — so rebuilding it from the
entries would export a different graph than the rest of the command reports.
The entries are there for the one thing only they carry.

**A conversion restates its source.** With exactly one source document, the
exported document adopts that document's identity rather than minting one, in
whichever identity slot the target format can hold it: an SPDX
`documentNamespace` takes any URI, a CycloneDX `serialNumber` takes only a
UUID URN, so a BOM-Link is parsed back to its serial and anything else is
linked instead. A caller-pinned identity always wins over both. The document
*name* is not adopted at the CLI, which names a document after the scanned
project.

> **Amended 2026-09-12 (issue #433):** only a conversion that *restates* its
> source adopts its identity. An export whose graph was scope-filtered,
> enriched, or degraded between ingest and export is a different document with
> the same one input, and behaves as a merge of one: its own identity and
> timestamp, the source linked. The caller declares this through
> `BuildOptions.RestatesSource`, which defaults to false; the CLI derives it
> from the same predicate that decides `compositions.aggregate`, so a document
> that cannot claim to be complete cannot claim to be its source either. The
> fixed point in Consequences holds for restating exports only. An SPDX link
> still requires the checksum captured at ingest, so a source written onto an
> entry by a plugin without one is neither adopted nor linked -- the merge
> behaviour that already existed, now stated.

**A merge links its sources.** With two or more, the document mints its own
identity and names each source through a reference of type `bom` carrying a
BOM-Link or the source's namespace URI. Creators and tools union in both
cases, which is the SDK's declared merge class for them.

**The claims are re-gated on export, not trusted from the entry.** A
`GraphEntry` is reachable by any detector or external plugin, so a value
written straight onto one never passed a decoder. Everything runs through
`DocumentAssertions.Normalized` on the way out as well as on the way in.

## Consequences

- `export → ingest → export` is a fixed point for both formats, asserted by
  `TestSingleSourceExportIsAFixedPoint`. It found a real defect on its first
  run: SPDX external references were emitted with the SDK's comparison-form
  category (`other`) instead of the specification's spelling (`OTHER`), so an
  ingested document changed case on its second export. `SPDXName()` is the
  authority now.
- The fixed point holds within a format, not across one. A CycloneDX document
  cannot hold a non-UUID identity, so an SPDX source converted to CycloneDX is
  linked rather than adopted, and the chain back is a different document.
- A merged SPDX document links nothing. SPDX names another document through
  `externalDocumentRefs`, and every entry requires a checksum over that
  document's bytes — computable only at ingest, and `DocumentAssertions` has
  nowhere to keep it. Filed as bomly-dev/bomly-sdk#55; the CycloneDX half
  ships now, and the SPDX projection belongs beside it when the carrier grows
  the field. Merged SPDX documents still preserve every component assertion.
- Consolidation carries `GraphEntry.Document` through, which it previously
  dropped when rebuilding entries. That was silent: nothing downstream read
  the field yet.
- `FuzzDocumentAssertions` covers the export projection with hostile claims
  and asserts idempotence, the property whose failure in the component half
  surfaced bomly-dev/bomly-sdk#54. The merged case is validated end to end by
  the SBOM interoperability workflow, through both official validators.

## Update (2026-09-06): both gaps this ADR left open are closed

Two consequences above were open questions with SDK issues attached. SDK
v0.9.5 closed both, and this repository consumes them.

**A merged SPDX document now links its sources.** The blocker was that
`DocumentAssertions` had nowhere to keep a checksum over a source document's
bytes, which SPDX requires on every `externalDocumentRefs` entry
(bomly-dev/bomly-sdk#55). The carrier grew a document version and a source
checksum, and ingest computes that checksum where the original bytes are --
in the codec entry point, once, for every format including one added later.
The SPDX projection now sits beside the CycloneDX one. A source that reached
a graph entry without passing through ingest has no checksum and is left
unnamed rather than written as an invalid reference.

**Those links are read back.** `DocumentAssertions.Sources`
(bomly-dev/bomly-sdk#61) gives the documents behind a document a home, so
both codecs read the links on ingest and re-emit them on export. A merged
export converted again still names its inputs. Each source contributes its
own link tuple and the tuples it recorded, which is the SDK's declared merge
class for the set -- inheritance, not a rule re-decided here. The CycloneDX
`bom` reference carries the checksum too, so converting a merged CycloneDX
document to SPDX can still name every source.
