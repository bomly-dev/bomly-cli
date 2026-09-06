package sbom

import (
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
)

// This file decides what an export says about itself when the graph it
// describes was read from other documents (ADR-0037, issue #396).
//
// The rule turns on how many documents were ingested, because both formats
// give a document exactly one identity:
//
//   - none: a native scan. Bomly asserts everything itself; nothing here
//     applies.
//   - one: a conversion. The document restates that source's assertions,
//     identity included, so `export -> ingest -> export` reproduces its own
//     bytes -- the fixed point #396 asks for.
//   - many: a merge. The document is a new one and says so: it keeps its own
//     identity and *links* each source instead of adopting one of them.
//
// Creators and tools union in every case, which is the SDK's declared merge
// class for them: two documents having produced this one is the normal case
// and both deserve credit.

// DocumentAssertionsFor returns the record of what a source document asserted
// about itself, for attaching to the graph entry that document became.
//
// It is never nil for a document that was read, even one that asserted
// nothing. The presence of the record is itself a fact -- that this entry came
// from an SBOM -- and a merged export needs it: CycloneDX permits a document
// with neither a serial number nor metadata, and treating that as "no source"
// made a merge of two documents look like a conversion of one, publishing the
// merged inventory under the other document's identity.
//
// Exported so the detector and this package agree by construction rather than
// by both remembering the same rule.
func DocumentAssertionsFor(doc *Document) *sdk.DocumentAssertions {
	if doc == nil {
		return nil
	}
	assertions := doc.Assertions
	return &assertions
}

// applySourceAssertions folds the source documents' own claims into the
// document being built, and records the sources for link emission.
func applySourceAssertions(doc *Document, sources []sdk.DocumentAssertions) {
	if doc == nil {
		return
	}
	if len(sources) == 0 {
		return
	}
	cleaned := make([]sdk.DocumentAssertions, 0, len(sources))
	for _, source := range sources {
		// Re-gated here rather than trusted from the entry: these arrived
		// from an untrusted document, crossed the plugin boundary as part of
		// a detection result, and are about to be written into an SBOM. That
		// is exactly the re-clearing rule ADR-0037 states.
		//
		// A source that normalizes to nothing is kept as a placeholder rather
		// than dropped. Whether this export is a conversion or a merge is a
		// question about how many documents were read, not about how many of
		// them had something publishable to say: CycloneDX permits a document
		// with neither a serial number nor metadata, and dropping it here made
		// a two-document merge look like a one-document conversion and adopt
		// the other source's identity.
		normalized, _ := source.Normalized()
		cleaned = append(cleaned, normalized)
	}
	doc.Sources = cleaned

	aggregate := cleaned[0]
	for _, source := range cleaned[1:] {
		aggregate = sdk.MergeDocumentAssertions(aggregate, source)
	}
	doc.Assertions.Creators = aggregate.Creators
	doc.Assertions.Tools = aggregate.Tools

	if len(cleaned) > 1 {
		// A merged document asserts its own identity. Its sources are named
		// by documentSourceLinks, not adopted here.
		return
	}

	only := cleaned[0]
	doc.Assertions.Comment = only.Comment
	if doc.Name == "" {
		doc.Name = only.Name
	}
	// The source's own timestamp, not this run's clock. A conversion adopts
	// the source's identity, and a document claiming to be that document while
	// stating a different creation time is two claims that disagree. It is
	// also what makes the fixed point hold without a caller pinning the
	// timestamp: re-exporting twice used to differ by wall clock alone.
	//
	// Parsed rather than copied because the model holds a time; the SDK keeps
	// the source spelling verbatim, and the first hop settles on the encoders'
	// rendering of it.
	if doc.Created.IsZero() {
		if created, err := time.Parse(time.RFC3339, only.Created); err == nil {
			doc.Created = created.UTC()
		}
	}
	// The data license is deliberately not inherited: SPDX 2.3 fixes it at
	// CC0-1.0 for the document itself, so re-asserting a source's value would
	// write an invalid document. It stays preserved in the model.
	inheritDocumentIdentity(doc, only.Identity)
}

// inheritDocumentIdentity adopts a single source's identity as this
// document's own, in whichever of the two formats' identity slots can hold
// it.
//
// A CycloneDX serial number is a UUID URN and nothing else, so an identity
// that is not a BOM-Link cannot become one; the SPDX namespace is any URI and
// takes either form. An identity that cannot be adopted is not lost -- it is
// linked instead, by documentSourceLinks.
func inheritDocumentIdentity(doc *Document, identity string) {
	if identity == "" {
		return
	}
	if doc.Namespace == "" {
		doc.Namespace = identity
	}
	if doc.SerialNumber != "" {
		return
	}
	// Parsed by the library that owns the grammar, so the serial comes back
	// in the urn:uuid form CycloneDX wants without this package taking a
	// position on how a BOM-Link is spelled.
	link, err := cdx.ParseBOMLink(identity)
	if err != nil {
		return
	}
	// The revision travels with the serial. Keeping only the serial made the
	// export claim to be revision 1 of a document whose revision 2 it read.
	doc.SerialNumber = link.SerialNumber()
	doc.SerialVersion = link.Version()
}

// documentIdentity is the identity a format actually writes into the document
// it is producing.
//
// Which slot is filled depends on the format: SPDX writes a namespace URI,
// CycloneDX a serial number, and neither writes the other. That distinction is
// the whole reason this type exists -- a source is only redundant with an
// identity the reader will actually see.
type documentIdentity struct {
	Namespace string
	Serial    string
	// SerialVersion is the revision written beside Serial. A link naming a
	// different revision of the same serial names a different document, so it
	// is still a link and not a self-reference.
	SerialVersion int
}

// names reports whether an identity refers to this same document.
//
// One document has two spellings across the formats: an SPDX namespace, and a
// BOM-Link over a CycloneDX serial. Parsed by the library that owns the link
// grammar, and compared on the serial rather than the rendered link, because a
// source that numbered itself version 2 spells the same document differently
// than the version this export would write.
func (d documentIdentity) names(identity string) bool {
	if identity == "" {
		return false
	}
	if d.Namespace != "" && identity == d.Namespace {
		return true
	}
	if d.Serial != "" {
		if link, err := cdx.ParseBOMLink(identity); err == nil &&
			link.SerialNumber() == d.Serial && link.Version() == d.SerialVersion {
			return true
		}
	}
	return false
}

// documentSourceLinks returns the references that name each source document
// this one was built from, for the sources whose identity this document did
// not adopt as the identity it is about to write.
//
// The comparison is against what the format emits, not against the model's
// namespace field. Converting an SPDX source to CycloneDX adopts the source
// namespace into the model and then writes a freshly minted serial, because
// CycloneDX has no namespace slot -- so comparing against the namespace
// suppressed the link for a document that had not in fact adopted anything,
// and the export named its source neither way.
//
// Only CycloneDX renders these today. SPDX links documents through
// externalDocumentRefs, whose every entry requires a checksum over the source
// document's bytes -- and DocumentAssertions has nowhere to carry one, so a
// merged SPDX export names no sources. Tracked as bomly-dev/bomly-sdk#55;
// when that field ships, an SPDX projection belongs here beside this one.
//
// These links are also write-only for now: DocumentAssertions records what a
// document says about itself, with no field for the documents behind it, so
// ingesting a merged export cannot restore them and a second export names no
// sources. Tracked as bomly-dev/bomly-sdk#61. Carrying them through Metadata
// instead is exactly what ADR-0037 closed off, so the gap is documented rather
// than worked around.
func documentSourceLinks(doc *Document, emitted documentIdentity) []sdk.ExternalReference {
	if doc == nil || len(doc.Sources) == 0 {
		return nil
	}
	links := make([]sdk.ExternalReference, 0, len(doc.Sources))
	for _, source := range doc.Sources {
		if emitted.names(source.Identity) || source.Identity == "" {
			continue
		}
		// Category stays unknown: this is CycloneDX's axis, and SPDX's
		// referenceCategory has no member that means "another document" --
		// SPDX links documents through externalDocumentRefs instead.
		ref, ok := sdk.ExternalReference{
			Type:    string(cdx.ERTypeBOM),
			Locator: source.Identity,
		}.Normalized()
		if !ok {
			continue
		}
		links = append(links, ref)
	}
	if len(links) == 0 {
		return nil
	}
	return sdk.MergeExternalReferences(nil, links)
}
