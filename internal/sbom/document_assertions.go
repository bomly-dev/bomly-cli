package sbom

import (
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

// applySourceAssertions folds the source documents' own claims into the
// document being built, and records the sources for link emission.
func applySourceAssertions(doc *Document, sources []sdk.DocumentAssertions) {
	if doc == nil {
		return
	}
	cleaned := make([]sdk.DocumentAssertions, 0, len(sources))
	for _, source := range sources {
		// Re-gated here rather than trusted from the entry: these arrived
		// from an untrusted document, crossed the plugin boundary as part of
		// a detection result, and are about to be written into an SBOM. That
		// is exactly the re-clearing rule ADR-0037 states.
		normalized, ok := source.Normalized()
		if !ok {
			continue
		}
		cleaned = append(cleaned, normalized)
	}
	if len(cleaned) == 0 {
		return
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
	doc.SerialNumber = link.SerialNumber()
}

// documentSourceLinks returns the references that name each source document
// this one was built from, for the sources whose identity this document did
// not adopt as its own.
//
// A source whose identity became this document's identity is not linked: the
// document would be pointing at itself.
//
// Only CycloneDX renders these today. SPDX links documents through
// externalDocumentRefs, whose every entry requires a checksum over the source
// document's bytes -- and DocumentAssertions has nowhere to carry one, so a
// merged SPDX export names no sources. Tracked as bomly-dev/bomly-sdk#55;
// when that field ships, an SPDX projection belongs here beside this one.
func documentSourceLinks(doc *Document) []sdk.ExternalReference {
	if doc == nil || len(doc.Sources) == 0 {
		return nil
	}
	links := make([]sdk.ExternalReference, 0, len(doc.Sources))
	for _, source := range doc.Sources {
		if source.Identity == "" || source.Identity == doc.Namespace {
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
