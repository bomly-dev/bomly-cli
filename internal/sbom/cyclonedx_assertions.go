package sbom

import (
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
)

// This file carries a CycloneDX document's own component assertions in and
// out: supplier, originator, description, homepage, checksums, CPE, and the
// document's external references (ADR-0037, issue #396).
//
// Every value crosses the trust boundary in both directions, so every value
// clears an SDK gate at each crossing. An ingested document is untrusted
// input that Bomly re-emits under its own name.

// cycloneDXSupplier reads a component's supplier as a contact.
//
// CycloneDX models an organization, so the kind is organization; a value that
// does not survive Contact.Normalized -- a control character that would
// corrupt the SPDX projection, an embedded address -- is dropped rather than
// repaired.
func cycloneDXSupplier(entity *cdx.OrganizationalEntity) *sdk.Contact {
	if entity == nil {
		return nil
	}
	contact := sdk.Contact{
		Kind: sdk.ContactKindOrganization,
		Name: entity.Name,
	}
	if entity.URL != nil && len(*entity.URL) > 0 {
		contact.URL = (*entity.URL)[0]
	}
	normalized, ok := contact.Normalized()
	if !ok {
		return nil
	}
	return &normalized
}

// cycloneDXOriginator reads the party that authored the component.
//
// CycloneDX spells this three ways across versions: `publisher` (a string),
// the deprecated `author`, and `authors`. Publisher is preferred because it
// is the field 1.5 and 1.6 documents actually carry; the others are read only
// when it is absent, so an older document is not silently less preserved.
func cycloneDXOriginator(comp cdx.Component) *sdk.Contact {
	candidates := []struct {
		kind  sdk.ContactKind
		value string
	}{
		{sdk.ContactKindOrganization, comp.Publisher},
		{sdk.ContactKindPerson, comp.Author},
	}
	if comp.Authors != nil {
		for _, author := range *comp.Authors {
			candidates = append(candidates, struct {
				kind  sdk.ContactKind
				value string
			}{sdk.ContactKindPerson, author.Name})
		}
	}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.value) == "" {
			continue
		}
		contact := sdk.Contact{Kind: candidate.kind, Name: candidate.value}
		if normalized, ok := contact.Normalized(); ok {
			return &normalized
		}
	}
	return nil
}

// cycloneDXComponentDigests reads a component's own checksums.
func cycloneDXComponentDigests(hashes *[]cdx.Hash) []Digest {
	if hashes == nil {
		return nil
	}
	digests := make([]Digest, 0, len(*hashes))
	for _, hash := range *hashes {
		digests = append(digests, Digest{Algorithm: string(hash.Algorithm), Value: hash.Value})
	}
	return digests
}

// cycloneDXIngestedReferences reads the document's external references.
//
// CycloneDX has no category axis, so the category stays empty -- which is
// itself the assertion that this reference came from a format that has none,
// and is what lets the SPDX projection stay faithful rather than inventing
// one. The type is the document's own token, kept verbatim: both
// specifications keep adding types, and a reference this build does not
// recognize still round-trips.
func cycloneDXIngestedReferences(refs *[]cdx.ExternalReference) []sdk.ExternalReference {
	if refs == nil {
		return nil
	}
	converted := make([]sdk.ExternalReference, 0, len(*refs))
	for _, ref := range *refs {
		if isOriginDerivedReferenceType(string(ref.Type)) {
			continue
		}
		converted = append(converted, sdk.ExternalReference{
			Type:    string(ref.Type),
			Locator: ref.URL,
			Comment: ref.Comment,
			Hashes:  cycloneDXReferenceHashes(ref.Hashes),
		})
	}
	return sdk.MergeExternalReferences(nil, converted)
}

// isOriginDerivedReferenceType reports whether a reference type is one Bomly
// emits from a package origin.
//
// These are not ingested, and the reason is a laundering hazard rather than
// squeamishness. Origin is detector-asserted (ADR-0033): a detector says
// where it actually resolved a package, and that claim drives the
// dependency-confusion signal. Bomly renders each origin as a distribution or
// vcs reference on export. Nothing in the document distinguishes a reference
// Bomly derived from an origin from one a third party asserted, so ingesting
// them would let Bomly's own detector assertion return as a source assertion
// and be re-emitted as one on the next hop -- a detector claim promoted to a
// document claim across two conversions, with no detector behind it.
//
// The cost is real and stated rather than hidden: a third-party document's
// own vcs or distribution reference is not preserved. Every other category
// is. Recovering these needs a way to tell our emission from a source's,
// which the formats do not offer today; docs/SBOM.md records the limit.
//
// The same rule already applies to origins themselves --
// TestOriginIsNotReadBackFromAnIngestedDocument pins it -- and this keeps the
// two halves of one decision from drifting apart.
func isOriginDerivedReferenceType(referenceType string) bool {
	switch strings.ToLower(strings.TrimSpace(referenceType)) {
	case string(cdx.ERTypeDistribution), string(cdx.ERTypeVCS):
		return true
	default:
		return false
	}
}

// cycloneDXReferenceHashes reads a reference's own integrity claims, which
// CycloneDX carries natively and SPDX 2.3 has no slot for.
func cycloneDXReferenceHashes(hashes *[]cdx.Hash) []sdk.Digest {
	if hashes == nil {
		return nil
	}
	converted := make([]sdk.Digest, 0, len(*hashes))
	for _, hash := range *hashes {
		converted = append(converted, sdk.Digest{
			Algorithm: sdk.DigestAlgorithm(hash.Algorithm),
			Value:     hash.Value,
		})
	}
	return converted
}

// applyCycloneDXAssertions fills a component with what the document asserted
// about it, each value through its gate.
func applyCycloneDXAssertions(component *Component, comp cdx.Component) {
	if component == nil {
		return
	}
	component.Supplier = cycloneDXSupplier(comp.Supplier)
	component.Originator = cycloneDXOriginator(comp)
	component.Description = sdk.NormalizeDescription(comp.Description)
	component.ExternalReferences = cycloneDXIngestedReferences(comp.ExternalReferences)
	if digests := cycloneDXComponentDigests(comp.Hashes); len(digests) > 0 {
		component.Digests = digests
	}
	if cpe := strings.TrimSpace(comp.CPE); cpe != "" {
		component.CPEs = append(component.CPEs, cpe)
	}
}

// cycloneDXEntityFor renders a contact as a CycloneDX organizational entity.
func cycloneDXEntityFor(contact *sdk.Contact) *cdx.OrganizationalEntity {
	if contact == nil {
		return nil
	}
	normalized, ok := contact.Normalized()
	if !ok || strings.TrimSpace(normalized.Name) == "" {
		return nil
	}
	entity := &cdx.OrganizationalEntity{Name: normalized.Name}
	if url := strings.TrimSpace(normalized.URL); url != "" {
		urls := []string{url}
		entity.URL = &urls
	}
	return entity
}

// cycloneDXEmittedReferences renders the component's references, dropping any
// that no longer clears the gate.
//
// The gate runs again on the way out. The node these came from is not a
// trusted carrier -- a detector or an external plugin can write the field
// directly, and such a value never passed an ingest gate at all.
func cycloneDXEmittedReferences(refs []sdk.ExternalReference) []cdx.ExternalReference {
	if len(refs) == 0 {
		return nil
	}
	emitted := make([]cdx.ExternalReference, 0, len(refs))
	for _, ref := range refs {
		normalized, ok := ref.Normalized()
		if !ok {
			continue
		}
		emitted = append(emitted, cdx.ExternalReference{
			Type:    cdx.ExternalReferenceType(normalized.Type),
			URL:     normalized.Locator,
			Comment: normalized.Comment,
			Hashes:  cycloneDXEmittedHashes(normalized.Hashes),
		})
	}
	if len(emitted) == 0 {
		return nil
	}
	return emitted
}

// cycloneDXEmittedHashes renders a reference's integrity claims.
func cycloneDXEmittedHashes(digests []sdk.Digest) *[]cdx.Hash {
	if len(digests) == 0 {
		return nil
	}
	hashes := make([]cdx.Hash, 0, len(digests))
	for _, digest := range digests {
		normalized, ok := digest.Normalized()
		if !ok {
			continue
		}
		hashes = append(hashes, cdx.Hash{
			Algorithm: cdx.HashAlgorithm(normalized.Algorithm),
			Value:     normalized.Value,
		})
	}
	if len(hashes) == 0 {
		return nil
	}
	return &hashes
}

// cycloneDXDocumentAssertions reads what a CycloneDX document says about
// itself.
//
// The identity is a BOM-Link, built by cyclonedx-go from the serial and
// version rather than formatted here: the URN's shape is the library's to
// own, down to stripping the "urn:uuid:" prefix. A document without a serial
// has no identity to state, which is legal -- serialNumber is optional.
func cycloneDXDocumentAssertions(bom *cdx.BOM) sdk.DocumentAssertions {
	if bom == nil {
		return sdk.DocumentAssertions{}
	}
	var assertions sdk.DocumentAssertions
	version := bom.Version
	if version < 1 {
		// ADR-0037's default: a document that did not number itself is
		// version 1, which is also the only value NewBOMLink accepts below.
		version = 1
	}
	if link, err := cdx.NewBOMLink(bom.SerialNumber, version, nil); err == nil {
		assertions.Identity = link.String()
	}
	if bom.Metadata != nil {
		assertions.Created = bom.Metadata.Timestamp
		if bom.Metadata.Manufacturer != nil {
			assertions.Creators = appendEntityContact(assertions.Creators, *bom.Metadata.Manufacturer)
		}
		if bom.Metadata.Authors != nil {
			for _, author := range *bom.Metadata.Authors {
				assertions.Creators = appendContact(assertions.Creators, sdk.Contact{
					Kind: sdk.ContactKindPerson,
					Name: author.Name,
				})
			}
		}
		assertions.Tools = cycloneDXIngestedTools(bom.Metadata.Tools)
	}
	normalized, ok := assertions.Normalized()
	if !ok {
		return sdk.DocumentAssertions{}
	}
	return normalized
}

// cycloneDXIngestedTools reads both shapes of the tools field: the component
// list CycloneDX 1.5 introduced and the deprecated flat list before it.
func cycloneDXIngestedTools(tools *cdx.ToolsChoice) []sdk.DocumentTool {
	if tools == nil {
		return nil
	}
	var ingested []sdk.DocumentTool
	if tools.Components != nil {
		for _, tool := range *tools.Components {
			vendor := ""
			if tool.Manufacturer != nil {
				vendor = tool.Manufacturer.Name
			}
			ingested = append(ingested, sdk.DocumentTool{Vendor: vendor, Name: tool.Name, Version: tool.Version})
		}
	}
	if tools.Tools != nil {
		for _, tool := range *tools.Tools {
			ingested = append(ingested, sdk.DocumentTool{Vendor: tool.Vendor, Name: tool.Name, Version: tool.Version})
		}
	}
	return ingested
}

func appendEntityContact(contacts []sdk.Contact, entity cdx.OrganizationalEntity) []sdk.Contact {
	contact := sdk.Contact{Kind: sdk.ContactKindOrganization, Name: entity.Name}
	if entity.URL != nil && len(*entity.URL) > 0 {
		contact.URL = (*entity.URL)[0]
	}
	return appendContact(contacts, contact)
}

// appendContact keeps only what the SDK's contact gate passes. A name that
// arrived with an email address loses the address there, not here.
func appendContact(contacts []sdk.Contact, contact sdk.Contact) []sdk.Contact {
	normalized, ok := contact.Normalized()
	if !ok {
		return contacts
	}
	return append(contacts, normalized)
}

// cycloneDXDocumentCreators renders the document's credited parties: the
// organizations become the manufacturer, the people become authors.
func cycloneDXDocumentAuthors(doc *Document) []cdx.OrganizationalContact {
	var authors []cdx.OrganizationalContact
	if doc.Provenance.Manufacturer != "" {
		author := cdx.OrganizationalContact{Name: doc.Provenance.Manufacturer}
		if email := bareEmail(doc.Provenance.SecurityContact); email != "" {
			author.Email = email
		}
		authors = append(authors, author)
	}
	for _, creator := range doc.Assertions.Creators {
		if creator.Kind != sdk.ContactKindPerson {
			continue
		}
		authors = append(authors, cdx.OrganizationalContact{Name: creator.Name})
	}
	return authors
}

// cycloneDXSourceTools folds the tools the source documents credited in with
// Bomly's own, deduplicated on the triple the SDK keys them by.
func cycloneDXSourceTools(doc *Document, tools *cdx.ToolsChoice) *cdx.ToolsChoice {
	if len(doc.Assertions.Tools) == 0 {
		return tools
	}
	components := make([]cdx.Component, 0, len(doc.Assertions.Tools))
	if tools != nil && tools.Components != nil {
		components = append(components, *tools.Components...)
	}
	seen := make(map[string]struct{}, len(components))
	for _, component := range components {
		seen[component.Name+"\x00"+component.Version] = struct{}{}
	}
	for _, tool := range doc.Assertions.Tools {
		key := tool.Name + "\x00" + tool.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		component := cdx.Component{Type: cdx.ComponentTypeApplication, Name: tool.Name, Version: tool.Version}
		if tool.Vendor != "" {
			component.Manufacturer = &cdx.OrganizationalEntity{Name: tool.Vendor}
		}
		components = append(components, component)
	}
	if len(components) == 0 {
		return tools
	}
	return &cdx.ToolsChoice{Components: &components}
}

// cycloneDXSourceLinks renders the links naming the documents this one was
// built from, as external references of type "bom" on the document itself.
func cycloneDXSourceLinks(doc *Document) []cdx.ExternalReference {
	links := documentSourceLinks(doc)
	if len(links) == 0 {
		return nil
	}
	refs := make([]cdx.ExternalReference, 0, len(links))
	for _, link := range links {
		refs = append(refs, cdx.ExternalReference{
			Type: cdx.ExternalReferenceType(link.Type),
			URL:  link.Locator,
		})
	}
	return refs
}
