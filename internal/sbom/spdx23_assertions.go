package sbom

import (
	"strings"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// This file carries an SPDX document's own component assertions in and out:
// supplier, originator, description, homepage, checksums and the document's
// external references (ADR-0037, issue #396).
//
// SPDX writes a contact as one line -- "Organization: Acme" -- so the parse
// and the render are the SDK's ParseSPDXContact and Contact.SPDXString. The
// grammar has an optional "(<email>)" suffix that must not be retained, which
// is the kind of rule that gets forgotten when it is rewritten per call site.

// SPDX names a creator by its type. tools-golang splits the line into type
// and value but declares no constants for the three spellings the
// specification allows, so they are named here once rather than repeated as
// literals at every site that reads or writes one.
const (
	spdxToolCreatorType         = "Tool"
	spdxOrganizationCreatorType = "Organization"
)

// spdxIngestedSupplier reads a package's supplier.
func spdxIngestedSupplier(supplier *common.Supplier) *sdk.Contact {
	if supplier == nil {
		return nil
	}
	return spdxContactFrom(supplier.SupplierType, supplier.Supplier)
}

// spdxIngestedOriginator reads the party that authored the package.
func spdxIngestedOriginator(originator *common.Originator) *sdk.Contact {
	if originator == nil {
		return nil
	}
	return spdxContactFrom(originator.OriginatorType, originator.Originator)
}

// spdxContactFrom rebuilds SPDX's single-line contact form and parses it
// through the SDK.
//
// tools-golang splits the line into a type and a value, so the line is
// reassembled rather than mapped field by field: the SDK owns what the form
// means, including the address suffix it strips, and a second reading of the
// same grammar here would be a second place to get it wrong.
func spdxContactFrom(contactType, value string) *sdk.Contact {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	line := value
	if contactType = strings.TrimSpace(contactType); contactType != "" {
		line = contactType + ": " + value
	}
	contact, ok := sdk.ParseSPDXContact(line)
	if !ok {
		return nil
	}
	normalized, ok := contact.Normalized()
	if !ok {
		return nil
	}
	return &normalized
}

// spdxIngestedChecksums reads a package's own checksums.
func spdxIngestedChecksums(checksums []common.Checksum) []Digest {
	if len(checksums) == 0 {
		return nil
	}
	digests := make([]Digest, 0, len(checksums))
	for _, checksum := range checksums {
		digests = append(digests, Digest{
			Algorithm: string(checksum.Algorithm),
			Value:     checksum.Value,
		})
	}
	return digests
}

// spdxIngestedReferences reads the document's external references, keeping
// the category SPDX stated alongside the type.
//
// The triple (category, type, locator) is the reference's identity, and the
// category is an SPDX-only axis with no CycloneDX source value -- so keeping
// it is what lets an SPDX reference round-trip without being re-derived from
// the type alone.
//
// Bomly's own emissions are skipped. The PURL and CPE references it writes
// are projections of the component's identity and enrichment, and reading
// them back as source assertions would duplicate them on the next export;
// the origin-derived ones are excluded for the laundering reason recorded on
// isOriginDerivedReferenceType.
func spdxIngestedReferences(refs []*v23.PackageExternalReference) []sdk.ExternalReference {
	if len(refs) == 0 {
		return nil
	}
	converted := make([]sdk.ExternalReference, 0, len(refs))
	for _, ref := range refs {
		if ref == nil || isBomlyProjectedReference(ref) {
			continue
		}
		category, err := sdk.ParseExternalReferenceCategory(ref.Category)
		if err != nil {
			continue
		}
		converted = append(converted, sdk.ExternalReference{
			Category: category,
			Type:     ref.RefType,
			Locator:  ref.Locator,
			Comment:  ref.ExternalRefComment,
		})
	}
	return sdk.MergeExternalReferences(nil, converted)
}

// spdxIngestedCPEs reads the CPEs a document stated.
//
// SPDX 2.3 has no CPE field: a CPE is carried as a SECURITY external
// reference, so the reference list is the only place one can be. They are
// read into Component.CPEs rather than kept among the external references,
// because that is the field they mean and the exporter writes them back from
// there -- keeping them in both would emit each CPE twice on the next hop.
//
// The locator is not re-validated here. It arrives from the same list
// spdxIngestedReferences reads, and ingestedCPEs re-clears the CPE grammar
// through the SDK gate before any of this reaches a node.
func spdxIngestedCPEs(refs []*v23.PackageExternalReference) []string {
	if len(refs) == 0 {
		return nil
	}
	cpes := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(ref.RefType)) {
		case strings.ToLower(common.TypeSecurityCPE23Type), strings.ToLower(common.TypeSecurityCPE22Type):
		default:
			continue
		}
		locator := strings.TrimSpace(ref.Locator)
		if locator == "" {
			continue
		}
		if _, duplicate := seen[locator]; duplicate {
			continue
		}
		seen[locator] = struct{}{}
		cpes = append(cpes, locator)
	}
	if len(cpes) == 0 {
		return nil
	}
	return cpes
}

// isBomlyProjectedReference reports whether a reference is one Bomly derives
// from the component itself rather than one a source asserted.
//
// The purl and cpe references are projections of identity and enrichment: the
// exporter writes them from Component.PURL and Component.CPEs on every run,
// so ingesting them as assertions would produce a second copy on re-export
// and make the round trip grow. The Bomly-defined origin reference type is
// excluded for the separate laundering reason.
func isBomlyProjectedReference(ref *v23.PackageExternalReference) bool {
	switch strings.ToLower(strings.TrimSpace(ref.RefType)) {
	case strings.ToLower(common.TypePackageManagerPURL),
		strings.ToLower(common.TypeSecurityCPE23Type),
		strings.ToLower(common.TypeSecurityCPE22Type),
		spdxOriginRefType:
		return true
	default:
		return false
	}
}

// applySPDXAssertions fills a component with what the document asserted about
// it, each value through its gate.
func applySPDXAssertions(component *Component, pkg *v23.Package) {
	if component == nil || pkg == nil {
		return
	}
	component.Supplier = spdxIngestedSupplier(pkg.PackageSupplier)
	component.Originator = spdxIngestedOriginator(pkg.PackageOriginator)
	// SPDX has both; description is the fuller field, so summary fills in
	// only when it is absent rather than overwriting it.
	description := pkg.PackageDescription
	if strings.TrimSpace(description) == "" {
		description = pkg.PackageSummary
	}
	component.Description = sdk.NormalizeDescription(description)
	component.Homepage = sdk.NormalizeHomepage(pkg.PackageHomePage)
	component.ExternalReferences = spdxIngestedReferences(pkg.PackageExternalReferences)
	if cpes := spdxIngestedCPEs(pkg.PackageExternalReferences); len(cpes) > 0 {
		component.CPEs = cpes
	}
	if digests := spdxIngestedChecksums(pkg.PackageChecksums); len(digests) > 0 {
		component.Digests = digests
	}
}

// spdxSupplierFor renders a contact into SPDX's supplier form.
func spdxSupplierFor(contact *sdk.Contact) *common.Supplier {
	if contact == nil {
		return nil
	}
	kind, name, ok := spdxContactParts(*contact)
	if !ok {
		return nil
	}
	return &common.Supplier{SupplierType: kind, Supplier: name}
}

// spdxOriginatorFor renders a contact into SPDX's originator form.
func spdxOriginatorFor(contact *sdk.Contact) *common.Originator {
	if contact == nil {
		return nil
	}
	kind, name, ok := spdxContactParts(*contact)
	if !ok {
		return nil
	}
	return &common.Originator{OriginatorType: kind, Originator: name}
}

// spdxContactParts splits the SDK's rendered contact line back into the two
// fields tools-golang holds it in.
//
// The line is produced by Contact.SPDXString rather than assembled here, so
// the gate runs and the rendering stays the SDK's; this only re-splits what
// it produced. A contact with nothing publishable renders empty and is
// omitted rather than written as a malformed line.
func spdxContactParts(contact sdk.Contact) (kind, name string, ok bool) {
	line := contact.SPDXString()
	if line == "" {
		return "", "", false
	}
	prefix, value, found := strings.Cut(line, ": ")
	if !found {
		// NOASSERTION carries no type half.
		return "", line, true
	}
	return prefix, value, true
}

// spdxEmittedReferences renders the component's own asserted references,
// re-clearing the gate on the way out.
func spdxEmittedReferences(refs []sdk.ExternalReference) []*v23.PackageExternalReference {
	if len(refs) == 0 {
		return nil
	}
	emitted := make([]*v23.PackageExternalReference, 0, len(refs))
	for _, ref := range refs {
		normalized, ok := ref.Normalized()
		if !ok {
			continue
		}
		// SPDXName, not the category's own string: the SDK holds the
		// category in its comparison form ("package-manager") and renders
		// SPDX's spelling ("PACKAGE-MANAGER") separately. Emitting the
		// comparison form wrote a category the specification does not define,
		// and only showed up as an ingested document changing case on its
		// second export -- which the fixed-point test is there to catch.
		category := normalized.Category.SPDXName()
		if category == "" {
			// A CycloneDX-sourced reference has no category axis. SPDX
			// requires one, and OTHER is the category the specification
			// provides for a reference outside its defined vocabularies.
			category = common.CategoryOther
		}
		emitted = append(emitted, &v23.PackageExternalReference{
			Category:           category,
			RefType:            normalized.Type,
			Locator:            normalized.Locator,
			ExternalRefComment: normalized.Comment,
		})
	}
	if len(emitted) == 0 {
		return nil
	}
	return emitted
}

// spdxDocumentAssertions reads what an SPDX document says about itself.
//
// tools-golang has already split each creator line into its type and value,
// so the "Person: name (email)" grammar is never re-parsed here -- the type
// selects the slot, and the value goes through the SDK's own contact gate.
func spdxDocumentAssertions(doc *v23.Document) sdk.DocumentAssertions {
	if doc == nil {
		return sdk.DocumentAssertions{}
	}
	assertions := sdk.DocumentAssertions{
		Identity:    doc.DocumentNamespace,
		Name:        doc.DocumentName,
		DataLicense: doc.DataLicense,
		Comment:     doc.DocumentComment,
	}
	if doc.CreationInfo != nil {
		assertions.Created = doc.CreationInfo.Created
		for _, creator := range doc.CreationInfo.Creators {
			if strings.EqualFold(strings.TrimSpace(creator.CreatorType), spdxToolCreatorType) {
				// Kept whole: see documentSourceTools for why the
				// "name-version" convention is not split apart.
				assertions.Tools = append(assertions.Tools, sdk.DocumentTool{Name: creator.Creator})
				continue
			}
			if contact := spdxContactFrom(creator.CreatorType, creator.Creator); contact != nil {
				assertions.Creators = append(assertions.Creators, *contact)
			}
		}
	}
	normalized, ok := assertions.Normalized()
	if !ok {
		return sdk.DocumentAssertions{}
	}
	return normalized
}

// spdxDocumentCreators renders the creator lines for a document, folding the
// parties and tools the source documents credited in with Bomly's own.
//
// Deduplicated on the rendered line, because that is what the format carries:
// a tool the source credited as "bomly-cli-0.19.0" and Bomly crediting itself
// under the same version are one creator, not two.
func spdxDocumentCreators(doc *Document) []common.Creator {
	creators := make([]common.Creator, 0, len(doc.ToolNamesOrDefault())+1)
	seen := make(map[string]struct{})
	add := func(creatorType, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		line := creatorType + ": " + value
		if _, dup := seen[line]; dup {
			return
		}
		seen[line] = struct{}{}
		creators = append(creators, common.Creator{CreatorType: creatorType, Creator: value})
	}

	for _, tool := range doc.ToolNamesOrDefault() {
		// SPDX creator convention appends the tool version as "name-version".
		if tool == doc.ToolOrDefault() && doc.ToolVersion != "" {
			tool += "-" + doc.ToolVersion
		}
		add(spdxToolCreatorType, tool)
	}
	for _, tool := range doc.Assertions.Tools {
		add(spdxToolCreatorType, tool.Name)
	}
	if doc.Provenance.Manufacturer != "" {
		add(spdxOrganizationCreatorType, doc.Provenance.Manufacturer)
	}
	for _, creator := range doc.Assertions.Creators {
		// Rendered by the SDK so the line matches the one it would parse
		// back, rather than being assembled from the parts a second time.
		line := creator.SPDXString()
		creatorType, value, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		add(creatorType, value)
	}
	return creators
}
