package sbom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/spdxkit"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type spdx23Codec struct{}

func (spdx23Codec) encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error) {
	idByComponent := make(map[string]common.ElementID, len(doc.Components))
	usedIDs := make(map[string]int, len(doc.Components))
	packages := make([]*v23.Package, 0, len(doc.Components))

	// Document roots are the packages SPDX DESCRIBES, i.e. the primary
	// component in either form: the synthesized project root, or the graph's
	// own single root when no pseudo root was needed. Provenance attaches to
	// both so the SPDX export matches CycloneDX metadata.component.
	rootComponents := make(map[string]struct{}, len(doc.Roots))
	for _, root := range doc.Roots {
		rootComponents[root] = struct{}{}
	}

	// Collected while packages render, emitted once as the document's
	// hasExtractedLicensingInfos: a reference is written per package but the
	// text it names lives at document scope.
	var extractedLicenses []spdxkit.ExtractedText

	for _, c := range doc.Components {
		base := sanitizeSPDXID(c.ID)
		seq := usedIDs[base]
		usedIDs[base] = seq + 1
		if seq > 0 {
			base = fmt.Sprintf("%s-%d", base, seq)
		}
		spdxID := common.ElementID(base)
		idByComponent[c.ID] = spdxID

		licenseDeclared, componentExtracted := spdxLicenseValue(c.Licenses)
		extractedLicenses = append(extractedLicenses, componentExtracted...)

		pkg := &v23.Package{
			PackageName:             c.NameOrID(),
			PackageSPDXIdentifier:   spdxID,
			PackageVersion:          c.Version,
			PackageDownloadLocation: spdxDownloadLocation(c),
			FilesAnalyzed:           false,
			PackageComment:          spdxPackageComment(c),
			PackageLicenseDeclared:  licenseDeclared,

			// Concluded is the document creator's own determination. Every
			// license Bomly carries is declared by a lockfile or a registry --
			// the domain model has no other kind -- and Bomly does not analyze
			// package contents, so it has nothing of its own to conclude.
			// SPDX names that case: NOASSERTION when the creator made no
			// attempt to determine the field. Nothing is lost; the declared
			// value above still carries what a source asserted.
			PackageLicenseConcluded:   "NOASSERTION",
			PackageCopyrightText:      spdxCopyrightValue(c.Copyright),
			PackageChecksums:          spdxChecksums(c.Digests),
			PackageSourceInfo:         spdxSourceInfo(c),
			PackageExternalReferences: append(spdxExternalReferences(c), spdxEmittedReferences(c.ExternalReferences)...),
			PackageSupplier:           spdxSupplierFor(c.Supplier),
			PackageOriginator:         spdxOriginatorFor(c.Originator),
			PackageDescription:        sdk.NormalizeDescription(c.Description),
			PackageHomePage:           sdk.NormalizeHomepage(c.Homepage),
			PrimaryPackagePurpose:     spdxPrimaryPackagePurpose(c.Type),
		}
		if _, isRoot := rootComponents[c.ID]; isRoot || IsProjectRootComponent(c) {
			if doc.Provenance.Manufacturer != "" {
				pkg.PackageSupplier = &common.Supplier{SupplierType: spdxOrganizationCreatorType, Supplier: doc.Provenance.Manufacturer}
			}
		}
		packages = append(packages, pkg)
	}

	relationships := make([]*v23.Relationship, 0, allocHint(len(doc.Dependencies), len(doc.Roots)))
	documentRef := common.DocElementID{ElementRefID: common.ElementID("DOCUMENT")}
	for _, root := range doc.Roots {
		rootID, ok := idByComponent[root]
		if !ok {
			continue
		}
		relationships = append(relationships, &v23.Relationship{
			RefA:         documentRef,
			RefB:         common.DocElementID{ElementRefID: rootID},
			Relationship: common.TypeRelationshipDescribe,
		})
	}

	for _, dep := range doc.Dependencies {
		fromID, ok := idByComponent[dep.Ref]
		if !ok {
			continue
		}
		for _, to := range dep.DependsOn {
			toID, ok := idByComponent[to]
			if !ok {
				continue
			}
			relationships = append(relationships, &v23.Relationship{
				RefA:         common.DocElementID{ElementRefID: fromID},
				RefB:         common.DocElementID{ElementRefID: toID},
				Relationship: common.TypeRelationshipDependsOn,
			})
		}
	}

	creation := &v23.CreationInfo{
		Creators:       spdxDocumentCreators(doc),
		Created:        doc.CreatedOrNow().Format("2006-01-02T15:04:05Z"),
		CreatorComment: spdxCreatorComment(doc.Provenance),
	}

	spdxDoc := &v23.Document{
		SPDXVersion:       v23.Version,
		DataLicense:       v23.DataLicense,
		SPDXIdentifier:    common.ElementID("DOCUMENT"),
		DocumentName:      doc.NameOrDefault(),
		DocumentNamespace: doc.NamespaceOrDefault(),
		CreationInfo:      creation,
		DocumentComment:   doc.Assertions.Comment,
		Packages:          packages,
		Relationships:     relationships,
		OtherLicenses:     spdxOtherLicenses(extractedLicenses),
	}

	return marshalJSON(spdxDoc, opts.Pretty)
}

func (spdx23Codec) decodeJSON(data []byte) (*Document, error) {
	var spdxDoc v23.Document
	if err := json.Unmarshal(data, &spdxDoc); err != nil {
		return nil, err
	}

	extractedByRef := spdxExtractedTexts(spdxDoc.OtherLicenses)

	components := make([]Component, 0, len(spdxDoc.Packages))
	for _, p := range spdxDoc.Packages {
		if p == nil {
			continue
		}
		id := common.RenderElementID(p.PackageSPDXIdentifier)
		component := Component{
			ID:             id,
			Name:           p.PackageName,
			Version:        p.PackageVersion,
			Scope:          parseSPDXCommentField(p.PackageComment, "scope"),
			Type:           parseSPDXComponentType(p),
			PURL:           parseSPDXPURL(p.PackageExternalReferences),
			Ecosystem:      parseSPDXYcosystem(p.PackageExternalReferences),
			PackageManager: parseSPDXPackageManager(p.PackageExternalReferences),
			Copyright:      parseSPDXCopyright(p.PackageCopyrightText),
			Licenses:       parseSPDXLicenses(extractedByRef, p.PackageLicenseConcluded, p.PackageLicenseDeclared),
		}
		applySPDXAssertions(&component, p)
		components = append(components, component)
	}

	depsByRef := make(map[string][]string, len(components))
	for _, c := range components {
		depsByRef[c.ID] = nil
	}

	roots := make([]string, 0)
	for _, rel := range spdxDoc.Relationships {
		if rel == nil {
			continue
		}
		a := common.RenderDocElementID(rel.RefA)
		b := common.RenderDocElementID(rel.RefB)

		switch rel.Relationship {
		case common.TypeRelationshipDescribe:
			if a == "SPDXRef-DOCUMENT" {
				roots = append(roots, b)
			}
		case common.TypeRelationshipDependsOn:
			depsByRef[a] = append(depsByRef[a], b)
		case common.TypeRelationshipDependencyOf,
			common.TypeRelationshipBuildDependencyOf,
			common.TypeRelationshipDevDependencyOf,
			common.TypeRelationshipOptionalDependencyOf,
			common.TypeRelationshipProvidedDependencyOf,
			common.TypeRelationshipRuntimeDependencyOf,
			common.TypeRelationshipTestDependencyOf:
			depsByRef[b] = append(depsByRef[b], a)
		}
	}

	dependencies := make([]Dependency, 0, len(components))
	for _, c := range components {
		deps := depsByRef[c.ID]
		if len(deps) > 1 {
			sort.Strings(deps)
		}
		dependencies = append(dependencies, Dependency{
			Ref:       c.ID,
			DependsOn: deps,
		})
	}

	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })
	sort.Strings(roots)

	return &Document{
		Name:         spdxDoc.DocumentName,
		Namespace:    spdxDoc.DocumentNamespace,
		Assertions:   spdxDocumentAssertions(&spdxDoc),
		Tool:         extractSPDXToolName(spdxDoc.CreationInfo),
		Tools:        extractSPDXToolNames(spdxDoc.CreationInfo),
		Created:      parseSPDXCreated(spdxDoc.CreationInfo),
		Components:   components,
		Dependencies: dependencies,
		Roots:        roots,
	}, nil
}

func sanitizeSPDXID(raw string) string {
	if raw == "" {
		return "pkg"
	}
	var b strings.Builder
	b.Grow(len(raw))
	lastDash := false
	for _, r := range raw {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "pkg"
	}
	return out
}

func extractSPDXToolName(ci *v23.CreationInfo) string {
	tools := extractSPDXToolNames(ci)
	if len(tools) > 0 {
		return tools[0]
	}
	return ""
}

func extractSPDXToolNames(ci *v23.CreationInfo) []string {
	if ci == nil {
		return nil
	}
	tools := make([]string, 0, len(ci.Creators))
	for _, c := range ci.Creators {
		if c.CreatorType == spdxToolCreatorType {
			tools = append(tools, c.Creator)
		}
	}
	return tools
}

func parseSPDXCreated(ci *v23.CreationInfo) time.Time {
	if ci == nil || ci.Created == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, ci.Created)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// spdxPrimaryPackagePurpose maps Bomly's component type onto the SPDX 2.3
// PrimaryPackagePurpose vocabulary. Ordinary registry packages default to
// LIBRARY; unmapped domain types (for example workflows) return OTHER.
func spdxPrimaryPackagePurpose(componentType string) string {
	switch strings.ToLower(strings.TrimSpace(componentType)) {
	case "", "package", "library":
		return "LIBRARY"
	case "application":
		return "APPLICATION"
	case "framework":
		return "FRAMEWORK"
	case "container":
		return "CONTAINER"
	case "operating-system":
		return "OPERATING-SYSTEM"
	case "device":
		return "DEVICE"
	case "firmware":
		return "FIRMWARE"
	case "file":
		return "FILE"
	default:
		return "OTHER"
	}
}

// spdxCreatorComment folds provenance contact metadata into the SPDX creation
// comment; SPDX 2.3 has no first-class fields for these.
func spdxCreatorComment(p Provenance) string {
	fields := make([]string, 0, 3)
	if contact := strings.TrimSpace(p.SecurityContact); contact != "" {
		fields = append(fields, "SecurityContact: "+contact)
	}
	if disclosure := strings.TrimSpace(p.VulnerabilityDisclosureURL); disclosure != "" {
		fields = append(fields, "VulnerabilityDisclosure: "+disclosure)
	}
	if supportEnd := strings.TrimSpace(p.SupportEnd); supportEnd != "" {
		fields = append(fields, "SupportEnd: "+supportEnd)
	}
	return strings.Join(fields, "; ")
}

func spdxPackageComment(component Component) string {
	fields := make([]string, 0, 4)
	if scope := strings.TrimSpace(component.Scope); scope != "" {
		fields = append(fields, "scope="+scope)
	}
	if typ := strings.TrimSpace(component.Type); typ != "" && !strings.EqualFold(typ, "package") {
		fields = append(fields, "type="+typ)
	}
	if component.EOL != nil {
		fields = append(fields, "eol="+strconv.FormatBool(component.EOL.EOL))
		if date := strings.TrimSpace(component.EOL.EOLDate); date != "" {
			fields = append(fields, "eol_date="+date)
		}
	}
	if len(fields) == 0 {
		return ""
	}
	return "bomly:" + strings.Join(fields, ";")
}

// spdxChecksums maps component digests onto SPDX package checksums, dropping
// entries whose algorithm is not part of the SPDX checksum vocabulary.
func spdxChecksums(digests []Digest) []common.Checksum {
	if len(digests) == 0 {
		return nil
	}
	out := make([]common.Checksum, 0, len(digests))
	for _, d := range digests {
		alg := spdxChecksumAlgorithm(d.Algorithm)
		if alg == "" || strings.TrimSpace(d.Value) == "" {
			continue
		}
		out = append(out, common.Checksum{Algorithm: alg, Value: d.Value})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func spdxChecksumAlgorithm(algorithm string) common.ChecksumAlgorithm {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "md5":
		return common.MD5
	case "sha1", "sha-1":
		return common.SHA1
	case "sha224", "sha-224":
		return common.SHA224
	case "sha256", "sha-256":
		return common.SHA256
	case "sha384", "sha-384":
		return common.SHA384
	case "sha512", "sha-512":
		return common.SHA512
	case "sha3-256":
		return common.SHA3_256
	case "sha3-384":
		return common.SHA3_384
	case "sha3-512":
		return common.SHA3_512
	default:
		return ""
	}
}

func parseSPDXComponentType(p *v23.Package) string {
	if p == nil {
		return ""
	}
	if value := parseSPDXCommentField(p.PackageComment, "type"); value != "" {
		return value
	}
	return strings.ToLower(strings.TrimSpace(p.PrimaryPackagePurpose))
}

func parseSPDXCommentField(comment, field string) string {
	comment = strings.TrimSpace(comment)
	if !strings.HasPrefix(comment, "bomly:") {
		return ""
	}
	for _, part := range strings.Split(strings.TrimPrefix(comment, "bomly:"), ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), field) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// spdxLicenseValue renders a component's licenses into one SPDX license field,
// with the extracted-text entries the field's references depend on.
//
// SPDX 2.3 has no free-text license field. licenseDeclared must hold a valid
// expression, NOASSERTION, NONE, or a LicenseRef-* identifier, so a registry
// value like "see LICENSE file" cannot be written verbatim -- which is what
// this did, producing a document a strict consumer can reject (#410). Each
// unrecognized value mints a reference instead, and the original text travels
// beside it in hasExtractedLicensingInfos. That is what SPDX defines for this
// case, and unlike NOASSERTION it keeps the information: an ingest can read
// the text back.
//
// Minting is the kit's, not this package's. A reference has to be
// deterministic, collision-free across components without coordination, and
// restricted to the characters the idstring grammar allows; spdxkit.MintLicenseRef
// answers all three by hashing, and hand-rolling a sanitizer here would be a
// second, worse answer to a question the SDK already settled.
//
// Composition now applies to every set. A LicenseRef is a valid expression
// element, so a mixed set of recognized and unrecognized values composes
// fully rather than falling back to the first value and dropping the rest --
// the silent loss the old comment described as deliberate.
//
// SPDX 2.3 holds a single expression per package and has no way to list
// licenses without relating them, so a component carrying several composes
// them. AND is the conservative reading -- it overstates obligations rather
// than understating them -- but it is still more than a source that merely
// listed licenses actually said. CycloneDX lists them instead; this is the
// one place the two formats differ, and it is recorded in docs/SBOM.md.
//
// A source that knows the relationship states it in one value ("Apache-2.0 OR
// MIT"), which arrives here as a single value and passes through untouched.
func spdxLicenseValue(licenses []License) (string, []spdxkit.ExtractedText) {
	values := componentLicenseValues(licenses)
	if len(values) == 0 {
		return "NOASSERTION", nil
	}

	elements := make([]string, 0, len(values))
	var extracted []spdxkit.ExtractedText
	for _, value := range values {
		if spdxkit.Classify(value) == spdxkit.ClassFreeText {
			ref := spdxkit.MintLicenseRef(value)
			elements = append(elements, ref.RefID)
			extracted = append(extracted, ref)
			continue
		}
		elements = append(elements, value)
	}
	if len(elements) == 1 {
		return elements[0], extracted
	}
	return spdxkit.Compose(elements), extracted
}

// maxAllocHint bounds a preallocation hint. It is a dumb count, not a limit
// on the work: a hint is only a hint, and append grows past it, so a
// genuinely larger document still encodes in full.
const maxAllocHint = 1 << 20

// allocHint sizes a preallocation from two lengths that came from a decoded
// document. Each side is clamped before the addition rather than the sum
// checked after it, so the sum cannot wrap -- an overflowed hint reaches make
// as a negative size, which panics.
//
// These lengths are attacker-influenced now: ingest carries a foreign
// document's own assertions, so a component's reference and vulnerability
// counts come from that document rather than from Bomly's own detection.
//
// Not delegated. bomly-sdk hardened the same pattern in its merges
// (bomly-dev/bomly-sdk#53) but keeps mergeCapacity unexported, and a resource
// bound is the project's own call rather than a rule a library owns -- the
// delegation convention says so explicitly. The bound is kept identical to
// the SDK's so the two do not drift into different answers for one question.
func allocHint(a, b int) int {
	return min(a, maxAllocHint) + min(b, maxAllocHint)
}

// spdxOtherLicenses renders the document's extracted-text section: one entry
// per distinct reference, sorted by identifier so the document is stable.
//
// The entries are document-scoped while the references that need them are
// written per package, so they are collected during package assembly and
// emitted once here. Two components carrying the same unrecognized text mint
// the same reference and collapse to one entry, which is the property that
// makes the reference safe to share.
func spdxOtherLicenses(extracted []spdxkit.ExtractedText) []*v23.OtherLicense {
	if len(extracted) == 0 {
		return nil
	}
	byRef := make(map[string]spdxkit.ExtractedText, len(extracted))
	for _, entry := range extracted {
		if entry.RefID == "" {
			continue
		}
		byRef[entry.RefID] = entry
	}
	refs := make([]string, 0, len(byRef))
	for ref := range byRef {
		refs = append(refs, ref)
	}
	sort.Strings(refs)

	out := make([]*v23.OtherLicense, 0, len(refs))
	for _, ref := range refs {
		out = append(out, &v23.OtherLicense{
			LicenseIdentifier: ref,
			ExtractedText:     byRef[ref].Text,
		})
	}
	return out
}

func spdxCopyrightValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return value
}

// spdxSourceInfoPrefix labels the repository recorded in PackageSourceInfo,
// which SPDX defines as free text.
const spdxSourceInfoPrefix = "Source repository: "

// spdxDownloadLocation renders where a package came from. SPDX requires the
// field, so a package whose detector asserted nothing keeps NOASSERTION rather
// than a guess.
func spdxDownloadLocation(component Component) string {
	if artifact := strings.TrimSpace(component.ArtifactURL); artifact != "" {
		return artifact
	}
	if locator := spdxVCSLocator(component); locator != "" {
		return locator
	}
	return "NOASSERTION"
}

// spdxVCSLocator renders a repository in SPDX 2.3's version-control form,
// "<tool>+<transport>://<host><path>[@<revision>]". The grammar has no query
// component and no room for anything but the revision after "@", which is why
// the origin invariant strips both before a URL gets here.
func spdxVCSLocator(component Component) string {
	repository := strings.TrimSpace(component.VCSURL)
	if repository == "" {
		return ""
	}
	locator := "git+" + repository
	if revision := strings.TrimSpace(component.VCSRevision); revision != "" {
		locator += "@" + revision
	}
	return locator
}

// spdxSourceInfo records the source repository when it is not already the
// download location. A package downloaded as an artifact still has a
// repository worth naming, and SPDX has one download location per package, so
// the repository goes here rather than being dropped.
func spdxSourceInfo(component Component) string {
	repository := strings.TrimSpace(component.VCSURL)
	if repository == "" || strings.TrimSpace(component.ArtifactURL) == "" {
		// With no artifact, the repository is the download location already.
		return ""
	}
	return spdxSourceInfoPrefix + spdxVCSLocator(component)
}

func spdxExternalReferences(component Component) []*v23.PackageExternalReference {
	refs := make([]*v23.PackageExternalReference, 0, allocHint(len(component.CPEs), len(component.Vulnerabilities))+1)
	if purl := strings.TrimSpace(component.PURL); purl != "" {
		refs = append(refs, &v23.PackageExternalReference{
			Category: common.CategoryPackageManager,
			RefType:  common.TypePackageManagerPURL,
			Locator:  purl,
		})
	}
	for _, cpe := range component.CPEs {
		cpe = strings.TrimSpace(cpe)
		if cpe == "" {
			continue
		}
		refs = append(refs, &v23.PackageExternalReference{
			Category: common.CategorySecurity,
			RefType:  common.TypeSecurityCPE23Type,
			Locator:  cpe,
		})
	}
	for _, vuln := range component.Vulnerabilities {
		locator := spdxVulnerabilityLocator(vuln)
		if locator == "" {
			continue
		}
		refs = append(refs, &v23.PackageExternalReference{
			Category: common.CategorySecurity,
			RefType:  common.TypeSecurityAdvisory,
			Locator:  locator,
		})
	}
	refs = append(refs, spdxAdditionalOriginReferences(component)...)
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// spdxOriginRefType labels an origin beyond the primary one.
//
// SPDX 2.3 defines one download location per package and one source-info
// field, so a package resolved from more than one place has nowhere in the
// defined vocabulary to say so. Category OTHER exists for exactly this: the
// specification leaves its reference type to the document, which is why this
// is a Bomly-defined type rather than a misuse of a defined category. The
// alternative was to keep dropping the evidence, and a package resolved from
// two registries is the one case where dropping it matters most.
const spdxOriginRefType = "bomly-package-origin"

// spdxAdditionalOriginReferences renders every origin after the first, which
// the download location and source info already carry between them.
func spdxAdditionalOriginReferences(component Component) []*v23.PackageExternalReference {
	if len(component.Origins) < 2 {
		return nil
	}
	refs := make([]*v23.PackageExternalReference, 0, 2*(len(component.Origins)-1))
	seen := make(map[string]struct{}, 2*len(component.Origins))
	// The primary is already published as downloadLocation and sourceInfo, so
	// it is seeded here rather than repeated.
	seen[strings.TrimSpace(component.ArtifactURL)] = struct{}{}
	seen[spdxVCSLocator(component)] = struct{}{}
	add := func(locator string) {
		locator = strings.TrimSpace(locator)
		if locator == "" {
			return
		}
		if _, duplicate := seen[locator]; duplicate {
			return
		}
		seen[locator] = struct{}{}
		refs = append(refs, &v23.PackageExternalReference{
			Category: common.CategoryOther,
			RefType:  spdxOriginRefType,
			Locator:  locator,
		})
	}
	for _, origin := range component.Origins[1:] {
		add(origin.ArtifactURL)
		add(spdxVCSLocator(Component{VCSURL: origin.Repository, VCSRevision: origin.Revision}))
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// spdxVulnerabilityLocator returns the best URL for a vulnerability external
// reference, falling back to the advisory ID when no reference URL is known.
func spdxVulnerabilityLocator(vuln Vulnerability) string {
	if len(vuln.Advisories) > 0 {
		if url := strings.TrimSpace(vuln.Advisories[0]); url != "" {
			return url
		}
	}
	return strings.TrimSpace(vuln.ID)
}

// spdxExtractedTexts indexes a document's extracted-license section by
// reference, so ingest can read back the text an exported reference names.
//
// An entry whose text does not mint its own identifier is kept under the
// identifier the document wrote, not repaired. This is a foreign document:
// the pairing it states is what it means, and re-minting would answer with a
// reference the document never used. The kit's Valid is the gate for values
// this process minted; here the document is the authority.
func spdxExtractedTexts(others []*v23.OtherLicense) map[string]string {
	if len(others) == 0 {
		return nil
	}
	byRef := make(map[string]string, len(others))
	for _, other := range others {
		if other == nil {
			continue
		}
		ref := strings.TrimSpace(other.LicenseIdentifier)
		if ref == "" {
			continue
		}
		byRef[ref] = other.ExtractedText
	}
	return byRef
}

// parseSPDXLicenses reads a package's license fields back into the model,
// resolving any reference to the text the document extracted for it.
//
// Export mints a reference for a value SPDX cannot hold verbatim (#410), so
// ingest has to undo it or a round trip would return "LicenseRef-<hash>"
// where the source said "see LICENSE file" -- information the reference
// exists to preserve, lost at the boundary that was supposed to carry it.
//
// The expression keeps the reference and the value carries the text: the
// first is what the document said, the second is what a human means, and
// collapsing them would make the resolved text look like a license
// identifier to everything downstream.
func parseSPDXLicenses(extractedByRef map[string]string, values ...string) []License {
	for _, value := range values {
		value = strings.TrimSpace(value)
		switch value {
		case "", "NOASSERTION", "NONE":
			continue
		default:
			license := License{SPDXExpression: value, Value: value}
			if text, ok := resolveSingleLicenseRef(extractedByRef, value); ok {
				license.Value = text
			}
			return []License{license}
		}
	}
	return nil
}

// resolveSingleLicenseRef returns the extracted text when the expression is
// exactly one reference and the document supplied its text.
//
// Only the atomic case resolves. A compound expression naming a reference
// among other terms ("MIT AND LicenseRef-abc") has no single text to become:
// substituting free text into it would produce something that no longer
// parses, and the reference is already the correct representation there.
func resolveSingleLicenseRef(extractedByRef map[string]string, expression string) (string, bool) {
	if len(extractedByRef) == 0 {
		return "", false
	}
	refs := spdxkit.LicenseRefsIn(expression)
	if len(refs) != 1 || refs[0] != expression {
		return "", false
	}
	text, ok := extractedByRef[expression]
	if !ok || strings.TrimSpace(text) == "" {
		return "", false
	}
	return text, true
}

func parseSPDXPURL(refs []*v23.PackageExternalReference) string {
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(ref.Category), "PACKAGE-MANAGER") &&
			strings.EqualFold(strings.TrimSpace(ref.RefType), "purl") {
			return strings.TrimSpace(ref.Locator)
		}
	}
	return ""
}

func parseSPDXPackageManager(refs []*v23.PackageExternalReference) string {
	purl := parseSPDXPURL(refs)
	if manager := packageManagerForPURL(purl, "", ""); manager != sdk.PackageManagerUnknown {
		return manager.Name()
	}
	return ""
}

func parseSPDXYcosystem(refs []*v23.PackageExternalReference) string {
	purl := parseSPDXPURL(refs)
	if parsed := parsePURL(purl); parsed != nil {
		return string(ecosystemFromPURLType(parsed.Type))
	}
	return ""
}

func parseSPDXCopyright(value string) string {
	value = strings.TrimSpace(value)
	switch value {
	case "", "NOASSERTION", "NONE":
		return ""
	default:
		return value
	}
}
