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

	for _, c := range doc.Components {
		base := sanitizeSPDXID(c.ID)
		seq := usedIDs[base]
		usedIDs[base] = seq + 1
		if seq > 0 {
			base = fmt.Sprintf("%s-%d", base, seq)
		}
		spdxID := common.ElementID(base)
		idByComponent[c.ID] = spdxID

		pkg := &v23.Package{
			PackageName:               c.NameOrID(),
			PackageSPDXIdentifier:     spdxID,
			PackageVersion:            c.Version,
			PackageDownloadLocation:   spdxDownloadLocation(c),
			FilesAnalyzed:             false,
			PackageComment:            spdxPackageComment(c),
			PackageLicenseDeclared:    spdxLicenseValue(c.Licenses),
			PackageLicenseConcluded:   spdxLicenseValue(c.Licenses),
			PackageCopyrightText:      spdxCopyrightValue(c.Copyright),
			PackageChecksums:          spdxChecksums(c.Digests),
			PackageExternalReferences: spdxExternalReferences(c),
			PrimaryPackagePurpose:     spdxPrimaryPackagePurpose(c.Type),
			PackageDescription:        c.Description,
			PackageSummary:            c.Summary,
			PackageSourceInfo:         spdxSourceInfo(c),
			PackageHomePage:           spdxHomePage(c),
		}
		// SPDX has no untyped originator: the value must be declared a Person
		// or an Organization. A CycloneDX `publisher` is a free string that
		// the spec defines as either, so emitting one here would assert an
		// entity type the source document never made. Emit only when the
		// source established the type.
		if c.Originator != "" && c.OriginatorType != "" {
			pkg.PackageOriginator = &common.Originator{
				OriginatorType: spdxEntityType(c.OriginatorType),
				Originator:     c.Originator,
			}
		}
		// The configured manufacturer is the user's own claim about their
		// product, so it wins on the document's primary package. Everywhere
		// else a supplier appears only when a source document asserted one.
		supplier, supplierType := c.Supplier, c.SupplierType
		if _, isRoot := rootComponents[c.ID]; isRoot || IsProjectRootComponent(c) {
			if doc.Provenance.Manufacturer != "" {
				supplier, supplierType = doc.Provenance.Manufacturer, "Organization"
			}
		}
		if supplier != "" {
			pkg.PackageSupplier = &common.Supplier{SupplierType: spdxEntityType(supplierType), Supplier: supplier}
		}
		packages = append(packages, pkg)
	}

	relationships := make([]*v23.Relationship, 0, len(doc.Dependencies)+len(doc.Roots))
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

	creators := make([]common.Creator, 0, len(doc.ToolNamesOrDefault())+1)
	for _, tool := range doc.ToolNamesOrDefault() {
		// SPDX creator convention appends the tool version as "name-version".
		if tool == doc.ToolOrDefault() && doc.ToolVersion != "" {
			tool += "-" + doc.ToolVersion
		}
		creators = append(creators, common.Creator{
			CreatorType: "Tool",
			Creator:     tool,
		})
	}
	if doc.Provenance.Manufacturer != "" {
		creators = append(creators, common.Creator{
			CreatorType: "Organization",
			Creator:     doc.Provenance.Manufacturer,
		})
	}
	creation := &v23.CreationInfo{
		Creators:       creators,
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
		Packages:          packages,
		Relationships:     relationships,
	}

	return marshalJSON(spdxDoc, opts.Pretty)
}

func (spdx23Codec) decodeJSON(data []byte) (*Document, error) {
	var spdxDoc v23.Document
	if err := json.Unmarshal(data, &spdxDoc); err != nil {
		return nil, err
	}

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
			Licenses:       parseSPDXLicenses(p.PackageLicenseConcluded, p.PackageLicenseDeclared),
			Description:    parseSPDXEntity(p.PackageDescription),
			Summary:        parseSPDXEntity(p.PackageSummary),
			CPEs:           parseSPDXCPEs(p.PackageExternalReferences),
			Digests:        parseSPDXChecksums(p.PackageChecksums),
		}
		component.Repository, component.VCSURL = parseSPDXSourceInfo(p.PackageSourceInfo)
		if p.PackageSupplier != nil {
			component.Supplier = parseSPDXEntity(p.PackageSupplier.Supplier)
			component.SupplierType = p.PackageSupplier.SupplierType
		}
		if p.PackageOriginator != nil {
			component.Originator = parseSPDXEntity(p.PackageOriginator.Originator)
			component.OriginatorType = p.PackageOriginator.OriginatorType
		}
		if strings.EqualFold(strings.TrimSpace(p.PackageDownloadLocation), "NONE") {
			component.NoDownloadLocation = true
		}
		applyLocator(&component, classifyAssertedDownloadLocation(parseSPDXEntity(p.PackageDownloadLocation)))
		if home := parseSPDXEntity(p.PackageHomePage); isPublishableReferenceURL(home) {
			component.ExternalRefs = append(component.ExternalRefs, ExternalRef{Type: "website", URL: home})
		}
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
		if c.CreatorType == "Tool" {
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
	case "blake3":
		return common.BLAKE3
	case "blake2b-256":
		return common.BLAKE2b_256
	case "blake2b-384":
		return common.BLAKE2b_384
	case "blake2b-512":
		return common.BLAKE2b_512
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

func spdxLicenseValue(licenses []License) string {
	if len(licenses) == 0 {
		return "NOASSERTION"
	}
	if licenses[0].SPDXExpression != "" {
		return licenses[0].SPDXExpression
	}
	if licenses[0].Value != "" {
		return licenses[0].Value
	}
	return "NOASSERTION"
}

func spdxCopyrightValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return value
}

// parseSPDXEntity normalizes an SPDX free-text field, treating the reserved
// NOASSERTION and NONE markers as absent rather than as literal values.
func parseSPDXEntity(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToUpper(value) {
	case "", "NOASSERTION", "NONE":
		return ""
	}
	return value
}

// parseSPDXSourceInfo recovers a source repository written by spdxSourceInfo.
// Free text without the marker prefix is another producer's prose and is left
// alone rather than guessed at.
//
// The recovered value is untrusted and is re-published in both formats — SPDX
// PackageSourceInfo and a CycloneDX `vcs` reference — so it goes through the
// same gate as every other ingested URL. A source document asserting
// "Source repository: https://user:secret@github.com/org/repo", or a local
// file:// path, yields nothing.
func parseSPDXSourceInfo(value string) (repository, vcs string) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, spdxSourceInfoPrefix) {
		return "", ""
	}
	locator := strings.TrimSpace(strings.TrimPrefix(value, spdxSourceInfoPrefix))
	if strings.HasPrefix(locator, "git+") {
		// spdxSourceInfo writes the version-control form when the artifact
		// owns downloadLocation, so it has to be recognized here or the
		// repository is lost on the way back.
		return "", validatedVCSLocator(locator)
	}
	return normalizeRepositoryURL(locator), ""
}

// spdxSourceInfoPrefix marks a source repository inside the free-text
// PackageSourceInfo field so the decoder can recover it deterministically.
const spdxSourceInfoPrefix = "Source repository: "

// spdxDownloadLocation renders where the package was obtained.
//
// A registry root is deliberately not used: "https://rubygems.org/" is a
// syntactically valid URL that both validators accept, and every consumer
// would read it as the artifact's origin, which is false. NOASSERTION is the
// honest answer when only a registry root is known.
func spdxDownloadLocation(component Component) string {
	if location := firstNonEmpty(component.ArtifactURL, component.VCSURL); location != "" {
		return location
	}
	// SPDX separates "there is no download location" from "no claim was
	// made". Collapsing NONE to NOASSERTION would weaken an explicit
	// assertion the source document made.
	if component.NoDownloadLocation {
		return "NONE"
	}
	return "NOASSERTION"
}

// spdxSourceInfo renders the source repository into SPDX's free-text origin
// field.
//
// PackageSourceInfo is defined as free text about the origin of the package,
// which is what a source repository is. PackageHomePage is a different claim
// (the package's home page) that Bomly does not know, and SPDX 2.3 has no
// version-control external-reference category.
func spdxSourceInfo(component Component) string {
	// Suppress only when the VCS locator actually became the download
	// location, which is the case that would make one package assert two
	// different source repositories. An ingested component may carry both a
	// distribution and a vcs reference; there the artifact owns
	// downloadLocation, and dropping the repository as well would lose it
	// entirely even though PackageSourceInfo can represent it.
	if component.VCSURL != "" && component.ArtifactURL == "" {
		return ""
	}
	repo := strings.TrimSpace(component.Repository)
	if repo == "" && component.ArtifactURL != "" {
		// Keep the version-control form intact. Stripping "git+" from
		// "git+https://host/org/repo@deadbeef" turns the revision into part
		// of the URL path, producing a repository address that does not
		// exist — and one that re-ingests cleanly as if it did.
		repo = component.VCSURL
	}
	if repo == "" {
		return ""
	}
	return spdxSourceInfoPrefix + repo
}

// spdxHomePage restores a home page carried on an ingested website reference.
//
// SPDX has a first-class field for this, so an SPDX-to-SPDX pass would
// otherwise drop a value the destination format represents exactly.
func spdxHomePage(component Component) string {
	for _, ref := range component.ExternalRefs {
		if strings.EqualFold(ref.Type, "website") && isPublishableReferenceURL(ref.URL) {
			return ref.URL
		}
	}
	return ""
}

// spdxEntityType normalizes a supplier or originator type to one SPDX accepts,
// defaulting to Organization.
func spdxEntityType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "person":
		return "Person"
	case "noassertion":
		return "NOASSERTION"
	default:
		return "Organization"
	}
}

func spdxExternalReferences(component Component) []*v23.PackageExternalReference {
	refs := make([]*v23.PackageExternalReference, 0, 1+len(component.CPEs)+len(component.Vulnerabilities))
	if purl := strings.TrimSpace(component.PURL); purl != "" {
		refs = append(refs, &v23.PackageExternalReference{
			Category: "PACKAGE-MANAGER",
			RefType:  "purl",
			Locator:  purl,
		})
	}
	for _, cpe := range component.CPEs {
		cpe = strings.TrimSpace(cpe)
		if cpe == "" {
			continue
		}
		refs = append(refs, &v23.PackageExternalReference{
			Category: "SECURITY",
			RefType:  spdxCPERefType(cpe),
			Locator:  cpe,
		})
	}
	for _, vuln := range component.Vulnerabilities {
		locator := spdxVulnerabilityLocator(vuln)
		if locator == "" {
			continue
		}
		refs = append(refs, &v23.PackageExternalReference{
			Category: "SECURITY",
			RefType:  "advisory",
			Locator:  locator,
		})
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

func parseSPDXLicenses(values ...string) []License {
	for _, value := range values {
		value = strings.TrimSpace(value)
		switch value {
		case "", "NOASSERTION", "NONE":
			continue
		default:
			return []License{{SPDXExpression: value, Value: value}}
		}
	}
	return nil
}

// isValidCPE reports whether a locator is a well-formed CPE in either the 2.3
// formatted-string or the 2.2 URI binding.
//
// An ingested document can label any string cpe23Type. Preserving one
// unchecked republishes a false package-identity assertion — it becomes an
// SPDX security reference and CycloneDX's `cpe` field — and can make the
// output non-conformant, so the shape is verified before it is stored.
func isValidCPE(value string) bool {
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, "cpe:2.3:"):
		// "cpe:2.3:" plus 11 colon-separated components: part, vendor,
		// product, version, update, edition, language, sw_edition,
		// target_sw, target_hw, other. Escaped colons ("\:") are literals.
		parts := splitUnescaped(value, ':')
		if len(parts) != 13 {
			return false
		}
		if !isCPEPart(parts[2]) {
			return false
		}
		// Every remaining component must be a well-formed avstring. Checking
		// only the field count let values such as
		// "cpe:2.3:a:vendor with space:product:…" through.
		for _, part := range parts[3:] {
			if !isCPEComponent(part) {
				return false
			}
		}
		return true
	case strings.HasPrefix(value, "cpe:/"):
		// URI binding: "cpe:/" plus up to 7 components, the first the part.
		parts := splitUnescaped(strings.TrimPrefix(value, "cpe:/"), ':')
		if len(parts) == 0 || len(parts) > 7 {
			return false
		}
		if !isCPEPart(parts[0]) {
			return false
		}
		for _, part := range parts[1:] {
			if !isCPEComponent(part) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// isCPEPart reports whether a CPE part component is one of the defined values.
//
// An empty part is not among them: "cpe:2.3::vendor:…" names no component
// class, so accepting it would preserve an identity assertion that identifies
// nothing.
func isCPEPart(part string) bool {
	switch part {
	case "a", "o", "h", "*", "-":
		return true
	default:
		return false
	}
}

// isCPEComponent reports whether a CPE attribute value is well formed.
//
// The logical values "*" and "-" stand alone. Otherwise the value is a quoted
// string of printable ASCII: whitespace and control characters are not
// permitted, and the punctuation CPE reserves must be backslash-escaped. A
// trailing lone backslash escapes nothing and is malformed.
//
// The wildcards "*" and "?" are allowed unescaped, because partial values such
// as "1.3.*" are legal and common. Rejecting them would drop real identity
// data, which is the same kind of harm as preserving a fabricated value.
func isCPEComponent(value string) bool {
	switch value {
	case "*", "-":
		return true
	case "":
		return false
	}

	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			escaped = false
		case r == '\\':
			escaped = true
		case r < '!' || r > '~':
			// Space, control characters, and anything non-ASCII.
			return false
		case strings.ContainsRune(`!"#$%&'()+,/:;<=>@[]^`+"`"+`{|}~`, r):
			// Reserved punctuation must be escaped to appear literally.
			return false
		}
	}
	return !escaped
}

// splitUnescaped splits on sep, treating a backslash-escaped separator as a
// literal character rather than a delimiter.
func splitUnescaped(value string, sep rune) []string {
	var parts []string
	var current strings.Builder
	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			current.WriteRune(r)
			escaped = true
		case r == sep:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	parts = append(parts, current.String())
	return parts
}

// spdxCPERefType labels a CPE locator with the reference type matching its own
// syntax.
//
// The two forms are self-describing — 2.3 is colon-delimited and starts
// "cpe:2.3:", 2.2 starts "cpe:/" — so the type is derived rather than carried.
// Emitting a 2.2 locator as cpe23Type would relabel it without converting it,
// asserting a syntax the value does not use.
func spdxCPERefType(cpe string) string {
	if strings.HasPrefix(strings.TrimSpace(cpe), "cpe:/") {
		return "cpe22Type"
	}
	return "cpe23Type"
}

// parseSPDXCPEs recovers CPE identifiers from a package's security external
// references.
func parseSPDXCPEs(refs []*v23.PackageExternalReference) []string {
	var cpes []string
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		// SPDX 2.3 defines both CPE reference types. Bomly writes cpe23Type,
		// but an ingested third-party document may use either.
		switch strings.ToLower(strings.TrimSpace(ref.RefType)) {
		case "cpe23type", "cpe22type":
			if locator := strings.TrimSpace(ref.Locator); isValidCPE(locator) {
				cpes = append(cpes, locator)
			}
		}
	}
	return cpes
}

// parseSPDXChecksums projects SPDX checksums onto neutral digests.
func parseSPDXChecksums(checksums []common.Checksum) []Digest {
	if len(checksums) == 0 {
		return nil
	}
	digests := make([]Digest, 0, len(checksums))
	for _, checksum := range checksums {
		digest, ok := ingestedDigest(string(checksum.Algorithm), checksum.Value)
		if !ok {
			continue
		}
		digests = append(digests, digest)
	}
	if len(digests) == 0 {
		return nil
	}
	return digests
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
