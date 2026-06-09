package sbom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

type spdx23Codec struct{}

func (spdx23Codec) encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error) {
	idByComponent := make(map[string]common.ElementID, len(doc.Components))
	usedIDs := make(map[string]int, len(doc.Components))
	packages := make([]*v23.Package, 0, len(doc.Components))

	for _, c := range doc.Components {
		base := sanitizeSPDXID(c.ID)
		seq := usedIDs[base]
		usedIDs[base] = seq + 1
		if seq > 0 {
			base = fmt.Sprintf("%s-%d", base, seq)
		}
		spdxID := common.ElementID(base)
		idByComponent[c.ID] = spdxID

		packages = append(packages, &v23.Package{
			PackageName:               c.NameOrID(),
			PackageSPDXIdentifier:     spdxID,
			PackageVersion:            c.Version,
			PackageDownloadLocation:   "NOASSERTION",
			FilesAnalyzed:             false,
			PackageComment:            spdxPackageComment(c),
			PackageLicenseDeclared:    spdxLicenseValue(c.Licenses),
			PackageLicenseConcluded:   spdxLicenseValue(c.Licenses),
			PackageCopyrightText:      spdxCopyrightValue(c.Copyright),
			PackageChecksums:          spdxChecksums(c.Digests),
			PackageExternalReferences: spdxExternalReferences(c),
		})
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

	creators := make([]common.Creator, 0, len(doc.ToolNamesOrDefault()))
	for _, tool := range doc.ToolNamesOrDefault() {
		creators = append(creators, common.Creator{
			CreatorType: "Tool",
			Creator:     tool,
		})
	}
	creation := &v23.CreationInfo{
		Creators: creators,
		Created:  doc.CreatedOrNow().Format("2006-01-02T15:04:05Z"),
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
		components = append(components, Component{
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
		})
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
			RefType:  "cpe23Type",
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
