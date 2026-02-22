package sbom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	model "github.com/bomly-dev/bomly-cli/sdk"
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
			PackageComment:            spdxScopeComment(c.Scope),
			PackageLicenseDeclared:    spdxLicenseValue(c.Licenses),
			PackageLicenseConcluded:   spdxLicenseValue(c.Licenses),
			PackageCopyrightText:      spdxCopyrightValue(c.Copyright),
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

	creation := &v23.CreationInfo{
		Creators: []common.Creator{
			{
				CreatorType: "Tool",
				Creator:     doc.ToolOrDefault(),
			},
		},
		Created: doc.CreatedOrNow().Format("2006-01-02T15:04:05Z"),
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
			Scope:          parseSPDXScopeComment(p.PackageComment),
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
	if ci == nil {
		return ""
	}
	for _, c := range ci.Creators {
		if c.CreatorType == "Tool" {
			return c.Creator
		}
	}
	return ""
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

func spdxScopeComment(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return ""
	}
	return "bomly:scope=" + strings.TrimSpace(scope)
}

func parseSPDXScopeComment(comment string) string {
	comment = strings.TrimSpace(comment)
	if !strings.HasPrefix(comment, "bomly:scope=") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(comment, "bomly:scope="))
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
	purl := strings.TrimSpace(component.PURL)
	if purl == "" {
		return nil
	}
	return []*v23.PackageExternalReference{{
		Category: "PACKAGE-MANAGER",
		RefType:  "purl",
		Locator:  purl,
	}}
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
	if manager := packageManagerForPURL(purl, "", ""); manager != model.PackageManagerUnknown {
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
