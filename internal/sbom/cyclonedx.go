package sbom

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type cycloneDXCodec struct {
	version Target
}

func (c cycloneDXCodec) encodeJSON(doc *Document, opts EncodeOptions) ([]byte, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = doc.SerialNumber

	components := make([]cdx.Component, 0, len(doc.Components))
	for _, comp := range doc.Components {
		component := cdx.Component{
			BOMRef:     comp.ID,
			Type:       cycloneDXComponentType(comp.Type),
			Name:       comp.NameOrID(),
			Scope:      cycloneDXScope(comp.Scope),
			Version:    comp.Version,
			PackageURL: comp.PURL,
			Copyright:  comp.Copyright,
		}
		if licenses := cycloneDXLicenses(comp.Licenses); len(licenses) > 0 {
			component.Licenses = &licenses
		}
		if len(comp.CPEs) > 0 {
			component.CPE = comp.CPEs[0]
		}
		if hashes := cycloneDXHashes(comp.Digests); len(hashes) > 0 {
			component.Hashes = &hashes
		}
		if props := cycloneDXEOLProperties(comp.EOL); len(props) > 0 {
			component.Properties = &props
		}
		components = append(components, component)
	}
	bom.Components = &components

	if vulns := cycloneDXVulnerabilities(doc.Components); len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	deps := make([]cdx.Dependency, 0, len(doc.Dependencies))
	for _, dep := range doc.Dependencies {
		cd := cdx.Dependency{Ref: dep.Ref}
		if len(dep.DependsOn) > 0 {
			children := make([]string, len(dep.DependsOn))
			copy(children, dep.DependsOn)
			cd.Dependencies = &children
		}
		deps = append(deps, cd)
	}
	bom.Dependencies = &deps

	metadata := &cdx.Metadata{
		Timestamp: doc.CreatedOrNow().Format(time.RFC3339),
		Tools:     cycloneDXTools(doc.ToolNamesOrDefault()),
	}
	if root := chooseRoot(doc); root != nil {
		metadata.Component = &cdx.Component{
			BOMRef:  root.ID,
			Type:    cycloneDXComponentType(firstNonEmpty(root.Type, "application")),
			Name:    root.NameOrID(),
			Scope:   cycloneDXScope(root.Scope),
			Version: root.Version,
		}
	}
	bom.Metadata = metadata

	var out bytes.Buffer
	enc := cdx.NewBOMEncoder(&out, cdx.BOMFileFormatJSON).SetPretty(opts.Pretty)
	if err := enc.EncodeVersion(bom, toCycloneDXVersion(c.version)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (c cycloneDXCodec) decodeJSON(data []byte) (*Document, error) {
	bom := new(cdx.BOM)
	dec := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON)
	if err := dec.Decode(bom); err != nil {
		return nil, err
	}

	componentByID := make(map[string]Component)
	if bom.Components != nil {
		for _, comp := range *bom.Components {
			componentByID[comp.BOMRef] = Component{
				ID:        comp.BOMRef,
				Name:      comp.Name,
				Type:      string(comp.Type),
				Scope:     string(comp.Scope),
				Version:   comp.Version,
				PURL:      comp.PackageURL,
				Copyright: comp.Copyright,
				Licenses:  parseCycloneDXLicenses(comp.Licenses),
			}
		}
	}

	dependencies := make([]Dependency, 0, len(componentByID))
	inDegree := make(map[string]int, len(componentByID))
	if bom.Dependencies != nil {
		for _, dep := range *bom.Dependencies {
			ds := make([]string, 0)
			if dep.Dependencies != nil {
				ds = append(ds, *dep.Dependencies...)
				for _, child := range ds {
					inDegree[child]++
				}
			}
			if len(ds) > 1 {
				sort.Strings(ds)
			}
			dependencies = append(dependencies, Dependency{
				Ref:       dep.Ref,
				DependsOn: ds,
			})
		}
	}

	if len(componentByID) == 0 && bom.Metadata != nil && bom.Metadata.Component != nil {
		root := bom.Metadata.Component
		componentByID[root.BOMRef] = Component{
			ID:        root.BOMRef,
			Name:      root.Name,
			Type:      string(root.Type),
			Scope:     string(root.Scope),
			Version:   root.Version,
			PURL:      root.PackageURL,
			Copyright: root.Copyright,
			Licenses:  parseCycloneDXLicenses(root.Licenses),
		}
	}

	components := make([]Component, 0, len(componentByID))
	for _, comp := range componentByID {
		components = append(components, comp)
	}
	sort.Slice(components, func(i, j int) bool { return components[i].ID < components[j].ID })

	if len(dependencies) == 0 {
		dependencies = make([]Dependency, 0, len(components))
		for _, comp := range components {
			dependencies = append(dependencies, Dependency{Ref: comp.ID})
		}
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].Ref < dependencies[j].Ref })

	roots := make([]string, 0)
	for _, comp := range components {
		if inDegree[comp.ID] == 0 {
			roots = append(roots, comp.ID)
		}
	}
	sort.Strings(roots)

	created := time.Time{}
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err == nil {
			created = t.UTC()
		}
	}

	return &Document{
		Name:         defaultDocumentName,
		Tool:         cycloneDXPrimaryToolName(bom.Metadata),
		Tools:        cycloneDXToolNames(bom.Metadata),
		Created:      created,
		SerialNumber: bom.SerialNumber,
		Components:   components,
		Dependencies: dependencies,
		Roots:        roots,
	}, nil
}

func cycloneDXTools(names []string) *cdx.ToolsChoice {
	if len(names) == 0 {
		return nil
	}
	components := make([]cdx.Component, 0, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		components = append(components, cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: name,
		})
	}
	if len(components) == 0 {
		return nil
	}
	return &cdx.ToolsChoice{Components: &components}
}

func cycloneDXToolNames(metadata *cdx.Metadata) []string {
	if metadata == nil || metadata.Tools == nil {
		return nil
	}
	names := make([]string, 0)
	if metadata.Tools.Components != nil {
		for _, tool := range *metadata.Tools.Components {
			if strings.TrimSpace(tool.Name) != "" {
				names = append(names, tool.Name)
			}
		}
	}
	if metadata.Tools.Tools != nil {
		for _, tool := range *metadata.Tools.Tools {
			if strings.TrimSpace(tool.Name) != "" {
				names = append(names, tool.Name)
			}
		}
	}
	return names
}

func cycloneDXPrimaryToolName(metadata *cdx.Metadata) string {
	names := cycloneDXToolNames(metadata)
	if len(names) > 0 {
		return names[0]
	}
	return defaultToolName
}

func cycloneDXComponentType(value string) cdx.ComponentType {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "application":
		return cdx.ComponentTypeApplication
	case "framework":
		return cdx.ComponentTypeFramework
	case "container":
		return cdx.ComponentTypeContainer
	case "operating-system":
		return cdx.ComponentTypeOS
	case "device":
		return cdx.ComponentTypeDevice
	case "file":
		return cdx.ComponentTypeFile
	case "firmware":
		return cdx.ComponentTypeFirmware
	default:
		return cdx.ComponentTypeLibrary
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cycloneDXScope(value string) cdx.Scope {
	switch value {
	case "runtime":
		return cdx.ScopeRequired
	case "development":
		return cdx.ScopeExcluded
	default:
		return ""
	}
}

func chooseRoot(doc *Document) *Component {
	if doc == nil || len(doc.Components) == 0 {
		return nil
	}
	if len(doc.Roots) > 0 {
		rootID := doc.Roots[0]
		for i := range doc.Components {
			if doc.Components[i].ID == rootID {
				return &doc.Components[i]
			}
		}
	}
	return &doc.Components[0]
}

func toCycloneDXVersion(target Target) cdx.SpecVersion {
	switch target {
	case TargetCycloneDX14JSON:
		return cdx.SpecVersion1_4
	case TargetCycloneDX15JSON:
		return cdx.SpecVersion1_5
	case TargetCycloneDX16JSON:
		return cdx.SpecVersion1_6
	default:
		return cdx.SpecVersion1_7
	}
}

func cycloneDXLicenses(licenses []License) cdx.Licenses {
	if len(licenses) == 0 {
		return nil
	}
	out := make(cdx.Licenses, 0, len(licenses))
	for _, license := range licenses {
		switch {
		case license.SPDXExpression != "":
			out = append(out, cdx.LicenseChoice{Expression: license.SPDXExpression})
		case license.Value != "":
			out = append(out, cdx.LicenseChoice{License: &cdx.License{Name: license.Value}})
		}
	}
	return out
}

func cycloneDXHashes(digests []Digest) []cdx.Hash {
	if len(digests) == 0 {
		return nil
	}
	out := make([]cdx.Hash, 0, len(digests))
	for _, d := range digests {
		alg := cycloneDXHashAlgorithm(d.Algorithm)
		if alg == "" || strings.TrimSpace(d.Value) == "" {
			continue
		}
		out = append(out, cdx.Hash{Algorithm: alg, Value: d.Value})
	}
	return out
}

// cycloneDXHashAlgorithm maps a digest algorithm string onto a CycloneDX hash
// algorithm constant. Returns "" when the algorithm is unsupported so the
// digest is dropped rather than emitting an invalid BOM.
func cycloneDXHashAlgorithm(algorithm string) cdx.HashAlgorithm {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "md5":
		return cdx.HashAlgoMD5
	case "sha1", "sha-1":
		return cdx.HashAlgoSHA1
	case "sha256", "sha-256":
		return cdx.HashAlgoSHA256
	case "sha384", "sha-384":
		return cdx.HashAlgoSHA384
	case "sha512", "sha-512":
		return cdx.HashAlgoSHA512
	case "sha3-256":
		return cdx.HashAlgoSHA3_256
	case "sha3-384":
		return cdx.HashAlgoSHA3_384
	case "sha3-512":
		return cdx.HashAlgoSHA3_512
	default:
		return ""
	}
}

func cycloneDXEOLProperties(eol *EOL) []cdx.Property {
	if eol == nil {
		return nil
	}
	props := make([]cdx.Property, 0, 3)
	props = append(props, cdx.Property{Name: "bomly:eol", Value: strconv.FormatBool(eol.EOL)})
	if eol.EOLDate != "" {
		props = append(props, cdx.Property{Name: "bomly:eol_date", Value: eol.EOLDate})
	}
	if eol.Cycle != "" {
		props = append(props, cdx.Property{Name: "bomly:eol_cycle", Value: eol.Cycle})
	}
	return props
}

// cycloneDXVulnerabilities flattens per-component vulnerabilities into the
// BOM-level vulnerabilities array, deduplicating by advisory ID and collecting
// every affected component BOMRef under Affects.
func cycloneDXVulnerabilities(components []Component) []cdx.Vulnerability {
	type accumulator struct {
		vuln  Vulnerability
		refs  []string
		order int
	}
	byID := make(map[string]*accumulator)
	order := 0
	for _, comp := range components {
		for _, v := range comp.Vulnerabilities {
			if strings.TrimSpace(v.ID) == "" {
				continue
			}
			acc, ok := byID[v.ID]
			if !ok {
				acc = &accumulator{vuln: v, order: order}
				order++
				byID[v.ID] = acc
			}
			acc.refs = append(acc.refs, comp.ID)
		}
	}
	if len(byID) == 0 {
		return nil
	}
	out := make([]cdx.Vulnerability, 0, len(byID))
	for _, acc := range byID {
		out = append(out, cycloneDXVulnerability(acc.vuln, acc.refs))
	}
	sort.Slice(out, func(i, j int) bool {
		return byID[out[i].ID].order < byID[out[j].ID].order
	})
	return out
}

func cycloneDXVulnerability(v Vulnerability, refs []string) cdx.Vulnerability {
	vuln := cdx.Vulnerability{
		ID:          v.ID,
		Description: v.Description,
	}
	if v.Source != "" {
		vuln.Source = &cdx.Source{Name: v.Source}
	}
	if v.Score != nil || v.Severity != "" || v.Vector != "" {
		rating := cdx.VulnerabilityRating{
			Severity: cycloneDXSeverity(v.Severity),
			Method:   cdx.ScoringMethod(v.Method),
			Vector:   v.Vector,
		}
		if v.Score != nil {
			rating.Score = new(*v.Score)
		}
		if v.Source != "" {
			rating.Source = &cdx.Source{Name: v.Source}
		}
		ratings := []cdx.VulnerabilityRating{rating}
		vuln.Ratings = &ratings
	}
	if len(v.CWEs) > 0 {
		vuln.CWEs = new(append([]int(nil), v.CWEs...))
	}
	if len(v.Advisories) > 0 {
		advisories := make([]cdx.Advisory, 0, len(v.Advisories))
		for _, url := range v.Advisories {
			advisories = append(advisories, cdx.Advisory{URL: url})
		}
		vuln.Advisories = &advisories
	}
	if len(refs) > 0 {
		sorted := append([]string(nil), refs...)
		sort.Strings(sorted)
		affects := make([]cdx.Affects, 0, len(sorted))
		for _, ref := range sorted {
			affects = append(affects, cdx.Affects{Ref: ref})
		}
		vuln.Affects = &affects
	}
	return vuln
}

func cycloneDXSeverity(severity string) cdx.Severity {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return cdx.SeverityCritical
	case "high":
		return cdx.SeverityHigh
	case "medium", "moderate":
		return cdx.SeverityMedium
	case "low":
		return cdx.SeverityLow
	case "none":
		return cdx.SeverityNone
	case "info", "informational":
		return cdx.SeverityInfo
	default:
		return cdx.SeverityUnknown
	}
}

func parseCycloneDXLicenses(licenses *cdx.Licenses) []License {
	if licenses == nil || len(*licenses) == 0 {
		return nil
	}
	out := make([]License, 0, len(*licenses))
	for _, choice := range *licenses {
		switch {
		case choice.Expression != "":
			out = append(out, License{SPDXExpression: choice.Expression, Value: choice.Expression})
		case choice.License != nil:
			value := choice.License.ID
			if value == "" {
				value = choice.License.Name
			}
			out = append(out, License{Value: value, SPDXExpression: choice.License.ID})
		}
	}
	return out
}
