package sbom

import (
	"bytes"
	"sort"
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
			Type:       cdx.ComponentTypeLibrary,
			Name:       comp.NameOrID(),
			Scope:      cycloneDXScope(comp.Scope),
			Version:    comp.Version,
			PackageURL: comp.PURL,
			Copyright:  comp.Copyright,
		}
		if licenses := cycloneDXLicenses(comp.Licenses); len(licenses) > 0 {
			component.Licenses = &licenses
		}
		components = append(components, component)
	}
	bom.Components = &components

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

	if root := chooseRoot(doc); root != nil {
		bom.Metadata = &cdx.Metadata{
			Timestamp: doc.CreatedOrNow().Format(time.RFC3339),
			Component: &cdx.Component{
				BOMRef:  root.ID,
				Type:    cdx.ComponentTypeApplication,
				Name:    root.NameOrID(),
				Scope:   cycloneDXScope(root.Scope),
				Version: root.Version,
			},
		}
	}

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
				ds = append(ds, (*dep.Dependencies)...)
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
		Tool:         defaultToolName,
		Created:      created,
		SerialNumber: bom.SerialNumber,
		Components:   components,
		Dependencies: dependencies,
		Roots:        roots,
	}, nil
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
	default:
		return cdx.SpecVersion1_6
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
