package sbom

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// ToGraph converts a neutral SBOM document back into a dependency graph.
func ToGraph(doc *Document) (*sdk.Graph, error) {
	if doc == nil {
		return nil, ErrNilDocument
	}

	depsGraph := sdk.New()
	idMap := make(map[string]string, len(doc.Components))
	for _, component := range doc.Components {
		ecosystem := strings.TrimSpace(component.Ecosystem)
		if ecosystem == "" {
			if purl := parsePURL(component.PURL); purl != nil {
				ecosystem = string(ecosystemFromPURLType(purl.Type))
			}
		}
		buildSystem := strings.TrimSpace(component.PackageManager)
		if buildSystem == "" {
			if manager := packageManagerForPURL(component.PURL, ecosystem, component.PackageManager); manager != sdk.PackageManagerUnknown {
				buildSystem = manager.Name()
			}
		}
		packageID := strings.TrimSpace(component.ID)
		if purl := strings.TrimSpace(component.PURL); purl != "" {
			packageID = purl
		}
		pkg := sdk.NewPackageWithID(packageID, sdk.Package{
			Name:        component.Name,
			Version:     component.Version,
			Scope:       component.Scope,
			Ecosystem:   ecosystem,
			BuildSystem: buildSystem,
			PURL:        strings.TrimSpace(component.PURL),
			Copyright:   component.Copyright,
			Licenses:    graphLicenses(component.Licenses),
		})
		if err := depsGraph.AddPackage(pkg); err != nil {
			return nil, fmt.Errorf("add package %q: %w", component.ID, err)
		}
		idMap[component.ID] = packageID
	}

	for _, dependency := range doc.Dependencies {
		fromID := dependency.Ref
		if mapped := idMap[fromID]; mapped != "" {
			fromID = mapped
		}
		for _, child := range dependency.DependsOn {
			toID := child
			if mapped := idMap[toID]; mapped != "" {
				toID = mapped
			}
			if err := depsGraph.AddDependency(fromID, toID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}

	return depsGraph, nil
}

func graphLicenses(licenses []License) []sdk.PackageLicense {
	if len(licenses) == 0 {
		return nil
	}
	out := make([]sdk.PackageLicense, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, sdk.PackageLicense{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           license.Type,
		})
	}
	return out
}
