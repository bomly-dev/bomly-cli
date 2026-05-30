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
	skipped := make(map[string]struct{})
	for _, component := range doc.Components {
		if isDocumentRootPseudoPackage(component) {
			skipped[component.ID] = struct{}{}
			continue
		}
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
		pkg := sdk.NewDependencyWithID(packageID, sdk.Dependency{
			Name:        component.Name,
			Version:     component.Version,
			Scopes:      sdk.ScopesOf(sdk.Scope(component.Scope)),
			Ecosystem:   ecosystem,
			BuildSystem: buildSystem,
			Type:        component.Type,
			PURL:        strings.TrimSpace(component.PURL),
			Copyright:   component.Copyright,
		})
		sdk.SetDetectionLicenses(pkg, graphLicenses(component.Licenses))

		if _, exists := depsGraph.Node(packageID); !exists {
			if err := depsGraph.AddNode(pkg); err != nil {
				return nil, fmt.Errorf("add package %q: %w", component.ID, err)
			}
		}
		idMap[component.ID] = packageID
	}

	for _, dependency := range doc.Dependencies {
		if _, ok := skipped[dependency.Ref]; ok {
			continue
		}
		fromID := dependency.Ref
		if mapped := idMap[fromID]; mapped != "" {
			fromID = mapped
		}
		for _, child := range dependency.DependsOn {
			if _, ok := skipped[child]; ok {
				continue
			}
			toID := child
			if mapped := idMap[toID]; mapped != "" {
				toID = mapped
			}
			if fromID == toID {
				continue
			}
			if err := depsGraph.AddEdge(fromID, toID); err != nil {
				return nil, fmt.Errorf("add dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}

	return depsGraph, nil
}

func isDocumentRootPseudoPackage(component Component) bool {
	if strings.TrimSpace(component.PURL) != "" {
		return false
	}
	id := strings.TrimSpace(component.ID)
	if strings.HasPrefix(id, "SPDXRef-DocumentRoot-") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(component.Type), "file") && strings.TrimSpace(component.Version) == "" {
		return true
	}
	return false
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
