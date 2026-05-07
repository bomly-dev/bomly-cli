package sbom

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

var ErrNilGraph = errors.New("dependency graph is nil")

// FromDepGraph builds a neutral SBOM document from a dependency DAG.
func FromDepGraph(g *sdk.Graph, opts BuildOptions) (*Document, error) {
	if g == nil {
		return nil, ErrNilGraph
	}

	componentCount := g.Size()
	components := make([]Component, 0, componentCount)
	depsByRef := make(map[string][]string, componentCount)

	g.WalkPackages(func(pkg *sdk.Package) bool {
		components = append(components, Component{
			ID:             pkg.ID,
			Name:           pkg.QualifiedName(),
			Version:        pkg.Version,
			Scope:          pkg.Scope,
			PURL:           pkg.PURL,
			Ecosystem:      pkg.Ecosystem,
			PackageManager: pkg.BuildSystem,
			Copyright:      pkg.Copyright,
			Licenses:       componentLicenses(pkg.Licenses),
		})
		depsByRef[pkg.ID] = nil
		return true
	})

	sort.Slice(components, func(i, j int) bool {
		return components[i].ID < components[j].ID
	})

	g.WalkRelationships(func(from, to *sdk.Package) bool {
		depsByRef[from.ID] = append(depsByRef[from.ID], to.ID)
		return true
	})

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

	roots := g.Roots()
	rootIDs := make([]string, 0, len(roots))
	for _, r := range roots {
		rootIDs = append(rootIDs, r.ID)
	}
	if opts.RootComponentID != "" {
		for _, c := range components {
			if c.ID == opts.RootComponentID {
				rootIDs = []string{opts.RootComponentID}
				break
			}
		}
	}

	created := opts.Created.UTC()
	if created.IsZero() {
		created = time.Now().UTC()
	}

	documentName := opts.DocumentName
	if documentName == "" {
		documentName = defaultDocumentName
	}
	documentNS := opts.DocumentNS
	if documentNS == "" {
		documentNS = fmt.Sprintf("https://bomly.dev/spdx/%d", created.UnixNano())
	}
	toolName := opts.ToolName
	if toolName == "" {
		toolName = defaultToolName
	}

	return &Document{
		Name:         documentName,
		Namespace:    documentNS,
		Tool:         toolName,
		Created:      created,
		SerialNumber: opts.SerialNumber,
		Components:   components,
		Dependencies: dependencies,
		Roots:        rootIDs,
	}, nil
}

func componentLicenses(licenses []sdk.PackageLicense) []License {
	if len(licenses) == 0 {
		return nil
	}
	out := make([]License, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, License{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           license.Type,
		})
	}
	return out
}
