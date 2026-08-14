package sbom

import (
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-sdk"
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
		ecosystem := sdk.Ecosystem(strings.TrimSpace(component.Ecosystem))
		if ecosystem == sdk.EcosystemUnknown {
			if purl := parsePURL(component.PURL); purl != nil {
				ecosystem = ecosystemFromPURLType(purl.Type)
			}
		}
		packageManager := sdk.PackageManagerUnknown
		if manager, err := sdk.ParsePackageManager(component.PackageManager); err == nil {
			packageManager = manager
		}
		if packageManager == sdk.PackageManagerUnknown {
			packageManager = packageManagerForPURL(component.PURL, string(ecosystem), component.PackageManager)
		}
		packageID := strings.TrimSpace(component.ID)
		if purl := strings.TrimSpace(component.PURL); purl != "" {
			packageID = purl
		}
		// Deliberately no Source: sdk.Dependency.Source feeds
		// RegistryMatchEligible, so classifying an ingested component as git
		// or url would quietly make it ineligible for enrichment and break
		// `scan --sbom --enrich`. ResolvedURL alone is safe — eligibility
		// never reads it.
		pkg := sdk.NewDependencyWithID(packageID, sdk.Dependency{Coordinates: sdk.Coordinates{Name: component.Name,
			Version: component.Version,

			Ecosystem:      ecosystem,
			PackageManager: packageManager,
			Type:           sdk.ParsePackageType(component.Type),
			PURL:           strings.TrimSpace(component.PURL)}, Scopes: sdk.ScopesOf(sdk.Scope(component.Scope)),

			Copyright:   component.Copyright,
			CPEs:        append([]string(nil), component.CPEs...),
			Digests:     graphDigests(component.Digests),
			ResolvedURL: firstNonEmpty(component.ArtifactURL, component.VCSURL, component.RegistryURL),
		})
		sdk.SetDetectionLicenses(pkg, graphLicenses(component.Licenses))
		setIngestedMetadata(pkg, component)

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
		fromID, ok := idMap[dependency.Ref]
		if !ok {
			// Dependency entries may reference the synthesized document root
			// (present only in CycloneDX metadata.component) or otherwise
			// dangling refs; neither has a graph node to anchor an edge.
			continue
		}
		for _, child := range dependency.DependsOn {
			if _, ok := skipped[child]; ok {
				continue
			}
			toID, ok := idMap[child]
			if !ok {
				continue
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
	// Bomly's synthesized project root carries a pkg:generic PURL but is
	// still a stand-in for the scanned tree, not a resolved package.
	if IsProjectRootComponent(component) {
		return true
	}
	if strings.TrimSpace(component.PURL) != "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(component.Type), "file") && strings.TrimSpace(component.Version) == "" {
		return true
	}
	return false
}

// graphDigests projects component digests onto a graph node. Ingest dropped
// these previously, so an incoming document's hashes did not survive a format
// conversion.
func graphDigests(digests []Digest) []sdk.Digest {
	if len(digests) == 0 {
		return nil
	}
	out := make([]sdk.Digest, 0, len(digests))
	for _, digest := range digests {
		out = append(out, sdk.Digest{
			Algorithm: sdk.DigestAlgorithm(digest.Algorithm),
			Value:     digest.Value,
		})
	}
	return out
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
			Type:           sdk.LicenseType(license.Type),
		})
	}
	return out
}
