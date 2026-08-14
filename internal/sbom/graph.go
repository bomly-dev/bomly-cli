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

		if existing, exists := depsGraph.Node(packageID); exists {
			// Several component IDs can share one PURL (a lockfile entry and
			// an installed-metadata entry for the same package). Only the
			// first becomes a graph node, so the duplicate's assertions have
			// to be folded in rather than dropped with the discarded object.
			mergeIngestedNode(existing, pkg)
		} else if err := depsGraph.AddNode(pkg); err != nil {
			return nil, fmt.Errorf("add package %q: %w", component.ID, err)
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

// mergeIngestedNode folds a duplicate-PURL component's assertions into the
// graph node that already represents that package.
//
// Fill-gaps semantics: the first component wins any conflict, and later ones
// only supply what is still missing. Set-valued fields are unioned, since two
// entries for the same package may each carry a digest or CPE the other does
// not.
func mergeIngestedNode(existing, incoming *sdk.Dependency) {
	if existing == nil || incoming == nil {
		return
	}
	if existing.Copyright == "" {
		existing.Copyright = incoming.Copyright
	}
	if existing.ResolvedURL == "" {
		existing.ResolvedURL = incoming.ResolvedURL
	}
	existing.CPEs = unionStrings(existing.CPEs, incoming.CPEs)
	existing.Digests = unionDigests(existing.Digests, incoming.Digests)

	if len(sdk.DetectionLicenses(existing)) == 0 {
		if licenses := sdk.DetectionLicenses(incoming); len(licenses) > 0 {
			sdk.SetDetectionLicenses(existing, licenses)
		}
	}
	for key, value := range incoming.Metadata {
		if existing.Metadata == nil {
			existing.Metadata = make(map[string]any, len(incoming.Metadata))
		}
		if _, present := existing.Metadata[key]; !present {
			existing.Metadata[key] = value
		}
	}
}

// unionStrings appends values from extra that are not already in base.
func unionStrings(base, extra []string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, value := range base {
		seen[value] = struct{}{}
	}
	for _, value := range extra {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		base = append(base, value)
	}
	return base
}

// unionDigests appends digests from extra that are not already in base.
func unionDigests(base, extra []sdk.Digest) []sdk.Digest {
	seen := make(map[sdk.Digest]struct{}, len(base))
	for _, digest := range base {
		seen[digest] = struct{}{}
	}
	for _, digest := range extra {
		if _, ok := seen[digest]; ok {
			continue
		}
		seen[digest] = struct{}{}
		base = append(base, digest)
	}
	return base
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
