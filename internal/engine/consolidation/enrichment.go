package consolidation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func normalizeGraphPackageIdentity(src *sdk.Graph) (*sdk.Graph, error) {
	if src == nil {
		return nil, nil
	}

	normalized := sdk.NewWithCapacity(src.Size())
	idMapping := make(map[string]string, src.Size())
	for _, pkg := range src.Packages() {
		if pkg == nil {
			continue
		}

		clone := pkg.Clone()
		sdk.NormalizePackageIdentity(clone)
		canonicalPURL := sdk.CanonicalPackageURLFromPackage(clone)
		if canonicalPURL != "" {
			clone.PURL = canonicalPURL
			clone.ID = canonicalPURL
		} else if strings.TrimSpace(clone.ID) == "" {
			clone.ID = clone.StableID()
		}

		if clone.ID == "" {
			return nil, fmt.Errorf("package %q has no canonical identity", pkg.QualifiedName())
		}
		if _, exists := normalized.Package(clone.ID); !exists {
			if err := normalized.AddPackage(clone); err != nil {
				return nil, fmt.Errorf("add normalized package %q: %w", clone.ID, err)
			}
		}
		idMapping[pkg.ID] = clone.ID
	}

	for _, pkg := range src.Packages() {
		if pkg == nil {
			continue
		}
		fromID := idMapping[pkg.ID]
		if fromID == "" {
			continue
		}
		deps, err := src.Dependencies(pkg.ID)
		if err != nil {
			continue
		}
		for _, dependency := range deps {
			if dependency == nil {
				continue
			}
			toID := idMapping[dependency.ID]
			if toID == "" || fromID == toID {
				continue
			}
			if err := normalized.AddDependency(fromID, toID); err != nil {
				return nil, fmt.Errorf("add normalized dependency %q -> %q: %w", fromID, toID, err)
			}
		}
	}
	return normalized, nil
}

func canonicalPackageKey(pkg *sdk.Package) string {
	if pkg == nil {
		return ""
	}
	if purl := sdk.CanonicalPackageURLFromPackage(pkg); purl != "" {
		return "purl:" + strings.ToLower(strings.TrimSpace(purl))
	}

	ecosystem := strings.ToLower(strings.TrimSpace(pkg.Ecosystem))
	buildSystem := strings.ToLower(strings.TrimSpace(pkg.BuildSystem))
	packageType := strings.ToLower(strings.TrimSpace(pkg.Type))
	org := strings.ToLower(strings.TrimSpace(pkg.Org))
	name := strings.ToLower(strings.TrimSpace(pkg.Name))
	version := strings.TrimSpace(pkg.Version)
	if ecosystem == "" && buildSystem == "" && packageType == "" && org == "" && name == "" && version == "" {
		return ""
	}
	return strings.Join([]string{ecosystem, buildSystem, packageType, org, name, version}, "\x00")
}

func syncGraphEnrichmentByIdentity(dst, src *sdk.Graph) {
	if dst == nil || src == nil {
		return
	}

	sourceByKey := make(map[string]*sdk.Package)
	for _, pkg := range src.Packages() {
		key := canonicalPackageKey(pkg)
		if key == "" {
			continue
		}
		if _, exists := sourceByKey[key]; !exists {
			sourceByKey[key] = pkg
		}
	}

	for _, pkg := range dst.Packages() {
		key := canonicalPackageKey(pkg)
		if key == "" {
			continue
		}
		source := sourceByKey[key]
		if source == nil {
			continue
		}
		syncPackageEnrichment(pkg, source)
	}
}

func syncPackageEnrichment(dst, src *sdk.Package) {
	if dst == nil || src == nil {
		return
	}
	if len(dst.Licenses) == 0 && len(src.Licenses) > 0 {
		dst.Licenses = append([]sdk.PackageLicense(nil), src.Licenses...)
	}
	if strings.TrimSpace(dst.Copyright) == "" && strings.TrimSpace(src.Copyright) != "" {
		dst.Copyright = src.Copyright
	}
	if !dst.Matched && src.Matched {
		dst.Matched = true
	}
	if len(src.Vulnerabilities) > 0 {
		idx := make(map[string]int, len(dst.Vulnerabilities))
		for i, vulnerability := range dst.Vulnerabilities {
			idx[vulnerability.Source+"\x00"+vulnerability.ID] = i
		}
		for _, vulnerability := range src.Vulnerabilities {
			key := vulnerability.Source + "\x00" + vulnerability.ID
			if existing, ok := idx[key]; ok {
				// Merge analyzer-supplied fields onto an existing entry so
				// reachability and affected-symbol annotations propagate
				// from the consolidated graph back to per-manifest entries.
				dstEntry := &dst.Vulnerabilities[existing]
				if dstEntry.Reachability == nil && vulnerability.Reachability != nil {
					dstEntry.Reachability = vulnerability.Reachability.Clone()
				}
				if len(dstEntry.AffectedSymbols) == 0 && len(vulnerability.AffectedSymbols) > 0 {
					dstEntry.AffectedSymbols = make([]sdk.AffectedSymbol, 0, len(vulnerability.AffectedSymbols))
					for _, sym := range vulnerability.AffectedSymbols {
						dstEntry.AffectedSymbols = append(dstEntry.AffectedSymbols, sym.Clone())
					}
				}
				continue
			}
			dst.Vulnerabilities = append(dst.Vulnerabilities, vulnerability.Clone())
			idx[key] = len(dst.Vulnerabilities) - 1
		}
	}
	if dst.Scorecard == nil && src.Scorecard != nil {
		dst.Scorecard = src.Scorecard.Clone()
	}
	if len(src.Metadata) > 0 {
		if dst.Metadata == nil {
			dst.Metadata = make(map[string]any, len(src.Metadata))
		}
		for key, value := range src.Metadata {
			if _, exists := dst.Metadata[key]; exists {
				continue
			}
			dst.Metadata[key] = value
		}
	}
}

// SyncConsolidatedEnrichmentToManifests propagates enrichment from a fully consolidated graph
// (matched, audited) back to each per-manifest entry graph so callers can render per-manifest
// views with the enriched data.
func SyncConsolidatedEnrichmentToManifests(consolidated *sdk.ConsolidatedGraph, graph *sdk.Graph) {
	if consolidated == nil || graph == nil {
		return
	}
	for idx := range consolidated.Manifests {
		entryGraph := consolidated.Manifests[idx].Entry.Graph
		if entryGraph == nil || entryGraph == graph {
			continue
		}
		syncGraphEnrichmentByIdentity(entryGraph, graph)
	}
}

func addPackageIfMissing(g *sdk.Graph, pkg *sdk.Package) error {
	if pkg == nil {
		return nil
	}
	clone := pkg.Clone()
	if err := g.AddPackage(clone); err != nil && !errors.Is(err, sdk.ErrPackageAlreadyExist) {
		return fmt.Errorf("add package %q: %w", pkg.ID, err)
	}
	return nil
}
