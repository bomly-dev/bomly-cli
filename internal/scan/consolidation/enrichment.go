package consolidation

import (
	"errors"
	"fmt"
	"strings"

	model "github.com/bomly-dev/bomly-cli/sdk"
)

func normalizeGraphPackageIdentity(src *model.Graph) (*model.Graph, error) {
	if src == nil {
		return nil, nil
	}

	normalized := model.NewWithCapacity(src.Size())
	idMapping := make(map[string]string, src.Size())
	for _, pkg := range src.Packages() {
		if pkg == nil {
			continue
		}

		clone := pkg.Clone()
		model.NormalizePackageIdentity(clone)
		canonicalPURL := model.CanonicalPackageURLFromPackage(clone)
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

func canonicalPackageKey(pkg *model.Package) string {
	if pkg == nil {
		return ""
	}
	if purl := model.CanonicalPackageURLFromPackage(pkg); purl != "" {
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

func syncGraphEnrichmentByIdentity(dst, src *model.Graph) {
	if dst == nil || src == nil {
		return
	}

	sourceByKey := make(map[string]*model.Package)
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

func syncPackageEnrichment(dst, src *model.Package) {
	if dst == nil || src == nil {
		return
	}
	if len(dst.Licenses) == 0 && len(src.Licenses) > 0 {
		dst.Licenses = append([]model.PackageLicense(nil), src.Licenses...)
	}
	if strings.TrimSpace(dst.Copyright) == "" && strings.TrimSpace(src.Copyright) != "" {
		dst.Copyright = src.Copyright
	}
	if !dst.Matched && src.Matched {
		dst.Matched = true
	}
	if len(src.Vulnerabilities) > 0 {
		seen := make(map[string]struct{}, len(dst.Vulnerabilities))
		for _, vulnerability := range dst.Vulnerabilities {
			seen[vulnerability.Source+"\x00"+vulnerability.ID] = struct{}{}
		}
		for _, vulnerability := range src.Vulnerabilities {
			key := vulnerability.Source + "\x00" + vulnerability.ID
			if _, exists := seen[key]; exists {
				continue
			}
			dst.Vulnerabilities = append(dst.Vulnerabilities, vulnerability.Clone())
			seen[key] = struct{}{}
		}
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
func SyncConsolidatedEnrichmentToManifests(consolidated *model.ConsolidatedGraph, graph *model.Graph) {
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

func addPackageIfMissing(g *model.Graph, pkg *model.Package) error {
	if pkg == nil {
		return nil
	}
	clone := pkg.Clone()
	if err := g.AddPackage(clone); err != nil && !errors.Is(err, model.ErrPackageAlreadyExist) {
		return fmt.Errorf("add package %q: %w", pkg.ID, err)
	}
	return nil
}
