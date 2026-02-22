package scan

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/normalization"
)

// ConsolidatedSubproject describes one subproject included in a consolidated graph.
type ConsolidatedSubproject struct {
	Subproject      Subproject
	DetectorName    string
	RootManifestIDs []string
}

// ConsolidatedManifest describes one selected manifest after detector-level
// deduplication and precedence rules have been applied.
type ConsolidatedManifest struct {
	Entry          GraphEntry
	Subproject     Subproject
	DetectorName   string
	DetectorType   DetectorType
	RootManifestID string
}

// ConsolidatedGraph describes a merged view above per-subproject graph results.
type ConsolidatedGraph struct {
	ExecutionTarget ExecutionTarget
	Graphs          *GraphContainer
	Manifests       []ConsolidatedManifest
	Subprojects     []ConsolidatedSubproject
}

// ConsolidateGraphs merges resolved subproject graph containers while preserving manifest roots.
func ConsolidateGraphs(results []ResolveGraphResult) (ConsolidatedGraph, error) {
	consolidated := ConsolidatedGraph{
		Graphs:      &GraphContainer{},
		Manifests:   make([]ConsolidatedManifest, 0, len(results)),
		Subprojects: make([]ConsolidatedSubproject, 0, len(results)),
	}
	selectedTarget, selectedManifests, err := selectManifestEntries(results)
	if err != nil {
		return ConsolidatedGraph{}, err
	}
	consolidated.ExecutionTarget = selectedTarget
	consolidated.Manifests = selectedManifests

	subprojectIndex := make(map[string]int)
	for _, selected := range selectedManifests {
		consolidated.Graphs.Entries = append(consolidated.Graphs.Entries, selected.Entry)

		subprojectKey := consolidatedSubprojectKey(selected.Subproject, selected.DetectorName)
		idx, exists := subprojectIndex[subprojectKey]
		if !exists {
			subprojectIndex[subprojectKey] = len(consolidated.Subprojects)
			consolidated.Subprojects = append(consolidated.Subprojects, ConsolidatedSubproject{
				Subproject:      selected.Subproject,
				DetectorName:    selected.DetectorName,
				RootManifestIDs: []string{selected.RootManifestID},
			})
			continue
		}
		consolidated.Subprojects[idx].RootManifestIDs = append(consolidated.Subprojects[idx].RootManifestIDs, selected.RootManifestID)
	}
	return consolidated, nil
}

type consolidatedEntryCandidate struct {
	entry          GraphEntry
	subproject     Subproject
	detectorName   string
	detectorType   DetectorType
	rootManifestID string
	priority       int
}

func selectManifestEntries(results []ResolveGraphResult) (ExecutionTarget, []ConsolidatedManifest, error) {
	var executionTarget ExecutionTarget
	selectedEntries := make([]consolidatedEntryCandidate, 0)
	entryIndexByManifest := make(map[string]int)
	for _, result := range results {
		if result.Graphs == nil || result.Graphs.Len() == 0 {
			continue
		}
		candidateTarget := result.RootExecutionTarget
		if candidateTarget.Kind == "" {
			candidateTarget = result.SubprojectInfo.ExecutionTarget
		}
		if executionTarget.Kind == "" {
			executionTarget = candidateTarget
		} else if executionTarget != candidateTarget {
			return ExecutionTarget{}, nil, fmt.Errorf("cannot consolidate graphs from multiple execution targets")
		}

		for idx, entry := range result.Graphs.Entries {
			if err := validateGraphEntry(entry); err != nil {
				return ExecutionTarget{}, nil, fmt.Errorf("subproject %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}

			normalizedGraph, err := normalizeGraphPackageIdentity(entry.Graph)
			if err != nil {
				return ExecutionTarget{}, nil, fmt.Errorf("normalize graph identity for %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}
			manifest := normalizeSubprojectManifest(result.SubprojectInfo, entry.Manifest, idx, result.DetectorType, result.DetectorName)
			if err := ensureEntryRoot(normalizedGraph, manifest, idx); err != nil {
				return ExecutionTarget{}, nil, fmt.Errorf("ensure entry root for %s entry %d: %w", result.SubprojectInfo.RelativePath, idx, err)
			}
			candidate := consolidatedEntryCandidate{
				entry: GraphEntry{
					Graph:    normalizedGraph,
					Manifest: manifest,
				},
				subproject:     result.SubprojectInfo,
				detectorName:   result.DetectorName,
				detectorType:   result.DetectorType,
				rootManifestID: consolidatedEntryRootID(normalizedGraph, manifest, idx),
				priority:       ManifestDedupPriority(result.DetectorType, result.DetectorName),
			}

			manifestKey := manifestDedupKey(result.SubprojectInfo, manifest)
			existingIdx, exists := entryIndexByManifest[manifestKey]
			if !exists {
				entryIndexByManifest[manifestKey] = len(selectedEntries)
				selectedEntries = append(selectedEntries, candidate)
				continue
			}

			if candidate.priority < selectedEntries[existingIdx].priority {
				selectedEntries[existingIdx] = candidate
			}
		}
	}

	selectedManifests := make([]ConsolidatedManifest, 0, len(selectedEntries))
	for _, selected := range selectedEntries {
		selectedManifests = append(selectedManifests, ConsolidatedManifest{
			Entry:          selected.entry,
			Subproject:     selected.subproject,
			DetectorName:   selected.detectorName,
			DetectorType:   selected.detectorType,
			RootManifestID: selected.rootManifestID,
		})
	}
	return executionTarget, selectedManifests, nil
}

func normalizeSubprojectManifest(subproject Subproject, manifest ManifestMetadata, idx int, detectorType DetectorType, detectorName string) ManifestMetadata {
	if strings.TrimSpace(manifest.Path) == "" {
		manifest.Path = subprojectManifestPath(subproject, idx)
	}
	manifest.Path = strings.ReplaceAll(strings.TrimSpace(manifest.Path), "\\", "/")
	if isNativeDetector(detectorType, detectorName) {
		manifest.Path = normalizeNativeManifestPath(subproject, manifest.Path)
	}
	if strings.TrimSpace(manifest.Kind) == "" {
		manifest.Kind = subproject.PackageManager.Name()
	}
	manifest.Kind = strings.TrimSpace(manifest.Kind)
	return manifest
}

// ManifestDedupPriority returns the precedence rank used when multiple
// detectors resolve the same manifest. Lower values win.
//
// Priority order:
// 0. Native and lockfile-parser detectors
// 1. Plugin detectors and non-Syft third-party detectors
// 2. Syft fallback detector
func ManifestDedupPriority(detectorType DetectorType, detectorName string) int {
	switch effectiveDetectorType(detectorType, detectorName) {
	case NativeDetector, LockfileParserDetector:
		return 0
	case ThirdPartyDetector:
		if strings.EqualFold(strings.TrimSpace(detectorName), "syft-detector") {
			return 2
		}
		return 1
	case PluginDetector:
		return 1
	default:
		return 1
	}
}

func isNativeDetector(detectorType DetectorType, detectorName string) bool {
	effectiveType := effectiveDetectorType(detectorType, detectorName)
	return effectiveType == NativeDetector || effectiveType == LockfileParserDetector
}

func effectiveDetectorType(detectorType DetectorType, detectorName string) DetectorType {
	if detectorType != "" {
		return detectorType
	}
	if strings.EqualFold(strings.TrimSpace(detectorName), "syft-detector") {
		return ThirdPartyDetector
	}
	return NativeDetector
}

func normalizeNativeManifestPath(subproject Subproject, manifestPath string) string {
	if manifestPath == "" {
		return manifestPath
	}
	if !manifestPathIsAbs(manifestPath) {
		return filepath.ToSlash(manifestPath)
	}

	root := strings.TrimSpace(subproject.ExecutionTarget.Location)
	if root != "" {
		if rel, ok := pathRelativeToRoot(root, manifestPath); ok {
			return rel
		}
	}
	if strings.TrimSpace(subproject.ExecutionTarget.Location) != "" {
		if rel, ok := pathRelativeToRoot(subproject.ExecutionTarget.Location, manifestPath); ok {
			return rel
		}
	}
	return filepath.ToSlash(filepath.Base(manifestPath))
}

func pathRelativeToRoot(root, target string) (string, bool) {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == "" || rel == "." {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func manifestDedupKey(subproject Subproject, manifest ManifestMetadata) string {
	path := manifestDedupPath(subproject, manifest.Path)
	// kind := strings.TrimSpace(strings.ToLower(manifest.Kind))
	return path
}

func manifestDedupPath(subproject Subproject, manifestPath string) string {
	path := strings.TrimSpace(strings.ReplaceAll(manifestPath, "\\", "/"))
	if path == "" {
		return path
	}
	if !manifestPathIsAbs(path) {
		return path
	}
	if root := strings.TrimSpace(subproject.ExecutionTarget.Location); root != "" {
		if rel, ok := pathRelativeToRoot(root, path); ok {
			return rel
		}
	}
	if subproject.ExecutionTarget.Location != "" {
		if rel, ok := pathRelativeToRoot(subproject.ExecutionTarget.Location, path); ok {
			return rel
		}
	}
	return filepath.ToSlash(filepath.Base(path))
}

func manifestPathIsAbs(path string) bool {
	normalized := strings.TrimSpace(strings.ReplaceAll(path, "\\", "/"))
	return filepath.IsAbs(path) || strings.HasPrefix(normalized, "/")
}

func consolidatedSubprojectKey(subproject Subproject, detectorName string) string {
	return strings.Join([]string{subproject.RelativePath, subproject.PackageManager.Name(), detectorName, subproject.ExecutionTarget.Location}, "::")
}

func subprojectManifestPath(subproject Subproject, idx int) string {
	label := strings.TrimSpace(subproject.RelativePath)
	if label == "" || label == "." {
		label = strings.TrimSpace(subproject.ExecutionTarget.Location)
	}
	if label == "" {
		return fmt.Sprintf("entry-%d", idx+1)
	}
	return strings.ReplaceAll(label, "\\", "/")
}

func consolidatedEntryRootID(g *model.Graph, manifest ManifestMetadata, idx int) string {
	if g != nil {
		roots := g.Roots()
		if len(roots) > 0 && roots[0] != nil && strings.TrimSpace(roots[0].ID) != "" {
			return roots[0].ID
		}
		packages := g.Packages()
		if len(packages) > 0 && packages[0] != nil && strings.TrimSpace(packages[0].ID) != "" {
			return packages[0].ID
		}
	}
	if strings.TrimSpace(manifest.Path) != "" {
		return strings.TrimSpace(manifest.Path)
	}
	return fmt.Sprintf("entry-%d", idx+1)
}

func ensureEntryRoot(g *model.Graph, manifest ManifestMetadata, idx int) error {
	if g == nil || g.Size() == 0 {
		return nil
	}
	if hasSingleRoot(g) {
		return nil
	}

	rootID := virtualManifestRootID(g, manifest, idx)
	manifestLabel := strings.TrimSpace(manifest.Path)
	if manifestLabel == "" {
		manifestLabel = fmt.Sprintf("entry-%d", idx+1)
	}
	manifestLabel = strings.ReplaceAll(manifestLabel, "\\", "/")

	kind := strings.TrimSpace(manifest.Kind)
	if kind == "" {
		kind = "manifest"
	}

	virtualRoot := model.NewPackageWithID(rootID, model.Package{
		Name:        manifestLabel,
		Type:        "manifest",
		BuildSystem: kind,
	})
	if err := addPackageIfMissing(g, virtualRoot); err != nil {
		return err
	}

	targets := g.Roots()
	if len(targets) == 0 {
		targets = g.Packages()
	}
	for _, target := range targets {
		if target == nil || target.ID == rootID {
			continue
		}
		if err := g.AddDependency(rootID, target.ID); err != nil {
			if errors.Is(err, model.ErrSelfDependency) {
				continue
			}
			return fmt.Errorf("attach virtual root %q -> %q: %w", rootID, target.ID, err)
		}
	}

	return nil
}

func hasSingleRoot(g *model.Graph) bool {
	if g == nil {
		return false
	}
	roots := g.Roots()
	return len(roots) == 1 && roots[0] != nil && strings.TrimSpace(roots[0].ID) != ""
}

func virtualManifestRootID(g *model.Graph, manifest ManifestMetadata, idx int) string {
	base := strings.TrimSpace(manifest.Path)
	if base == "" {
		base = fmt.Sprintf("entry-%d", idx+1)
	}
	base = strings.ReplaceAll(base, "\\", "/")

	if _, exists := g.Package(base); !exists {
		return base
	}

	candidate := "manifest:" + base
	if _, exists := g.Package(candidate); !exists {
		return candidate
	}

	for i := 2; ; i++ {
		next := fmt.Sprintf("%s#%d", candidate, i)
		if _, exists := g.Package(next); !exists {
			return next
		}
	}
}

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
		normalization.NormalizePackageIdentity(clone)
		canonicalPURL := packagePURL(clone)
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

func packagePURL(pkg *model.Package) string {
	if pkg == nil {
		return ""
	}
	if strings.TrimSpace(pkg.PURL) != "" {
		return strings.TrimSpace(pkg.PURL)
	}
	if strings.EqualFold(strings.TrimSpace(pkg.Type), "manifest") {
		return ""
	}

	name := strings.TrimSpace(pkg.Name)
	if name == "" {
		return ""
	}

	purlType := purlTypeForPackage(pkg)
	namespace := strings.TrimSpace(pkg.Org)
	if purlType == "golang" && namespace == "" {
		parts := strings.Split(strings.ReplaceAll(name, "\\", "/"), "/")
		if len(parts) > 1 {
			namespace = strings.Join(parts[:len(parts)-1], "/")
			name = parts[len(parts)-1]
		}
	}

	builder := strings.Builder{}
	builder.WriteString("pkg:")
	builder.WriteString(strings.ToLower(purlType))
	builder.WriteRune('/')
	if namespace != "" {
		builder.WriteString(strings.ReplaceAll(strings.Trim(namespace, "/"), "\\", "/"))
		builder.WriteRune('/')
	}
	builder.WriteString(strings.ReplaceAll(strings.Trim(name, "/"), "\\", "/"))
	if strings.TrimSpace(pkg.Version) != "" {
		builder.WriteRune('@')
		builder.WriteString(strings.TrimSpace(pkg.Version))
	}
	return builder.String()
}

func canonicalPackageKey(pkg *model.Package) string {
	if pkg == nil {
		return ""
	}
	if purl := packagePURL(pkg); purl != "" {
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

func SyncConsolidatedEnrichmentToManifests(consolidated *ConsolidatedGraph, graph *model.Graph) {
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

func purlTypeForPackage(pkg *model.Package) string {
	if pkg == nil {
		return "generic"
	}
	candidates := []string{pkg.Ecosystem, pkg.BuildSystem, pkg.Type}
	for _, value := range candidates {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		switch normalized {
		case "go", "gomod":
			return "golang"
		default:
			return normalized
		}
	}
	return "generic"
}

func mergeGraph(dst, src *model.Graph) error {
	if dst == nil || src == nil {
		return nil
	}
	var mergeErr error
	src.WalkPackages(func(pkg *model.Package) bool {
		if err := addPackageIfMissing(dst, pkg); err != nil {
			mergeErr = err
			return false
		}
		return true
	})
	if mergeErr != nil {
		return mergeErr
	}
	src.WalkRelationships(func(from, to *model.Package) bool {
		if err := dst.AddDependency(from.ID, to.ID); err != nil {
			mergeErr = fmt.Errorf("merge relationship %q -> %q: %w", from.ID, to.ID, err)
			return false
		}
		return true
	})
	return mergeErr
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
