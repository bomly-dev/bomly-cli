package viewmodel

import (
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly/bomly-cli/internal/explain"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/normalization"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/scan"
)

// ScanResponse is the structured payload for the scan command.
type ScanResponse struct {
	SchemaVersion string                   `json:"schema_version"`
	Command       string                   `json:"command"`
	Project       output.ProjectDescriptor `json:"project"`
	Manifests     []ScanManifest           `json:"manifests"`
	Findings      []AuditFinding           `json:"findings,omitempty"`
	AuditSummary  *AuditSummary            `json:"audit_summary,omitempty"`
	Metadata      output.Metadata          `json:"metadata"`
}

// ScanManifest is one manifest-scoped dependency inventory in the scan payload.
type ScanManifest struct {
	Path           string        `json:"path,omitempty"`
	Kind           string        `json:"kind,omitempty"`
	Subproject     string        `json:"subproject,omitempty"`
	Ecosystem      string        `json:"ecosystem,omitempty"`
	PackageManager string        `json:"package_manager,omitempty"`
	Detector       string        `json:"detector,omitempty"`
	Packages       []ScanPackage `json:"packages"`
}

// AuditFinding is the serialized form of one normalized scan finding.
type AuditFinding struct {
	ID       string            `json:"id"`
	Kind     string            `json:"kind"`
	Severity string            `json:"severity"`
	Package  output.PackageRef `json:"package"`
	Title    string            `json:"title"`
	Reasons  []string          `json:"reasons,omitempty"`
	Source   string            `json:"source"`
}

// AuditSummary aggregates finding counts by severity.
type AuditSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// ScanTargetResponse represents one target-specific scan payload.
type ScanTargetResponse struct {
	Project  output.ProjectDescriptor `json:"project"`
	Detector string                   `json:"detector,omitempty"`
	Packages []ScanPackage            `json:"packages"`
}

// ScanPackage is one dependency plus its direct dependency IDs.
type ScanPackage struct {
	output.PackageRef
	Dependencies []string `json:"dependencies"`
}

// DiffResponse is the structured payload for the diff command.
type DiffResponse struct {
	SchemaVersion string                   `json:"schema_version"`
	Command       string                   `json:"command"`
	Project       output.ProjectDescriptor `json:"project"`
	Comparison    DiffComparison           `json:"comparison"`
	Results       DiffResults              `json:"results"`
	Summary       DiffSummary              `json:"summary"`
	Audit         *DiffAudit               `json:"audit,omitempty"`
	Metadata      output.Metadata          `json:"metadata"`
}

// DiffAudit groups audit deltas for diff output.
type DiffAudit struct {
	Introduced   []AuditFinding `json:"introduced,omitempty"`
	Resolved     []AuditFinding `json:"resolved,omitempty"`
	Persisted    []AuditFinding `json:"persisted,omitempty"`
	AuditSummary *AuditSummary  `json:"audit_summary,omitempty"`
}

// DiffComparison identifies the compared dependency states.
type DiffComparison struct {
	Base string `json:"base"`
	Head string `json:"head"`
}

// DiffResults groups per-manifest diff results.
type DiffResults struct {
	Manifests []DiffManifestResult `json:"manifests"`
}

// DiffPackageChange is one added or removed package.
type DiffPackageChange struct {
	Package output.PackageRef `json:"package"`
}

// DiffChangedPackage is one version-changed package.
type DiffChangedPackage struct {
	After  output.PackageRef `json:"after"`
	Before output.PackageRef `json:"before"`
}

// DiffManifestResult describes changes for one manifest.
type DiffManifestResult struct {
	Status         string               `json:"status"`
	Path           string               `json:"path,omitempty"`
	Kind           string               `json:"kind,omitempty"`
	Subproject     string               `json:"subproject,omitempty"`
	Ecosystem      string               `json:"ecosystem,omitempty"`
	PackageManager string               `json:"package_manager,omitempty"`
	Added          []DiffPackageChange  `json:"added,omitempty"`
	Removed        []DiffPackageChange  `json:"removed,omitempty"`
	Changed        []DiffChangedPackage `json:"changed,omitempty"`
}

// DiffSummary aggregates manifest and package counts for a diff.
type DiffSummary struct {
	AddedManifestCount     int `json:"added_manifest_count"`
	ChangedManifestCount   int `json:"changed_manifest_count"`
	RemovedManifestCount   int `json:"removed_manifest_count"`
	UnchangedManifestCount int `json:"unchanged_manifest_count"`
	AddedPackageCount      int `json:"added_package_count"`
	ChangedPackageCount    int `json:"changed_package_count"`
	RemovedPackageCount    int `json:"removed_package_count"`
}

// ExplainResponse is the structured payload for the explain command.
type ExplainResponse struct {
	SchemaVersion string                   `json:"schema_version"`
	Command       string                   `json:"command"`
	Project       output.ProjectDescriptor `json:"project"`
	Query         ExplainQuery             `json:"query"`
	Dependency    output.PackageRef        `json:"dependency,omitempty"`
	Paths         []explain.Path           `json:"paths,omitempty"`
	Findings      []AuditFinding           `json:"findings,omitempty"`
	AuditSummary  *AuditSummary            `json:"audit_summary,omitempty"`
	Targets       []ExplainTargetResponse  `json:"targets,omitempty"`
	Metadata      output.Metadata          `json:"metadata"`
}

// ExplainQuery records the user query issued to the explain command.
type ExplainQuery struct {
	Name string `json:"name"`
}

// ExplainTargetResponse represents explain output for one resolved target.
type ExplainTargetResponse struct {
	Project      output.ProjectDescriptor `json:"project"`
	Detector     string                   `json:"detector,omitempty"`
	Dependency   output.PackageRef        `json:"dependency"`
	Paths        []explain.Path           `json:"paths"`
	Findings     []AuditFinding           `json:"findings,omitempty"`
	AuditSummary *AuditSummary            `json:"audit_summary,omitempty"`
}

// BuildScanResponse constructs the structured scan payload from consolidated
// manifest selections and findings.
func BuildScanResponse(project output.ProjectDescriptor, consolidated scan.ConsolidatedGraph, findings []scan.Finding, started time.Time) ScanResponse {
	response := ScanResponse{
		SchemaVersion: output.SchemaVersion,
		Command:       "scan",
		Project:       project,
		Manifests:     ScanManifestsFromConsolidated(consolidated),
		Metadata:      output.Metadata{DurationMS: time.Since(started).Milliseconds()},
	}
	if len(findings) > 0 {
		response.Findings = FindingsFromScan(findings)
		response.AuditSummary = SummaryFromFindings(findings)
	}
	return response
}

// ScanManifestsFromConsolidated converts consolidated manifest selections into
// stable scan payloads.
func ScanManifestsFromConsolidated(consolidated scan.ConsolidatedGraph) []ScanManifest {
	manifests := make([]ScanManifest, 0, len(consolidated.Manifests))
	for idx, manifest := range consolidated.Manifests {
		if manifest.Entry.Graph == nil {
			continue
		}
		manifests = append(manifests, scanManifestFromConsolidated(manifest, idx))
	}
	sort.Slice(manifests, func(i, j int) bool {
		if manifests[i].Subproject != manifests[j].Subproject {
			return manifests[i].Subproject < manifests[j].Subproject
		}
		if manifests[i].Path != manifests[j].Path {
			return manifests[i].Path < manifests[j].Path
		}
		if manifests[i].PackageManager != manifests[j].PackageManager {
			return manifests[i].PackageManager < manifests[j].PackageManager
		}
		return manifests[i].Kind < manifests[j].Kind
	})
	return manifests
}

func scanManifestFromConsolidated(manifest scan.ConsolidatedManifest, idx int) ScanManifest {
	kind := strings.TrimSpace(manifest.Entry.Manifest.Kind)
	if kind == "" {
		kind = "entry-" + strconv.Itoa(idx+1)
	}
	return ScanManifest{
		Path:           normalizeScanManifestPath(manifest.Subproject, diffManifestPath(manifest.Subproject, manifest.Entry.Manifest), manifest.Entry.Manifest.Path),
		Kind:           kind,
		Subproject:     manifest.Subproject.RelativePath,
		Ecosystem:      string(manifest.Subproject.Ecosystem),
		PackageManager: manifest.Subproject.PackageManager.Name(),
		Detector:       manifest.DetectorName,
		Packages:       PackagesFromGraph(manifest.Entry.Graph),
	}
}

func normalizeScanManifestPath(subproject scan.Subproject, candidates ...string) string {
	for _, candidate := range candidates {
		normalized := strings.TrimSpace(strings.ReplaceAll(candidate, "\\", "/"))
		if normalized == "" {
			continue
		}
		if rel, ok := normalizeManifestPathAgainstBase(subproject.ExecutionTarget.Location, normalized); ok {
			return rel
		}
		if rel, ok := normalizeManifestPathAgainstBase(subproject.ExecutionTarget.Location, normalized); ok {
			return rel
		}
		return strings.TrimPrefix(normalized, "./")
	}
	return ""
}

func normalizeManifestPathAgainstBase(basePath, candidate string) (string, bool) {
	base := strings.TrimSpace(strings.ReplaceAll(basePath, "\\", "/"))
	if base == "" {
		return "", false
	}
	base = strings.TrimSuffix(base, "/")
	switch {
	case candidate == base:
		return "", true
	case strings.HasPrefix(candidate, base+"/"):
		return strings.TrimPrefix(candidate[len(base):], "/"), true
	default:
		return "", false
	}
}

// BuildExplainResponse constructs the structured explain payload from resolved targets.
func BuildExplainResponse(project output.ProjectDescriptor, query string, targets []ExplainTargetResponse, started time.Time) ExplainResponse {
	response := ExplainResponse{
		SchemaVersion: output.SchemaVersion,
		Command:       "explain",
		Project:       project,
		Query:         ExplainQuery{Name: query},
		Targets:       targets,
		Metadata:      output.Metadata{DurationMS: time.Since(started).Milliseconds()},
	}
	if len(targets) == 1 {
		response.Dependency = targets[0].Dependency
		response.Paths = targets[0].Paths
		response.Findings = targets[0].Findings
		response.AuditSummary = targets[0].AuditSummary
	}
	return response
}

// PackagesFromGraph converts a graph into stable scan package payloads.
func PackagesFromGraph(g *model.Graph) []ScanPackage {
	if g == nil {
		return nil
	}

	packages := g.Packages()
	payload := make([]ScanPackage, 0, len(packages))
	for _, pkg := range packages {
		deps, err := g.Dependencies(pkg.ID)
		dependencyIDs := make([]string, 0, len(deps))
		if err == nil {
			for _, dep := range deps {
				if dep == nil {
					continue
				}
				dependencyIDs = append(dependencyIDs, dep.ID)
			}
		}
		payload = append(payload, ScanPackage{
			PackageRef:   output.PackageFromGraphPackage(pkg),
			Dependencies: dependencyIDs,
		})
	}
	sort.Slice(payload, func(i, j int) bool {
		return payload[i].ID < payload[j].ID
	})
	for idx := range payload {
		sort.Strings(payload[idx].Dependencies)
	}
	return payload
}

// FindingsFromScan converts normalized findings into JSON-friendly DTOs.
func FindingsFromScan(findings []scan.Finding) []AuditFinding {
	result := make([]AuditFinding, 0, len(findings))
	for _, f := range findings {
		result = append(result, AuditFinding{
			ID:       f.ID,
			Kind:     string(f.Kind),
			Severity: f.Severity,
			Package:  output.PackageFromGraphPackage(f.Package),
			Title:    f.Title,
			Reasons:  f.Reasons,
			Source:   f.Source,
		})
	}
	return result
}

// SummaryFromFindings aggregates finding counts by severity band.
func SummaryFromFindings(findings []scan.Finding) *AuditSummary {
	s := &AuditSummary{}
	for _, f := range findings {
		s.Total++
		switch f.Severity {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		default:
			s.Unknown++
		}
	}
	return s
}

// BuildDiffResponse constructs the structured diff payload from consolidated manifest selections.
func BuildDiffResponse(projectPath, baseRef, headRef string, baseConsolidated, headConsolidated scan.ConsolidatedGraph, audit *DiffAudit, started time.Time) DiffResponse {
	results, summary := diffResultsFromConsolidated(baseConsolidated, headConsolidated)
	return DiffResponse{
		SchemaVersion: output.SchemaVersion,
		Command:       "diff",
		Project: output.ProjectDescriptor{
			Name:           filepathBase(projectPath),
			Path:           projectPath,
			Ecosystem:      "multiple",
			PackageManager: "multiple",
		},
		Comparison: DiffComparison{Base: baseRef, Head: headRef},
		Results:    results,
		Summary:    summary,
		Audit:      audit,
		Metadata:   output.Metadata{DurationMS: time.Since(started).Milliseconds()},
	}
}

type diffManifestSnapshot struct {
	Key      string
	Manifest diffManifestRef
	Graph    *model.Graph
}

type diffManifestRef struct {
	Path           string
	Kind           string
	Subproject     string
	Ecosystem      string
	PackageManager string
}

func diffResultsFromConsolidated(baseConsolidated, headConsolidated scan.ConsolidatedGraph) (DiffResults, DiffSummary) {
	baseByKey := manifestSnapshotsByConsolidated(baseConsolidated)
	headByKey := manifestSnapshotsByConsolidated(headConsolidated)
	keys := make([]string, 0, len(baseByKey)+len(headByKey))
	seen := make(map[string]struct{}, len(baseByKey)+len(headByKey))
	for key := range baseByKey {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range headByKey {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	results := DiffResults{Manifests: make([]DiffManifestResult, 0, len(keys))}
	summary := DiffSummary{}
	for _, key := range keys {
		baseManifest, hasBase := baseByKey[key]
		headManifest, hasHead := headByKey[key]

		switch {
		case !hasBase && hasHead:
			result := DiffManifestResult{
				Status:         "added",
				Path:           headManifest.Manifest.Path,
				Kind:           headManifest.Manifest.Kind,
				Subproject:     headManifest.Manifest.Subproject,
				Ecosystem:      headManifest.Manifest.Ecosystem,
				PackageManager: headManifest.Manifest.PackageManager,
				Added:          diffPackageChangesFromPackages(headManifest.Graph.Packages()),
			}
			results.Manifests = append(results.Manifests, result)
			summary.AddedManifestCount++
			summary.AddedPackageCount += len(result.Added)
		case hasBase && !hasHead:
			result := DiffManifestResult{
				Status:         "removed",
				Path:           baseManifest.Manifest.Path,
				Kind:           baseManifest.Manifest.Kind,
				Subproject:     baseManifest.Manifest.Subproject,
				Ecosystem:      baseManifest.Manifest.Ecosystem,
				PackageManager: baseManifest.Manifest.PackageManager,
				Removed:        diffPackageChangesFromPackages(baseManifest.Graph.Packages()),
			}
			results.Manifests = append(results.Manifests, result)
			summary.RemovedManifestCount++
			summary.RemovedPackageCount += len(result.Removed)
		case hasBase && hasHead:
			manifestDiff := model.Compare(baseManifest.Graph, headManifest.Graph)
			reconcileDiffWithFuzzyMatches(&manifestDiff)
			result := DiffManifestResult{
				Status:         "unchanged",
				Path:           headManifest.Manifest.Path,
				Kind:           headManifest.Manifest.Kind,
				Subproject:     headManifest.Manifest.Subproject,
				Ecosystem:      headManifest.Manifest.Ecosystem,
				PackageManager: headManifest.Manifest.PackageManager,
				Added:          diffPackageChangesFromPackages(manifestDiff.Added),
				Removed:        diffPackageChangesFromPackages(manifestDiff.Removed),
				Changed:        diffChangedPackagesFromDiff(manifestDiff.Updated),
			}
			if len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Changed) == 0 {
				summary.UnchangedManifestCount++
			} else {
				result.Status = "changed"
				summary.ChangedManifestCount++
				summary.AddedPackageCount += len(result.Added)
				summary.ChangedPackageCount += len(result.Changed)
				summary.RemovedPackageCount += len(result.Removed)
			}
			results.Manifests = append(results.Manifests, result)
		}
	}
	sort.Slice(results.Manifests, func(i, j int) bool {
		left := results.Manifests[i]
		right := results.Manifests[j]
		if left.Status != right.Status {
			return diffManifestStatusOrder(left.Status) < diffManifestStatusOrder(right.Status)
		}
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.PackageManager != right.PackageManager {
			return left.PackageManager < right.PackageManager
		}
		return left.Subproject < right.Subproject
	})

	return results, summary
}

func diffManifestStatusOrder(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "removed":
		return 0
	case "added":
		return 1
	case "changed":
		return 2
	case "unchanged":
		return 3
	default:
		return 99
	}
}

func manifestSnapshotsByConsolidated(consolidated scan.ConsolidatedGraph) map[string]diffManifestSnapshot {
	snapshots := make(map[string]diffManifestSnapshot)
	for idx, manifest := range consolidated.Manifests {
		if manifest.Entry.Graph == nil {
			continue
		}
		manifestRef := diffManifestRefFromConsolidated(manifest, idx)
		key := diffManifestKeyForConsolidated(manifest, manifestRef, idx)
		snapshots[key] = diffManifestSnapshot{
			Key:      key,
			Manifest: manifestRef,
			Graph:    manifest.Entry.Graph,
		}
	}
	return snapshots
}

func diffManifestRefFromConsolidated(manifest scan.ConsolidatedManifest, idx int) diffManifestRef {
	pathValue := normalizeScanManifestPath(manifest.Subproject, diffManifestPath(manifest.Subproject, manifest.Entry.Manifest), manifest.Entry.Manifest.Path)
	kind := strings.TrimSpace(manifest.Entry.Manifest.Kind)
	if kind == "" {
		kind = "entry-" + strconv.Itoa(idx+1)
	}
	return diffManifestRef{
		Path:           pathValue,
		Kind:           kind,
		Subproject:     manifest.Subproject.RelativePath,
		Ecosystem:      string(manifest.Subproject.Ecosystem),
		PackageManager: manifest.Subproject.PackageManager.Name(),
	}
}

func diffManifestPath(subproject scan.Subproject, manifest scan.ManifestMetadata) string {
	rawPath := strings.TrimSpace(manifest.Path)
	if rawPath == "" {
		if subproject.RelativePath == "." {
			return ""
		}
		return filepath.ToSlash(subproject.RelativePath)
	}

	normalized := filepath.ToSlash(rawPath)
	if filepath.IsAbs(rawPath) {
		if rel, ok := relativeManifestPath(subproject.ExecutionTarget.Location, rawPath); ok {
			normalized = rel
		}
	}
	normalized = strings.TrimPrefix(normalized, "./")

	subprojectPath := filepath.ToSlash(subproject.RelativePath)
	switch {
	case subprojectPath == "", subprojectPath == ".":
		return normalized
	case normalized == "", normalized == ".":
		return subprojectPath
	case normalized == subprojectPath || strings.HasPrefix(normalized, subprojectPath+"/"):
		return normalized
	default:
		return filepath.ToSlash(filepath.Join(subproject.RelativePath, filepath.FromSlash(normalized)))
	}
}

func relativeManifestPath(basePath, targetPath string) (string, bool) {
	if strings.TrimSpace(basePath) == "" || strings.TrimSpace(targetPath) == "" {
		return "", false
	}
	relPath, err := filepath.Rel(basePath, targetPath)
	if err != nil {
		return "", false
	}
	if relPath == ".." || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(relPath), true
}

func diffManifestKey(manifest diffManifestRef, idx int) string {
	pathValue := manifest.Path
	if strings.TrimSpace(pathValue) == "" {
		pathValue = "entry-" + strconv.Itoa(idx+1)
	}
	subproject := manifest.Subproject
	if subproject == "" {
		subproject = "."
	}
	return strings.Join([]string{subproject, manifest.PackageManager, manifest.Kind, pathValue}, "::")
}

func diffManifestKeyForConsolidated(manifest scan.ConsolidatedManifest, ref diffManifestRef, idx int) string {
	if !isSBOMManifest(manifest.Subproject) {
		return diffManifestKey(ref, idx)
	}

	if key, ok := derivedSBOMManifestKey(manifest, ref); ok {
		return key
	}

	return strings.Join([]string{
		"sbom",
		manifest.Subproject.PackageManager.Name(),
		"synthetic-manifest",
	}, "::")
}

func derivedSBOMManifestKey(manifest scan.ConsolidatedManifest, ref diffManifestRef) (string, bool) {
	pathValue := strings.TrimSpace(strings.ReplaceAll(ref.Path, "\\", "/"))
	if pathValue == "" || !sbomManifestPathLooksDerived(manifest, pathValue) {
		return "", false
	}
	return strings.Join([]string{
		"sbom",
		manifest.Subproject.PackageManager.Name(),
		pathValue,
	}, "::"), true
}

func sbomManifestPathLooksDerived(manifest scan.ConsolidatedManifest, candidate string) bool {
	if candidate == "" {
		return false
	}

	subprojectRelative := strings.TrimSpace(strings.ReplaceAll(manifest.Subproject.RelativePath, "\\", "/"))
	executionBase := filepathBase(manifest.Subproject.ExecutionTarget.Location)
	subprojectBase := filepathBase(subprojectRelative)
	rawManifestPath := strings.TrimSpace(strings.ReplaceAll(manifest.Entry.Manifest.Path, "\\", "/"))

	for _, fallback := range []string{
		subprojectRelative,
		executionBase,
		subprojectBase,
		rawManifestPath,
		filepathBase(rawManifestPath),
	} {
		fallback = strings.TrimSpace(strings.ReplaceAll(fallback, "\\", "/"))
		if fallback != "" && candidate == fallback {
			return false
		}
	}

	return true
}

func isSBOMManifest(subproject scan.Subproject) bool {
	return subproject.PackageManager == scan.PackageManagerSBOM || subproject.Ecosystem == scan.EcosystemSBOM
}

func diffPackageChangesFromPackages(packages []*model.Package) []DiffPackageChange {
	changes := make([]DiffPackageChange, 0, len(packages))
	for _, pkg := range packages {
		changes = append(changes, DiffPackageChange{Package: output.PackageFromGraphPackage(pkg)})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Package.ID < changes[j].Package.ID })
	return changes
}

func diffChangedPackagesFromDiff(changes []model.VersionChange) []DiffChangedPackage {
	out := make([]DiffChangedPackage, 0, len(changes))
	for _, change := range changes {
		out = append(out, DiffChangedPackage{
			After:  output.PackageFromGraphPackage(change.After),
			Before: output.PackageFromGraphPackage(change.Before),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].After.ID < out[j].After.ID })
	return out
}

const (
	diffFuzzyReconciledKey = "bomly.diff.fuzzy_reconciled"
	diffFuzzyScoreKey      = "bomly.diff.fuzzy_score"
	diffFuzzyTierKey       = "bomly.diff.fuzzy_tier"
)

func reconcileDiffWithFuzzyMatches(diff *model.Diff) {
	if diff == nil || len(diff.Added) == 0 || len(diff.Removed) == 0 {
		return
	}

	type candidate struct {
		addedIdx   int
		removedIdx int
		score      float64
		tier       string
	}

	candidates := make([]candidate, 0)
	for removedIdx, removed := range diff.Removed {
		for addedIdx, added := range diff.Added {
			score, tier := fuzzyReconcileScore(removed, added)
			if score < 0.90 {
				continue
			}
			candidates = append(candidates, candidate{addedIdx: addedIdx, removedIdx: removedIdx, score: score, tier: tier})
		}
	}

	if len(candidates) == 0 {
		return
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		if candidates[i].removedIdx != candidates[j].removedIdx {
			return candidates[i].removedIdx < candidates[j].removedIdx
		}
		return candidates[i].addedIdx < candidates[j].addedIdx
	})

	matchedAdded := make(map[int]struct{}, len(diff.Added))
	matchedRemoved := make(map[int]struct{}, len(diff.Removed))
	for _, match := range candidates {
		if _, ok := matchedAdded[match.addedIdx]; ok {
			continue
		}
		if _, ok := matchedRemoved[match.removedIdx]; ok {
			continue
		}

		after := diff.Added[match.addedIdx]
		before := diff.Removed[match.removedIdx]
		applyFuzzyMetadata(before, after, match.score, match.tier)
		diff.Updated = append(diff.Updated, model.VersionChange{Before: before, After: after})
		matchedAdded[match.addedIdx] = struct{}{}
		matchedRemoved[match.removedIdx] = struct{}{}
	}

	if len(matchedAdded) == 0 {
		return
	}

	remainingAdded := make([]*model.Package, 0, len(diff.Added)-len(matchedAdded))
	for idx, pkg := range diff.Added {
		if _, ok := matchedAdded[idx]; ok {
			continue
		}
		remainingAdded = append(remainingAdded, pkg)
	}
	remainingRemoved := make([]*model.Package, 0, len(diff.Removed)-len(matchedRemoved))
	for idx, pkg := range diff.Removed {
		if _, ok := matchedRemoved[idx]; ok {
			continue
		}
		remainingRemoved = append(remainingRemoved, pkg)
	}
	diff.Added = remainingAdded
	diff.Removed = remainingRemoved

	sort.Slice(diff.Updated, func(i, j int) bool {
		left := diff.Updated[i]
		right := diff.Updated[j]
		if left.Before.IdentityKey() != right.Before.IdentityKey() {
			return left.Before.IdentityKey() < right.Before.IdentityKey()
		}
		if left.Before.Version != right.Before.Version {
			return left.Before.Version < right.Before.Version
		}
		if left.After.Version != right.After.Version {
			return left.After.Version < right.After.Version
		}
		return left.Before.ID < right.Before.ID
	})
}

func fuzzyReconcileScore(before, after *model.Package) (float64, string) {
	if before == nil || after == nil {
		return 0, ""
	}
	if !sameEcosystemForFuzzy(before, after) {
		return 0, ""
	}

	beforeNorm := before.Clone()
	afterNorm := after.Clone()
	normalization.NormalizePackageIdentity(beforeNorm)
	normalization.NormalizePackageIdentity(afterNorm)

	if purlBase(beforeNorm.PURL) != "" && purlBase(beforeNorm.PURL) == purlBase(afterNorm.PURL) {
		return 1.0, "purl-base"
	}

	if beforeNorm.IdentityKey() == afterNorm.IdentityKey() {
		return 0.97, "normalized-identity"
	}

	nameScore := normalizedSimilarity(beforeNorm.Name, afterNorm.Name)
	beforeOrg := strings.TrimSpace(beforeNorm.Org)
	afterOrg := strings.TrimSpace(afterNorm.Org)
	if beforeOrg == "" && afterOrg == "" {
		return nameScore, "name-similarity"
	}
	orgScore := 0.0
	if strings.EqualFold(beforeOrg, afterOrg) {
		orgScore = 1.0
	}
	final := nameScore*0.85 + orgScore*0.15
	return final, "name-similarity"
}

func sameEcosystemForFuzzy(before, after *model.Package) bool {
	b := strings.ToLower(strings.TrimSpace(before.Ecosystem))
	a := strings.ToLower(strings.TrimSpace(after.Ecosystem))
	if b == "" || a == "" {
		return true
	}
	return b == a
}

func purlBase(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if q := strings.Index(value, "?"); q >= 0 {
		value = value[:q]
	}
	at := strings.LastIndex(value, "@")
	if at <= 0 {
		return value
	}
	return value[:at]
}

func normalizedSimilarity(left, right string) float64 {
	left = strings.ToLower(strings.TrimSpace(left))
	right = strings.ToLower(strings.TrimSpace(right))
	if left == "" || right == "" {
		return 0
	}
	if left == right {
		return 1
	}
	if collapseComparableName(left) == collapseComparableName(right) {
		return 0.96
	}
	dist := levenshteinDistance(left, right)
	maxLen := maxInt(len(left), len(right))
	if maxLen == 0 {
		return 0
	}
	score := 1 - float64(dist)/float64(maxLen)
	if score < 0 {
		return 0
	}
	return math.Min(score, 1)
}

func collapseComparableName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "", "_", "", ".", "", " ", "")
	return replacer.Replace(value)
}

func levenshteinDistance(a, b string) int {
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	prev := make([]int, len(b)+1)
	curr := make([]int, len(b)+1)
	for j := 0; j <= len(b); j++ {
		prev[j] = j
	}

	for i := 1; i <= len(a); i++ {
		curr[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			curr[j] = minInt(
				curr[j-1]+1,
				prev[j]+1,
				prev[j-1]+cost,
			)
		}
		prev, curr = curr, prev
	}
	return prev[len(b)]
}

func minInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	best := values[0]
	for _, value := range values[1:] {
		if value < best {
			best = value
		}
	}
	return best
}

func maxInt(values ...int) int {
	if len(values) == 0 {
		return 0
	}
	best := values[0]
	for _, value := range values[1:] {
		if value > best {
			best = value
		}
	}
	return best
}

func applyFuzzyMetadata(before, after *model.Package, score float64, tier string) {
	roundedScore := math.Round(score*1000) / 1000
	for _, pkg := range []*model.Package{before, after} {
		if pkg == nil {
			continue
		}
		if pkg.Metadata == nil {
			pkg.Metadata = make(map[string]any, 3)
		}
		pkg.Metadata[diffFuzzyReconciledKey] = true
		pkg.Metadata[diffFuzzyScoreKey] = roundedScore
		pkg.Metadata[diffFuzzyTierKey] = tier
	}
}

func filepathBase(path string) string {
	path = strings.TrimRight(path, "/\\")
	if path == "" {
		return path
	}
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}
