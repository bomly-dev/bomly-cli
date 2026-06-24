package output

import (
	"math"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// ScanResponse is the structured payload for the scan command. It surfaces the
// three-collection model: manifests carry lean detection-stage dependencies,
// packages is the deduplicated matching-stage registry projection, and findings
// is the reference-style audit output.
type ScanResponse struct {
	SchemaVersion string             `json:"schema_version"`
	Command       string             `json:"command"`
	Project       ProjectDescriptor  `json:"project"`
	Manifests     []ScanManifest     `json:"manifests"`
	Packages      []ScanPackageEntry `json:"packages"`
	Findings      []AuditFinding     `json:"findings,omitempty"`
	AuditSummary  *AuditSummary      `json:"audit_summary,omitempty"`
	Metadata      Metadata           `json:"metadata"`
}

// ScanManifest is one manifest-scoped dependency inventory in the scan payload.
type ScanManifest struct {
	Path           string             `json:"path,omitempty"`
	Kind           sdk.ManifestKind   `json:"kind,omitempty"`
	Subproject     string             `json:"subproject,omitempty"`
	Ecosystem      sdk.Ecosystem      `json:"ecosystem,omitempty"`
	PackageManager sdk.PackageManager `json:"package_manager,omitempty"`
	Detector       string             `json:"detector,omitempty"`
	Dependencies   []ScanDependency   `json:"dependencies"`
}

// DiffResponse is the structured payload for the diff command.
type DiffResponse struct {
	SchemaVersion string            `json:"schema_version"`
	Command       string            `json:"command"`
	Project       ProjectDescriptor `json:"project"`
	Comparison    DiffComparison    `json:"comparison"`
	Results       DiffResults       `json:"results"`
	Summary       DiffSummary       `json:"summary"`
	Audit         *DiffAudit        `json:"audit,omitempty"`
	Metadata      Metadata          `json:"metadata"`
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
	Dependencies    DiffDependencyResults    `json:"dependencies"`
	Licenses        DiffLicenseResults       `json:"licenses"`
	Vulnerabilities DiffVulnerabilityResults `json:"vulnerabilities"`
	Manifests       []DiffManifestResult     `json:"manifests"`
}

// DiffDependencyResults aggregates package changes across all manifests.
type DiffDependencyResults struct {
	Added   []DiffPackageChange  `json:"added,omitempty"`
	Removed []DiffPackageChange  `json:"removed,omitempty"`
	Changed []DiffChangedPackage `json:"changed,omitempty"`
}

// DiffLicenseResults aggregates license changes across all manifests.
type DiffLicenseResults struct {
	Added   []DiffLicenseChange `json:"added,omitempty"`
	Removed []DiffLicenseChange `json:"removed,omitempty"`
	Changed []DiffLicenseDelta  `json:"changed,omitempty"`
}

// DiffLicenseChange is a package whose license set was introduced or removed.
type DiffLicenseChange struct {
	Package  PackageRef   `json:"package"`
	Licenses []LicenseRef `json:"licenses"`
}

// DiffLicenseDelta is a package whose license set changed.
type DiffLicenseDelta struct {
	Package PackageRef   `json:"package"`
	Before  []LicenseRef `json:"before"`
	After   []LicenseRef `json:"after"`
}

// DiffVulnerabilityResults aggregates vulnerability changes across all manifests.
// Persisted holds vulnerabilities that affect a version-changed package on both
// sides of the diff — i.e. carried-over findings the upgrade did not remediate.
type DiffVulnerabilityResults struct {
	Added     []DiffVulnerabilityChange `json:"added,omitempty"`
	Removed   []DiffVulnerabilityChange `json:"removed,omitempty"`
	Persisted []DiffVulnerabilityChange `json:"persisted,omitempty"`
}

// DiffVulnerabilityChange is one vulnerability introduced or removed for a package.
type DiffVulnerabilityChange struct {
	Package       PackageRef       `json:"package"`
	Vulnerability VulnerabilityRef `json:"vulnerability"`
}

// DiffPackageChange is one added or removed package.
type DiffPackageChange struct {
	Package PackageRef `json:"package"`
}

// DiffChangedPackage is one version-changed package.
type DiffChangedPackage struct {
	After  PackageRef `json:"after"`
	Before PackageRef `json:"before"`
}

// DiffManifestResult describes changes for one manifest.
type DiffManifestResult struct {
	Status         string               `json:"status"`
	Path           string               `json:"path,omitempty"`
	Kind           sdk.ManifestKind     `json:"kind,omitempty"`
	Subproject     string               `json:"subproject,omitempty"`
	Ecosystem      sdk.Ecosystem        `json:"ecosystem,omitempty"`
	PackageManager sdk.PackageManager   `json:"package_manager,omitempty"`
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
	ExactMatchCount        int `json:"exact_match_count"`
	FuzzyMatchCount        int `json:"fuzzy_match_count"`
	UnmatchedPackageCount  int `json:"unmatched_package_count"`
}

// ExplainResponse is the structured payload for the explain command.
type ExplainResponse struct {
	SchemaVersion string                  `json:"schema_version"`
	Command       string                  `json:"command"`
	Project       ProjectDescriptor       `json:"project"`
	Query         ExplainQuery            `json:"query"`
	Dependency    PackageRef              `json:"dependency,omitempty"`
	Paths         []DependencyPath        `json:"paths,omitempty"`
	Findings      []AuditFinding          `json:"findings,omitempty"`
	AuditSummary  *AuditSummary           `json:"audit_summary,omitempty"`
	Targets       []ExplainTargetResponse `json:"targets,omitempty"`
	Metadata      Metadata                `json:"metadata"`
}

// ExplainQuery records the user query issued to the explain command.
type ExplainQuery struct {
	Name string `json:"name"`
}

// ExplainTargetResponse represents explain output for one resolved target.
type ExplainTargetResponse struct {
	Project        ProjectDescriptor  `json:"project"`
	Detector       string             `json:"detector,omitempty"`
	PackageManager sdk.PackageManager `json:"package_manager,omitempty"`
	Dependency     PackageRef         `json:"dependency"`
	Paths          []DependencyPath   `json:"paths"`
	Findings       []AuditFinding     `json:"findings,omitempty"`
	AuditSummary   *AuditSummary      `json:"audit_summary,omitempty"`
}

// BuildScanResponse constructs the structured scan payload from consolidated
// manifest selections and findings. Reachability metadata (analyzer runs and
// per-analyzer stats) is attached afterwards via ScanResponse.WithAnalyzerRuns.
func BuildScanResponse(project ProjectDescriptor, consolidated sdk.ConsolidatedGraph, registry *sdk.PackageRegistry, findings []sdk.Finding, started time.Time, options ...ReportOptions) ScanResponse {
	response := ScanResponse{
		SchemaVersion: SchemaVersion,
		Command:       "scan",
		Project:       project,
		Manifests:     ScanManifestsFromConsolidated(consolidated, registry),
		Packages:      PackagesFromRegistry(registry),
		Metadata:      Metadata{DurationMS: time.Since(started).Milliseconds()},
	}
	if len(findings) > 0 {
		response.Findings = FindingsFromScan(findings, registry)
		response.AuditSummary = SummaryFromFindings(findings)
	}
	return response.WithReportOptions(firstReportOptions(options))
}

// WithAnalyzerRuns annotates a ScanResponse with analyzer run names and
// per-analyzer reachability stats. Returns the response by value so it
// can be chained from BuildScanResponse callers without intermediate
// state.
func (r ScanResponse) WithAnalyzerRuns(runs []string, stats map[string]sdk.ReachabilityStats) ScanResponse {
	return r.WithReportOptions(ReportOptions{
		ReachabilityEnabled: len(runs) > 0 || len(stats) > 0,
		AnalyzerRuns:        runs,
		AnalyzerStats:       stats,
	})
}

// WithReportOptions annotates a ScanResponse with optional report data and
// strips experimental reachability annotations when the flag is disabled.
func (r ScanResponse) WithReportOptions(options ReportOptions) ScanResponse {
	r.Metadata = metadataWithReportOptions(r.Metadata, options)
	if options.ReachabilityEnabled {
		return r
	}
	for idx := range r.Packages {
		r.Packages[idx] = r.Packages[idx].withoutReachability()
	}
	for idx := range r.Findings {
		r.Findings[idx] = r.Findings[idx].withoutReachability()
	}
	return r
}

// ScanManifestsFromConsolidated converts consolidated manifest selections into stable scan payloads.
// registry, when non-nil, enriches each manifest's packages with matching-stage
// data (vulnerabilities / scorecard / etc.) resolved by PURL.
func ScanManifestsFromConsolidated(consolidated sdk.ConsolidatedGraph, registry *sdk.PackageRegistry) []ScanManifest {
	manifests := make([]ScanManifest, 0, len(consolidated.Manifests))
	for idx, manifest := range consolidated.Manifests {
		if manifest.Entry.Graph == nil {
			continue
		}
		manifests = append(manifests, scanManifestFromConsolidated(manifest, idx, registry))
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

func scanManifestFromConsolidated(manifest sdk.ConsolidatedManifest, idx int, registry *sdk.PackageRegistry) ScanManifest {
	kind := strings.TrimSpace(string(manifest.Entry.Manifest.Kind))
	if kind == "" {
		kind = "entry-" + strconv.Itoa(idx+1)
	}
	return ScanManifest{
		Path:           normalizeScanManifestPath(manifest.Subproject, diffManifestPath(manifest.Subproject, manifest.Entry.Manifest), manifest.Entry.Manifest.Path),
		Kind:           sdk.ManifestKind(kind),
		Subproject:     manifest.Subproject.RelativePath,
		Ecosystem:      manifest.Subproject.Ecosystem,
		PackageManager: manifest.Subproject.PrimaryPackageManager(),
		Detector:       manifest.DetectorName,
		Dependencies:   DependenciesFromGraph(manifest.Entry.Graph, registry),
	}
}

func normalizeScanManifestPath(subproject sdk.Subproject, candidates ...string) string {
	for _, candidate := range candidates {
		normalized := strings.TrimSpace(strings.ReplaceAll(candidate, "\\", "/"))
		if normalized == "" {
			continue
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
func BuildExplainResponse(project ProjectDescriptor, query string, targets []ExplainTargetResponse, started time.Time, options ...ReportOptions) ExplainResponse {
	response := ExplainResponse{
		SchemaVersion: SchemaVersion,
		Command:       "explain",
		Project:       project,
		Query:         ExplainQuery{Name: query},
		Targets:       targets,
		Metadata:      Metadata{DurationMS: time.Since(started).Milliseconds()},
	}
	if len(targets) == 1 {
		response.Dependency = targets[0].Dependency
		response.Paths = targets[0].Paths
		response.Findings = targets[0].Findings
		response.AuditSummary = targets[0].AuditSummary
	}
	return response.WithReportOptions(firstReportOptions(options))
}

// BuildDiffResponse constructs the structured diff payload from consolidated manifest selections.
func BuildDiffResponse(projectPath, baseRef, headRef string, baseConsolidated, headConsolidated sdk.ConsolidatedGraph, audit *DiffAudit, started time.Time, options ...ReportOptions) DiffResponse {
	reportOptions := firstReportOptions(options)
	results, summary := diffResultsFromConsolidated(baseConsolidated, headConsolidated, reportOptions.BaseRegistry, reportOptions.HeadRegistry)
	response := DiffResponse{
		SchemaVersion: SchemaVersion,
		Command:       "diff",
		Project: ProjectDescriptor{
			Name:           filepathBase(projectPath),
			Path:           projectPath,
			TargetType:     "dependency diff",
			Ecosystem:      sdk.EcosystemOther,
			PackageManager: sdk.PackageManagerMultiple,
		},
		Comparison: DiffComparison{Base: baseRef, Head: headRef},
		Results:    results,
		Summary:    summary,
		Audit:      audit,
		Metadata:   Metadata{DurationMS: time.Since(started).Milliseconds()},
	}
	return response.WithReportOptions(reportOptions)
}

// WithReportOptions annotates a DiffResponse with optional report data and
// strips experimental reachability annotations when the flag is disabled.
func (r DiffResponse) WithReportOptions(options ReportOptions) DiffResponse {
	r.Metadata = metadataWithReportOptions(r.Metadata, options)
	if options.ReachabilityEnabled {
		return r
	}
	r.Results.Dependencies = stripDiffDependencyReachability(r.Results.Dependencies)
	r.Results.Licenses = stripDiffLicenseReachability(r.Results.Licenses)
	r.Results.Vulnerabilities = stripDiffVulnerabilityReachability(r.Results.Vulnerabilities)
	for idx := range r.Results.Manifests {
		r.Results.Manifests[idx] = stripDiffManifestReachability(r.Results.Manifests[idx])
	}
	if r.Audit != nil {
		audit := *r.Audit
		audit.Introduced = append([]AuditFinding(nil), audit.Introduced...)
		audit.Resolved = append([]AuditFinding(nil), audit.Resolved...)
		audit.Persisted = append([]AuditFinding(nil), audit.Persisted...)
		r.Audit = &audit
		for idx := range r.Audit.Introduced {
			r.Audit.Introduced[idx] = r.Audit.Introduced[idx].withoutReachability()
		}
		for idx := range r.Audit.Resolved {
			r.Audit.Resolved[idx] = r.Audit.Resolved[idx].withoutReachability()
		}
		for idx := range r.Audit.Persisted {
			r.Audit.Persisted[idx] = r.Audit.Persisted[idx].withoutReachability()
		}
	}
	return r
}

// WithReportOptions annotates an ExplainResponse with optional report data
// and strips experimental reachability annotations when the flag is disabled.
func (r ExplainResponse) WithReportOptions(options ReportOptions) ExplainResponse {
	r.Metadata = metadataWithReportOptions(r.Metadata, options)
	if options.ReachabilityEnabled {
		return r
	}
	r.Dependency = r.Dependency.withoutReachability()
	r.Paths = copyDependencyPaths(r.Paths)
	for pathIdx := range r.Paths {
		for packageIdx := range r.Paths[pathIdx].Packages {
			r.Paths[pathIdx].Packages[packageIdx] = r.Paths[pathIdx].Packages[packageIdx].withoutReachability()
		}
	}
	r.Findings = append([]AuditFinding(nil), r.Findings...)
	for idx := range r.Findings {
		r.Findings[idx] = r.Findings[idx].withoutReachability()
	}
	r.Targets = copyExplainTargets(r.Targets)
	for targetIdx := range r.Targets {
		r.Targets[targetIdx] = stripExplainTargetReachability(r.Targets[targetIdx])
	}
	return r
}

func firstReportOptions(options []ReportOptions) ReportOptions {
	if len(options) == 0 {
		return ReportOptions{}
	}
	return options[0]
}

func metadataWithReportOptions(metadata Metadata, options ReportOptions) Metadata {
	metadata.ReachabilityEnabled = false
	metadata.AnalyzerRuns = nil
	metadata.AnalyzerStats = nil
	if !options.ReachabilityEnabled {
		return metadata
	}
	metadata.ReachabilityEnabled = true
	if len(options.AnalyzerRuns) > 0 {
		metadata.AnalyzerRuns = append([]string(nil), options.AnalyzerRuns...)
		sort.Strings(metadata.AnalyzerRuns)
	}
	if len(options.AnalyzerStats) > 0 {
		metadata.AnalyzerStats = make(map[string]sdk.ReachabilityStats, len(options.AnalyzerStats))
		for k, v := range options.AnalyzerStats {
			metadata.AnalyzerStats[k] = v
		}
	}
	return metadata
}

func stripDiffDependencyReachability(results DiffDependencyResults) DiffDependencyResults {
	for idx := range results.Added {
		results.Added[idx].Package = results.Added[idx].Package.withoutReachability()
	}
	for idx := range results.Removed {
		results.Removed[idx].Package = results.Removed[idx].Package.withoutReachability()
	}
	for idx := range results.Changed {
		results.Changed[idx].After = results.Changed[idx].After.withoutReachability()
		results.Changed[idx].Before = results.Changed[idx].Before.withoutReachability()
	}
	return results
}

func stripDiffLicenseReachability(results DiffLicenseResults) DiffLicenseResults {
	for idx := range results.Added {
		results.Added[idx].Package = results.Added[idx].Package.withoutReachability()
	}
	for idx := range results.Removed {
		results.Removed[idx].Package = results.Removed[idx].Package.withoutReachability()
	}
	for idx := range results.Changed {
		results.Changed[idx].Package = results.Changed[idx].Package.withoutReachability()
	}
	return results
}

func stripDiffVulnerabilityReachability(results DiffVulnerabilityResults) DiffVulnerabilityResults {
	for idx := range results.Added {
		results.Added[idx].Package = results.Added[idx].Package.withoutReachability()
		results.Added[idx].Vulnerability.Reachability = nil
	}
	for idx := range results.Removed {
		results.Removed[idx].Package = results.Removed[idx].Package.withoutReachability()
		results.Removed[idx].Vulnerability.Reachability = nil
	}
	return results
}

func stripDiffManifestReachability(result DiffManifestResult) DiffManifestResult {
	for idx := range result.Added {
		result.Added[idx].Package = result.Added[idx].Package.withoutReachability()
	}
	for idx := range result.Removed {
		result.Removed[idx].Package = result.Removed[idx].Package.withoutReachability()
	}
	for idx := range result.Changed {
		result.Changed[idx].After = result.Changed[idx].After.withoutReachability()
		result.Changed[idx].Before = result.Changed[idx].Before.withoutReachability()
	}
	return result
}

func stripExplainTargetReachability(target ExplainTargetResponse) ExplainTargetResponse {
	target.Dependency = target.Dependency.withoutReachability()
	target.Paths = copyDependencyPaths(target.Paths)
	for pathIdx := range target.Paths {
		for packageIdx := range target.Paths[pathIdx].Packages {
			target.Paths[pathIdx].Packages[packageIdx] = target.Paths[pathIdx].Packages[packageIdx].withoutReachability()
		}
	}
	target.Findings = append([]AuditFinding(nil), target.Findings...)
	for idx := range target.Findings {
		target.Findings[idx] = target.Findings[idx].withoutReachability()
	}
	return target
}

func copyDependencyPaths(paths []DependencyPath) []DependencyPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]DependencyPath(nil), paths...)
	for idx := range out {
		out[idx].Packages = append([]PackageRef(nil), out[idx].Packages...)
	}
	return out
}

func copyExplainTargets(targets []ExplainTargetResponse) []ExplainTargetResponse {
	if len(targets) == 0 {
		return nil
	}
	out := append([]ExplainTargetResponse(nil), targets...)
	for idx := range out {
		out[idx].Paths = copyDependencyPaths(out[idx].Paths)
		out[idx].Findings = append([]AuditFinding(nil), out[idx].Findings...)
	}
	return out
}

type diffManifestSnapshot struct {
	Key      string
	Manifest diffManifestRef
	Graph    *sdk.Graph
}

type diffManifestRef struct {
	Path           string
	Kind           sdk.ManifestKind
	Subproject     string
	Ecosystem      sdk.Ecosystem
	PackageManager sdk.PackageManager
}

func diffResultsFromConsolidated(baseConsolidated, headConsolidated sdk.ConsolidatedGraph, baseRegistry, headRegistry *sdk.PackageRegistry) (DiffResults, DiffSummary) {
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
				Added:          diffPackageChangesFromPackages(headManifest.Graph.Nodes(), headRegistry),
			}
			results.Manifests = append(results.Manifests, result)
			summary.AddedManifestCount++
			summary.AddedPackageCount += len(result.Added)
			summary.UnmatchedPackageCount += len(result.Added)
		case hasBase && !hasHead:
			result := DiffManifestResult{
				Status:         "removed",
				Path:           baseManifest.Manifest.Path,
				Kind:           baseManifest.Manifest.Kind,
				Subproject:     baseManifest.Manifest.Subproject,
				Ecosystem:      baseManifest.Manifest.Ecosystem,
				PackageManager: baseManifest.Manifest.PackageManager,
				Removed:        diffPackageChangesFromPackages(baseManifest.Graph.Nodes(), baseRegistry),
			}
			results.Manifests = append(results.Manifests, result)
			summary.RemovedManifestCount++
			summary.RemovedPackageCount += len(result.Removed)
			summary.UnmatchedPackageCount += len(result.Removed)
		case hasBase && hasHead:
			manifestDiff := sdk.Compare(baseManifest.Graph, headManifest.Graph)
			if isSBOMDiffManifest(baseManifest, headManifest) {
				filterSBOMPseudoPackageDiff(&manifestDiff, baseManifest.Graph, headManifest.Graph)
			}
			exactMatches := len(manifestDiff.Updated)
			reconcileDiffWithFuzzyMatches(&manifestDiff)
			summary.ExactMatchCount += exactMatches
			summary.FuzzyMatchCount += len(manifestDiff.Updated) - exactMatches
			summary.UnmatchedPackageCount += len(manifestDiff.Added) + len(manifestDiff.Removed)
			result := DiffManifestResult{
				Status:         "unchanged",
				Path:           headManifest.Manifest.Path,
				Kind:           headManifest.Manifest.Kind,
				Subproject:     headManifest.Manifest.Subproject,
				Ecosystem:      headManifest.Manifest.Ecosystem,
				PackageManager: headManifest.Manifest.PackageManager,
				Added:          diffPackageChangesFromPackages(manifestDiff.Added, headRegistry),
				Removed:        diffPackageChangesFromPackages(manifestDiff.Removed, baseRegistry),
				Changed:        diffChangedPackagesFromDiff(manifestDiff.Updated, baseRegistry, headRegistry),
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
	results.Dependencies = aggregateDependencyChanges(results.Manifests)
	results.Licenses = aggregateLicenseChanges(results.Dependencies)
	results.Vulnerabilities = aggregateVulnerabilityChanges(results.Dependencies)

	return results, summary
}

func aggregateDependencyChanges(manifests []DiffManifestResult) DiffDependencyResults {
	added := make(map[string]DiffPackageChange)
	removed := make(map[string]DiffPackageChange)
	changed := make(map[string]DiffChangedPackage)
	for _, manifest := range manifests {
		for _, change := range manifest.Added {
			added[change.Package.ID] = change
		}
		for _, change := range manifest.Removed {
			removed[change.Package.ID] = change
		}
		for _, change := range manifest.Changed {
			key := change.Before.ID + "->" + change.After.ID
			changed[key] = change
		}
	}
	out := DiffDependencyResults{}
	for _, change := range added {
		out.Added = append(out.Added, change)
	}
	for _, change := range removed {
		out.Removed = append(out.Removed, change)
	}
	for _, change := range changed {
		out.Changed = append(out.Changed, change)
	}
	sort.Slice(out.Added, func(i, j int) bool { return out.Added[i].Package.ID < out.Added[j].Package.ID })
	sort.Slice(out.Removed, func(i, j int) bool { return out.Removed[i].Package.ID < out.Removed[j].Package.ID })
	sort.Slice(out.Changed, func(i, j int) bool { return out.Changed[i].After.ID < out.Changed[j].After.ID })
	return out
}

func aggregateLicenseChanges(dependencies DiffDependencyResults) DiffLicenseResults {
	out := DiffLicenseResults{}
	for _, change := range dependencies.Added {
		if len(change.Package.Licenses) > 0 {
			out.Added = append(out.Added, DiffLicenseChange{Package: change.Package, Licenses: change.Package.Licenses})
		}
	}
	for _, change := range dependencies.Removed {
		if len(change.Package.Licenses) > 0 {
			out.Removed = append(out.Removed, DiffLicenseChange{Package: change.Package, Licenses: change.Package.Licenses})
		}
	}
	for _, change := range dependencies.Changed {
		if licenseRefsEqual(change.Before.Licenses, change.After.Licenses) {
			continue
		}
		out.Changed = append(out.Changed, DiffLicenseDelta{
			Package: change.After,
			Before:  change.Before.Licenses,
			After:   change.After.Licenses,
		})
	}
	return out
}

func aggregateVulnerabilityChanges(dependencies DiffDependencyResults) DiffVulnerabilityResults {
	out := DiffVulnerabilityResults{}
	for _, change := range dependencies.Added {
		for _, vulnerability := range change.Package.Vulnerabilities {
			out.Added = append(out.Added, DiffVulnerabilityChange{Package: change.Package, Vulnerability: vulnerability})
		}
	}
	for _, change := range dependencies.Removed {
		for _, vulnerability := range change.Package.Vulnerabilities {
			out.Removed = append(out.Removed, DiffVulnerabilityChange{Package: change.Package, Vulnerability: vulnerability})
		}
	}
	for _, change := range dependencies.Changed {
		before := indexVulnerabilities(change.Before.Vulnerabilities)
		after := indexVulnerabilities(change.After.Vulnerabilities)
		for id, vulnerability := range after {
			if _, ok := before[id]; ok {
				// Present on both versions: the upgrade did not remediate it.
				out.Persisted = append(out.Persisted, DiffVulnerabilityChange{Package: change.After, Vulnerability: vulnerability})
				continue
			}
			out.Added = append(out.Added, DiffVulnerabilityChange{Package: change.After, Vulnerability: vulnerability})
		}
		for id, vulnerability := range before {
			if _, ok := after[id]; !ok {
				out.Removed = append(out.Removed, DiffVulnerabilityChange{Package: change.Before, Vulnerability: vulnerability})
			}
		}
	}
	sortVulnerabilityChanges(out.Added)
	sortVulnerabilityChanges(out.Removed)
	sortVulnerabilityChanges(out.Persisted)
	return out
}

func sortVulnerabilityChanges(changes []DiffVulnerabilityChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Package.ID != changes[j].Package.ID {
			return changes[i].Package.ID < changes[j].Package.ID
		}
		return changes[i].Vulnerability.ID < changes[j].Vulnerability.ID
	})
}

func licenseRefsEqual(left, right []LicenseRef) bool {
	if len(left) != len(right) {
		return false
	}
	leftIDs := make([]string, 0, len(left))
	rightIDs := make([]string, 0, len(right))
	for _, ref := range left {
		leftIDs = append(leftIDs, ref.Identifier())
	}
	for _, ref := range right {
		rightIDs = append(rightIDs, ref.Identifier())
	}
	sort.Strings(leftIDs)
	sort.Strings(rightIDs)
	for idx := range leftIDs {
		if leftIDs[idx] != rightIDs[idx] {
			return false
		}
	}
	return true
}

func indexVulnerabilities(values []VulnerabilityRef) map[string]VulnerabilityRef {
	indexed := make(map[string]VulnerabilityRef, len(values))
	for _, value := range values {
		indexed[value.ID] = value
	}
	return indexed
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

func manifestSnapshotsByConsolidated(consolidated sdk.ConsolidatedGraph) map[string]diffManifestSnapshot {
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

func diffManifestRefFromConsolidated(manifest sdk.ConsolidatedManifest, idx int) diffManifestRef {
	pathValue := normalizeScanManifestPath(manifest.Subproject, diffManifestPath(manifest.Subproject, manifest.Entry.Manifest), manifest.Entry.Manifest.Path)
	kind := strings.TrimSpace(string(manifest.Entry.Manifest.Kind))
	if kind == "" {
		kind = "entry-" + strconv.Itoa(idx+1)
	}
	return diffManifestRef{
		Path:           pathValue,
		Kind:           sdk.ManifestKind(kind),
		Subproject:     manifest.Subproject.RelativePath,
		Ecosystem:      manifest.Subproject.Ecosystem,
		PackageManager: manifest.Subproject.PrimaryPackageManager(),
	}
}

func diffManifestPath(subproject sdk.Subproject, manifest sdk.ManifestMetadata) string {
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
	if strings.TrimSpace(manifest.Path) == "" {
		return strings.Join([]string{subproject, manifest.PackageManager.Name(), string(manifest.Kind), pathValue}, "::")
	}
	return strings.Join([]string{subproject, manifest.PackageManager.Name(), pathValue}, "::")
}

func diffManifestKeyForConsolidated(manifest sdk.ConsolidatedManifest, ref diffManifestRef, idx int) string {
	if !isSBOMManifest(manifest.Subproject) {
		return diffManifestKey(ref, idx)
	}

	if key, ok := derivedSBOMManifestKey(manifest, ref); ok {
		return key
	}

	return strings.Join([]string{
		"sbom",
		manifest.Subproject.PrimaryPackageManager().Name(),
		"synthetic-manifest",
	}, "::")
}

func derivedSBOMManifestKey(manifest sdk.ConsolidatedManifest, ref diffManifestRef) (string, bool) {
	pathValue := strings.TrimSpace(strings.ReplaceAll(ref.Path, "\\", "/"))
	if pathValue == "" || !sbomManifestPathLooksDerived(manifest, pathValue) {
		return "", false
	}
	return strings.Join([]string{
		"sbom",
		manifest.Subproject.PrimaryPackageManager().Name(),
		pathValue,
	}, "::"), true
}

func sbomManifestPathLooksDerived(manifest sdk.ConsolidatedManifest, candidate string) bool {
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

func isSBOMManifest(subproject sdk.Subproject) bool {
	return subproject.PrimaryPackageManager() == sdk.PackageManagerSBOM || subproject.Ecosystem == sdk.EcosystemSBOM
}

func isSBOMDiffManifest(base, head diffManifestSnapshot) bool {
	return base.Manifest.PackageManager == sdk.PackageManagerSBOM || head.Manifest.PackageManager == sdk.PackageManagerSBOM
}

func filterSBOMPseudoPackageDiff(diff *sdk.Diff, baseGraph, headGraph *sdk.Graph) {
	if diff == nil {
		return
	}
	diff.Added = filterSBOMPseudoPackages(diff.Added, headGraph)
	diff.Removed = filterSBOMPseudoPackages(diff.Removed, baseGraph)
}

func filterSBOMPseudoPackages(packages []*sdk.Dependency, graph *sdk.Graph) []*sdk.Dependency {
	if len(packages) == 0 {
		return packages
	}
	rootIDs := graphRootIDs(graph)
	filtered := make([]*sdk.Dependency, 0, len(packages))
	for _, pkg := range packages {
		if isSBOMPseudoPackage(pkg, rootIDs) {
			continue
		}
		filtered = append(filtered, pkg)
	}
	return filtered
}

func graphRootIDs(graph *sdk.Graph) map[string]struct{} {
	roots := map[string]struct{}{}
	if graph == nil {
		return roots
	}
	for _, root := range graph.Roots() {
		if root == nil {
			continue
		}
		roots[root.ID] = struct{}{}
	}
	return roots
}

func isSBOMPseudoPackage(pkg *sdk.Dependency, rootIDs map[string]struct{}) bool {
	if pkg == nil {
		return false
	}
	if !sdk.NodeIsDiffable(pkg) {
		return true
	}
	if _, ok := rootIDs[pkg.ID]; !ok {
		return false
	}
	if purl := sdk.ParsePackageURL(pkg.PURL); purl != nil && strings.EqualFold(purl.Type, "github") {
		return true
	}
	return false
}

func diffPackageChangesFromPackages(packages []*sdk.Dependency, registry *sdk.PackageRegistry) []DiffPackageChange {
	changes := make([]DiffPackageChange, 0, len(packages))
	for _, pkg := range packages {
		changes = append(changes, DiffPackageChange{Package: PackageFromDependencyAndRegistry(pkg, registry)})
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Package.ID < changes[j].Package.ID })
	return changes
}

func diffChangedPackagesFromDiff(changes []sdk.VersionChange, baseRegistry, headRegistry *sdk.PackageRegistry) []DiffChangedPackage {
	out := make([]DiffChangedPackage, 0, len(changes))
	for _, change := range changes {
		out = append(out, DiffChangedPackage{
			After:  PackageFromDependencyAndRegistry(change.After, headRegistry),
			Before: PackageFromDependencyAndRegistry(change.Before, baseRegistry),
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

func reconcileDiffWithFuzzyMatches(diff *sdk.Diff) {
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
		diff.Updated = append(diff.Updated, sdk.VersionChange{Before: before, After: after})
		matchedAdded[match.addedIdx] = struct{}{}
		matchedRemoved[match.removedIdx] = struct{}{}
	}

	if len(matchedAdded) == 0 {
		return
	}

	remainingAdded := make([]*sdk.Dependency, 0, len(diff.Added)-len(matchedAdded))
	for idx, pkg := range diff.Added {
		if _, ok := matchedAdded[idx]; ok {
			continue
		}
		remainingAdded = append(remainingAdded, pkg)
	}
	remainingRemoved := make([]*sdk.Dependency, 0, len(diff.Removed)-len(matchedRemoved))
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

func fuzzyReconcileScore(before, after *sdk.Dependency) (float64, string) {
	if before == nil || after == nil {
		return 0, ""
	}
	if !sameEcosystemForFuzzy(before, after) {
		return 0, ""
	}

	beforeNorm := before.Clone()
	afterNorm := after.Clone()
	sdk.NormalizeDependencyIdentity(beforeNorm)
	sdk.NormalizeDependencyIdentity(afterNorm)

	if sdk.PackageURLBase(beforeNorm.PURL) != "" && sdk.PackageURLBase(beforeNorm.PURL) == sdk.PackageURLBase(afterNorm.PURL) {
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

func sameEcosystemForFuzzy(before, after *sdk.Dependency) bool {
	b := strings.ToLower(strings.TrimSpace(string(before.Ecosystem)))
	a := strings.ToLower(strings.TrimSpace(string(after.Ecosystem)))
	if b == "" || a == "" {
		return true
	}
	return b == a
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

func applyFuzzyMetadata(before, after *sdk.Dependency, score float64, tier string) {
	roundedScore := math.Round(score*1000) / 1000
	for _, pkg := range []*sdk.Dependency{before, after} {
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
