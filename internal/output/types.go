package output

import (
	"maps"
	"slices"
	"sort"

	"github.com/bomly-dev/bomly-sdk/graphview"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
	"github.com/bomly-dev/bomly-sdk/scan"
)

// SchemaVersion is the schema version of the diff and explain documents,
// which keep the CLI's own numbering. The scan document is the SDK's scan
// record and carries scan.SchemaVersion.
const SchemaVersion = "1.0"

// Metadata captures execution metadata shared by all command outputs. It is
// the scan record's metadata type, so the three documents agree on it.
type Metadata = scan.Metadata

// The collections of the scan document are the SDK's own types, not
// projections of them: a manifest and its dependencies are scan.Manifest and
// scan.Dependency, a package is model.Package with its enrichment, a finding
// is model.Finding referencing its package by URL, a license is
// model.PackageLicense and a location model.PackageLocation. The names below
// remain for the renderers that grew up on them.
type (
	ScanResponse     = scan.Record
	ScanManifest     = scan.Manifest
	ScanDependency   = scan.Dependency
	ScanPackageEntry = model.Package
	AuditFinding     = model.Finding
	AuditSummary     = scan.AuditSummary
	LicenseRef       = model.PackageLicense
	LocationRef      = model.PackageLocation
	PositionRef      = model.SourcePosition
	VulnerabilityRef = model.Vulnerability
)

// ReportOptions controls optional experimental data in structured command
// outputs.
type ReportOptions struct {
	// DetectorWarnings are the detection-stage warnings the run produced. They
	// are surfaced in the response document so a consumer reading JSON sees the
	// same problems the progress stream showed.
	DetectorWarnings    []plugin.DetectorWarning
	ReachabilityEnabled bool
	ScorecardEnabled    bool
	AnalyzerRuns        []string
	AnalyzerStats       map[string]plugin.ReachabilityStats
	BaseRegistry        *model.PackageRegistry
	HeadRegistry        *model.PackageRegistry
}

// ProjectDescriptor describes the project being analyzed.
type ProjectDescriptor struct {
	Name           string               `json:"name,omitempty"`
	Path           string               `json:"path"`
	TargetType     string               `json:"target_type,omitempty"`
	TargetRef      string               `json:"target_ref,omitempty"`
	Ecosystem      model.Ecosystem      `json:"ecosystem"`
	PackageManager model.PackageManager `json:"package_manager,omitempty"`
}

// PackageRef identifies a package in command outputs.
type PackageRef struct {
	Name            string                  `json:"name"`
	Version         string                  `json:"version,omitempty"`
	Scope           string                  `json:"scope,omitempty"`
	Purl            string                  `json:"purl,omitempty"`
	ID              string                  `json:"id,omitempty"`
	Metadata        map[string]any          `json:"metadata,omitempty"`
	Locations       []LocationRef           `json:"locations,omitempty"`
	Licenses        []LicenseRef            `json:"licenses"`
	Vulnerabilities []VulnerabilityRef      `json:"vulnerabilities"`
	Scorecard       *model.PackageScorecard `json:"scorecard,omitempty"`
	Relationship    string                  `json:"relationship,omitempty"`
	// Direct reports whether the package is a direct dependency of a project
	// root. nil means directness could not be determined (e.g. a flat SBOM with
	// no dependency edges); it is only populated where a graph is in scope.
	Direct *bool `json:"direct,omitempty"`
}

// ExplainDependency is the focused package in explain output. Remediation is
// intentionally attached here rather than to PackageRef so dependency-path
// entries and diff package changes do not repeat package-level enrichment.
type ExplainDependency struct {
	PackageRef
	Remediation *model.PackageRemediation `json:"remediation,omitempty"`
}

func (p ExplainDependency) withoutReachability() ExplainDependency {
	p.PackageRef = p.PackageRef.withoutReachability()
	return p
}

// DependencyPath describes one resolved dependency path returned by the explain command.
type DependencyPath struct {
	Relationship  string       `json:"relationship,omitempty"`
	Packages      []PackageRef `json:"packages"`
	IntroducedVia string       `json:"introduced_via,omitempty"`
	Cyclic        bool         `json:"cyclic,omitempty"`
	CycleTo       string       `json:"cycle_to,omitempty"`
}

// PackageFromGraphPackage builds a PackageRef from a graph Dependency node.
// Detection-time license facts (carried in the dependency's metadata under
// MetadataKeyDetectionLicenses) are surfaced directly from the dependency;
// matching-stage enrichment (Vulnerabilities, Scorecard, EOL, licenses
// learned during matching) must come from the registry — use
// PackageFromDependencyAndRegistry when a registry is in scope.
func PackageFromGraphPackage(dep *model.DependencyNode) PackageRef {
	return PackageFromDependencyAndRegistry(dep, nil)
}

// PackageFromGraphNode renders any graph node as a package reference.
//
// A dependency path runs through the project's own artifacts before it reaches
// a consumed package, and those are module and manifest nodes now (ADR-0041).
// Rendering only the dependency nodes drops the head of every path -- "why is
// loose-envify here" answers with "react needs it" and never says which
// project pulled react in -- so a structural node renders too, with the fields
// its kind actually has.
func PackageFromGraphNode(node model.GraphNode) PackageRef {
	if dep, ok := node.(*model.DependencyNode); ok {
		return PackageFromDependencyAndRegistry(dep, nil)
	}
	// Scope is left unset deliberately. A dependency node returned above,
	// so what reaches here is a module or a manifest, and neither carries
	// one: scope is a claim about how a consumed package is used.
	ref := PackageRef{
		Name:            model.NodeDisplayName(node),
		Version:         model.NodeVersion(node),
		ID:              node.NodeID(),
		Locations:       append([]model.PackageLocation(nil), node.NodeLocations()...),
		Licenses:        []model.PackageLicense{},
		Vulnerabilities: []model.Vulnerability{},
	}
	ref.Purl = PurlFromGraphNode(node)
	return ref
}

// PurlFromGraphNode returns the package URL a node publishes, or "" when it
// has none. It delegates to graphview, which is the one place that decides
// this for every surface that publishes a purl.
func PurlFromGraphNode(node model.GraphNode) string {
	return graphview.PurlFor(node)
}

// PackageFromDependencyAndRegistry builds a PackageRef from a graph Dependency
// node and layers in matching-stage enrichment (vulnerabilities, scorecard,
// licenses learned during matching) by resolving dep.NodeID() against the
// registry. registry may be nil — callers without a registry get the
// detection-only projection.
func PackageFromDependencyAndRegistry(dep *model.DependencyNode, registry *model.PackageRegistry) PackageRef {
	if dep == nil {
		return PackageRef{Licenses: []model.PackageLicense{}, Vulnerabilities: []model.Vulnerability{}}
	}
	ref := PackageRef{
		Name:            dep.DisplayName(),
		Version:         dep.Version,
		Scope:           string(dep.PrimaryScope()),
		Purl:            dep.NodeID(),
		ID:              dep.NodeID(),
		Relationship:    string(dep.Relationship),
		Metadata:        cloneRefMetadata(dep.Metadata),
		Locations:       append([]model.PackageLocation(nil), dep.Locations...),
		Licenses:        cloneLicenses(model.DetectionLicenses(dep)),
		Vulnerabilities: []model.Vulnerability{},
	}
	pkg := RegistryPackageForNode(registry, dep)
	if pkg != nil {
		// Prefer registry-learned licenses when detection produced none.
		if len(ref.Licenses) == 0 && len(pkg.Licenses) > 0 {
			ref.Licenses = cloneLicenses(pkg.Licenses)
		}
		if len(pkg.Vulnerabilities) > 0 {
			ref.Vulnerabilities = cloneVulnerabilities(pkg.Vulnerabilities)
		}
		if pkg.Scorecard != nil {
			scorecardCopy := pkg.Scorecard.Clone()
			ref.Scorecard = scorecardCopy
		}
		// pkg.Matched is captured via the presence of registry data (vulns,
		// licenses, scorecard) — no separate flag is currently exposed on
		// PackageRef.
		_ = pkg.Matched
	}
	return ref
}

func (p PackageRef) withoutReachability() PackageRef {
	if len(p.Vulnerabilities) > 0 {
		p.Vulnerabilities = cloneVulnerabilities(p.Vulnerabilities)
		for idx := range p.Vulnerabilities {
			p.Vulnerabilities[idx].Reachability = nil
		}
	}
	return p
}

func cloneAffectedSymbols(src []model.AffectedSymbol) []model.AffectedSymbol {
	if len(src) == 0 {
		return nil
	}
	out := make([]model.AffectedSymbol, 0, len(src))
	for _, sym := range src {
		out = append(out, sym.Clone())
	}
	return out
}

// cloneRefMetadata copies package metadata for command output.
func cloneRefMetadata(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	clone := make(map[string]any, len(src))
	maps.Copy(clone, src)
	return clone
}

func cloneKnownExploited(src []model.KnownExploited) []model.KnownExploited {
	if len(src) == 0 {
		return nil
	}
	out := make([]model.KnownExploited, 0, len(src))
	for _, item := range src {
		if len(item.URLs) > 0 {
			item.URLs = append([]string(nil), item.URLs...)
		}
		if len(item.CWEs) > 0 {
			item.CWEs = append([]string(nil), item.CWEs...)
		}
		out = append(out, item)
	}
	return out
}

// FailingFindingCount reports how many findings should fail policy evaluation.
// Warning and suppressed findings remain reportable but do not gate execution.
func FailingFindingCount(findings []model.Finding) int {
	total := 0
	for _, finding := range findings {
		if finding.PolicyStatus == "" || finding.PolicyStatus == model.FindingPolicyStatusFail {
			total++
		}
	}
	return total
}

// DependenciesFromGraph converts a graph into stable, lean scan dependency
// payloads. registry, when non-nil, supplies the Matched flag via PURL lookup;
// all richer enrichment is surfaced through PackagesFromRegistry instead.
func DependenciesFromGraph(g *model.Graph, registry *model.PackageRegistry) []scan.Dependency {
	if g == nil {
		return nil
	}

	// Modules as well as dependencies: a module is the project's own
	// artifact, not a consumed package, but it is where the tree starts.
	// Listing only dependency nodes would leave every depends_on chain
	// headless -- a consumer could no longer say which module pulled a
	// package in. Manifest nodes stay out; they are what the listing is
	// about, not something in it.
	listed := make([]model.GraphNode, 0, g.Size())
	for _, module := range g.ModuleNodes() {
		listed = append(listed, module)
	}
	for _, dep := range g.DependencyNodes() {
		listed = append(listed, dep)
	}
	listedIDs := make(map[string]struct{}, len(listed))
	for _, node := range listed {
		if !model.IsNilNode(node) {
			listedIDs[node.NodeID()] = struct{}{}
		}
	}
	payload := make([]scan.Dependency, 0, len(listed))
	for _, node := range listed {
		if node == nil {
			continue
		}
		dependencyIDs := graphview.ChildrenAmong(g, node.NodeID(), listedIDs)
		name, version := model.NodeDisplayName(node), model.NodeVersion(node)
		entry := scan.Dependency{
			ID:        node.NodeID(),
			Name:      name,
			Version:   version,
			DependsOn: dependencyIDs,
			Locations: node.NodeLocations(),
		}
		if module, isModule := node.(*model.ModuleNode); isModule {
			// A module publishes the package URL its coordinates mint, when
			// they mint one; its node ID is not a package URL.
			entry.PURL = module.PURL()
		}
		if dep, isDependency := node.(*model.DependencyNode); isDependency {
			// Where the dependency was resolved from and whether its manifest
			// declared it directly travel with the record, as the SDK's own
			// builder writes them: a comparison rebuilt from the record has
			// no structural root and reads the stated relationship instead.
			entry.Source = dep.Source
			entry.Relationship = dep.Relationship
			matched := dep.Matched
			if pkg := RegistryPackageForNode(registry, dep); pkg != nil {
				matched = matched || pkg.Matched
			}
			entry.PURL = dep.NodeID()
			entry.Scopes = append([]model.Scope(nil), dep.Scopes...)
			entry.Matched = matched
			entry.PackageRef = dep.PackageRef
			entry.Licenses = model.DetectionLicenses(dep)
		}
		payload = append(payload, entry)
	}
	sort.Slice(payload, func(i, j int) bool {
		return payload[i].ID < payload[j].ID
	})
	for idx := range payload {
		sort.Strings(payload[idx].DependsOn)
	}
	return payload
}

// LicenseIdentifier returns the most useful license identifier for display.
func LicenseIdentifier(l model.PackageLicense) string {
	if l.SPDXExpression != "" {
		return l.SPDXExpression
	}
	return l.Value
}

// DependencyPrimaryScope returns the merged precedence scope across the
// dependency's recorded scopes, mirroring model.DependencyNode.PrimaryScope
// so text/markdown renderers reproduce the same scope label.
func DependencyPrimaryScope(d scan.Dependency) string {
	result := model.ScopeUnknown
	for _, scope := range d.Scopes {
		result = model.MergeScope(result, scope)
	}
	return string(result)
}

// FindingLabel returns a human-readable name@version label for the package a
// finding references, derived from its package URL.
func FindingLabel(f model.Finding) string {
	identity := identityFromPURL(f.PackageRef)
	switch {
	case identity.Name != "" && identity.Version != "":
		return identity.Name + "@" + identity.Version
	case identity.Name != "":
		return identity.Name
	default:
		return f.PackageRef
	}
}

// FindingResolvedVulnerabilityID returns the advisory id a finding names,
// falling back to its own id for vulnerability findings.
func FindingResolvedVulnerabilityID(f model.Finding) string {
	return resolvedVulnerabilityID(f.VulnerabilityID, f.ID)
}

// FindingVulnerabilityInPackages resolves a finding's advisory from the
// packages collection by package URL and advisory id.
func FindingVulnerabilityInPackages(f model.Finding, packages []*model.Package) *model.Vulnerability {
	id := FindingResolvedVulnerabilityID(f)
	for _, pkg := range packages {
		if pkg == nil || pkg.PURL != f.PackageRef {
			continue
		}
		return MatchVulnerabilityRef(pkg.Vulnerabilities, id)
	}
	return nil
}

// MatchVulnerabilityRef finds an advisory by id or alias.
func MatchVulnerabilityRef(refs []model.Vulnerability, id string) *model.Vulnerability {
	if id == "" {
		return nil
	}
	for i := range refs {
		if refs[i].ID == id || slices.Contains(refs[i].Aliases, id) {
			return &refs[i]
		}
	}
	return nil
}

// SummaryFromFindings aggregates finding counts by severity band.
func SummaryFromFindings(findings []model.Finding) *scan.AuditSummary {
	if len(findings) == 0 {
		return nil
	}
	summary := &scan.AuditSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.Severity {
		case model.SeverityCritical:
			summary.Critical++
		case model.SeverityHigh:
			summary.High++
		case model.SeverityMedium:
			summary.Medium++
		case model.SeverityLow:
			summary.Low++
		default:
			summary.Unknown++
		}
	}
	return summary
}

// PackagesFromRegistry projects the registry into the packages collection,
// sorted by package URL: a clone of each package, so the document never
// aliases the registry a later stage may still enrich.
func PackagesFromRegistry(registry *model.PackageRegistry) []*model.Package {
	if registry == nil {
		return []*model.Package{}
	}
	all := registry.All()
	out := make([]*model.Package, 0, len(all))
	for _, pkg := range all {
		if pkg == nil {
			continue
		}
		clone := pkg.Clone()
		// ResolvedURL is raw detection evidence -- a manifest's resolution
		// field verbatim, which may be a local path or a credentialed
		// registry URL -- carried for matchers and never published. The
		// document is a publication.
		clone.ResolvedURL = ""
		out = append(out, clone)
	}
	return out
}

// packageWithoutReachability strips analyzer annotations from a package's
// advisories when the run did not enable them.
func packageWithoutReachability(pkg *model.Package) *model.Package {
	if pkg == nil {
		return nil
	}
	for i := range pkg.Vulnerabilities {
		pkg.Vulnerabilities[i].Reachability = nil
	}
	return pkg
}

func cloneLicenses(licenses []model.PackageLicense) []model.PackageLicense {
	out := make([]model.PackageLicense, 0, len(licenses))
	return append(out, licenses...)
}

func cloneVulnerabilities(vulnerabilities []model.Vulnerability) []model.Vulnerability {
	out := make([]model.Vulnerability, 0, len(vulnerabilities))
	for _, v := range vulnerabilities {
		out = append(out, v.Clone())
	}
	return out
}

// FindingsWithSeverity returns the findings as the document carries them: a
// clone of each, with a severity the finding itself did not state backfilled
// from the advisory it references, so a vulnerability finding never reads as
// severity-less beside the advisory that rates it.
func FindingsWithSeverity(findings []model.Finding, registry *model.PackageRegistry) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		finding := f.Clone()
		if finding.Severity == "" {
			if _, advisory := FindingAdvisory(registry, finding); advisory != nil {
				finding.Severity = advisory.ParsedSeverity
			}
		}
		out = append(out, finding)
	}
	return out
}
