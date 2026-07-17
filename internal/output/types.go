package output

import (
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// SchemaVersion is the current CLI output schema version.
const SchemaVersion = "1.0"

// Metadata captures execution metadata shared by all command outputs.
type Metadata struct {
	DurationMS          int64                            `json:"duration_ms"`
	ReachabilityEnabled bool                             `json:"reachability_enabled,omitempty"`
	ScorecardEnabled    bool                             `json:"scorecard_enabled,omitempty"`
	AnalyzerRuns        []string                         `json:"analyzer_runs,omitempty"`
	AnalyzerStats       map[string]sdk.ReachabilityStats `json:"analyzer_stats,omitempty"`
}

// ReportOptions controls optional experimental data in structured command
// outputs.
type ReportOptions struct {
	ReachabilityEnabled bool
	ScorecardEnabled    bool
	AnalyzerRuns        []string
	AnalyzerStats       map[string]sdk.ReachabilityStats
	BaseRegistry        *sdk.PackageRegistry
	HeadRegistry        *sdk.PackageRegistry
}

// ProjectDescriptor describes the project being analyzed.
type ProjectDescriptor struct {
	Name           string             `json:"name,omitempty"`
	Path           string             `json:"path"`
	TargetType     string             `json:"target_type,omitempty"`
	TargetRef      string             `json:"target_ref,omitempty"`
	Ecosystem      sdk.Ecosystem      `json:"ecosystem"`
	PackageManager sdk.PackageManager `json:"package_manager,omitempty"`
}

// LicenseRef identifies one package license in command outputs.
type LicenseRef struct {
	Value          string          `json:"value,omitempty"`
	SPDXExpression string          `json:"spdxExpression,omitempty"`
	Type           sdk.LicenseType `json:"type,omitempty"`
}

// Identifier returns the most useful license identifier for display.
func (l LicenseRef) Identifier() string {
	switch {
	case strings.TrimSpace(l.SPDXExpression) != "":
		return strings.TrimSpace(l.SPDXExpression)
	case strings.TrimSpace(l.Value) != "":
		return strings.TrimSpace(l.Value)
	default:
		return ""
	}
}

// VulnerabilityRef identifies one package vulnerability in command outputs.
type VulnerabilityRef struct {
	ID                   string               `json:"id"`
	Source               string               `json:"source"`
	Title                string               `json:"title,omitempty"`
	Severity             sdk.SeverityLevel    `json:"severity,omitempty"`
	SeveritySource       string               `json:"severity_source,omitempty"`
	Aliases              []string             `json:"aliases,omitempty"`
	Description          string               `json:"description,omitempty"`
	Reasons              []string             `json:"reasons,omitempty"`
	CVSS                 []sdk.CVSSScore      `json:"cvss,omitempty"`
	FixedIn              string               `json:"fixed_in,omitempty"`
	FixedVersions        []string             `json:"fixed_versions,omitempty"`
	FixState             sdk.FixState         `json:"fix_state,omitempty"`
	FixAvailable         []sdk.FixAvailable   `json:"fix_available,omitempty"`
	AffectedVersionRange string               `json:"affected_version_range,omitempty"`
	References           []sdk.Reference      `json:"references,omitempty"`
	KEVExploited         bool                 `json:"kev_exploited,omitempty"`
	KnownExploited       []sdk.KnownExploited `json:"known_exploited,omitempty"`
	EPSS                 []sdk.EPSSScore      `json:"epss,omitempty"`
	CWEs                 []sdk.CWE            `json:"cwes,omitempty"`
	RiskScore            float64              `json:"risk_score,omitempty"`
	DataSource           string               `json:"data_source,omitempty"`
	Namespace            string               `json:"namespace,omitempty"`
	CPEs                 []string             `json:"cpes,omitempty"`
	AffectedSymbols      []sdk.AffectedSymbol `json:"affected_symbols,omitempty"`
	Reachability         *sdk.Reachability    `json:"reachability,omitempty"`
}

// PackageRef identifies a package in command outputs.
type PackageRef struct {
	Name            string                `json:"name"`
	Version         string                `json:"version,omitempty"`
	Scope           string                `json:"scope,omitempty"`
	Purl            string                `json:"purl,omitempty"`
	ID              string                `json:"id,omitempty"`
	Metadata        map[string]any        `json:"metadata,omitempty"`
	Locations       []LocationRef         `json:"locations,omitempty"`
	Licenses        []LicenseRef          `json:"licenses"`
	Vulnerabilities []VulnerabilityRef    `json:"vulnerabilities"`
	Scorecard       *sdk.PackageScorecard `json:"scorecard,omitempty"`
	Relationship    string                `json:"relationship,omitempty"`
	// Direct reports whether the package is a direct dependency of a project
	// root. nil means directness could not be determined (e.g. a flat SBOM with
	// no dependency edges); it is only populated where a graph is in scope.
	Direct *bool `json:"direct,omitempty"`
}

// LocationRef points at where a package was declared in a lockfile
// or manifest. Detectors populate this when their input format makes
// position cheaply recoverable; consumers (SARIF / explain output /
// IDE plugins) use it to deep-link into the source.
type LocationRef struct {
	RealPath   string       `json:"real_path,omitempty"`
	AccessPath string       `json:"access_path,omitempty"`
	Position   *PositionRef `json:"position,omitempty"`
}

// PositionRef is the JSON shape of sdk.SourcePosition.
type PositionRef struct {
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
	EndLine int    `json:"end_line,omitempty"`
}

// LocationRefsFromGraphLocations converts SDK locations into
// output-friendly values, dropping entries with no useful content.
func LocationRefsFromGraphLocations(locations []sdk.PackageLocation) []LocationRef {
	if len(locations) == 0 {
		return nil
	}
	out := make([]LocationRef, 0, len(locations))
	for _, loc := range locations {
		ref := LocationRef{RealPath: loc.RealPath, AccessPath: loc.AccessPath}
		if loc.Position != nil {
			ref.Position = &PositionRef{
				File:    loc.Position.File,
				Line:    loc.Position.Line,
				Column:  loc.Position.Column,
				EndLine: loc.Position.EndLine,
			}
		}
		if ref.RealPath == "" && ref.AccessPath == "" && ref.Position == nil {
			continue
		}
		out = append(out, ref)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
func PackageFromGraphPackage(dep *sdk.Dependency) PackageRef {
	return PackageFromDependencyAndRegistry(dep, nil)
}

// PackageFromDependencyAndRegistry builds a PackageRef from a graph Dependency
// node and layers in matching-stage enrichment (vulnerabilities, scorecard,
// licenses learned during matching) by resolving dep.PURL against the
// registry. registry may be nil — callers without a registry get the
// detection-only projection.
func PackageFromDependencyAndRegistry(dep *sdk.Dependency, registry *sdk.PackageRegistry) PackageRef {
	if dep == nil {
		return PackageRef{Licenses: []LicenseRef{}, Vulnerabilities: []VulnerabilityRef{}}
	}
	ref := PackageRef{
		Name:            dep.DisplayName(),
		Version:         dep.Version,
		Scope:           string(dep.PrimaryScope()),
		Purl:            dep.PURL,
		ID:              dep.ID,
		Relationship:    string(dep.Relationship),
		Metadata:        cloneRefMetadata(dep.Metadata),
		Locations:       LocationRefsFromGraphLocations(dep.Locations),
		Licenses:        LicenseRefsFromGraphLicenses(sdk.DetectionLicenses(dep)),
		Vulnerabilities: []VulnerabilityRef{},
	}
	pkg := lookupRegistryPackage(registry, dep.PURL)
	if pkg != nil {
		// Prefer registry-learned licenses when detection produced none.
		if len(ref.Licenses) == 0 && len(pkg.Licenses) > 0 {
			ref.Licenses = LicenseRefsFromGraphLicenses(pkg.Licenses)
		}
		if len(pkg.Vulnerabilities) > 0 {
			ref.Vulnerabilities = VulnerabilityRefsFromPackageVulnerabilities(pkg.Vulnerabilities)
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

// lookupRegistryPackage resolves a PURL against the registry, returning nil
// if the registry or the PURL is empty.
func lookupRegistryPackage(registry *sdk.PackageRegistry, purl string) *sdk.Package {
	if registry == nil || strings.TrimSpace(purl) == "" {
		return nil
	}
	pkg, _ := registry.Get(purl)
	return pkg
}

func (p PackageRef) withoutReachability() PackageRef {
	if len(p.Vulnerabilities) > 0 {
		p.Vulnerabilities = append([]VulnerabilityRef(nil), p.Vulnerabilities...)
		for idx := range p.Vulnerabilities {
			p.Vulnerabilities[idx].Reachability = nil
		}
	}
	return p
}

func cloneAffectedSymbols(src []sdk.AffectedSymbol) []sdk.AffectedSymbol {
	if len(src) == 0 {
		return nil
	}
	out := make([]sdk.AffectedSymbol, 0, len(src))
	for _, sym := range src {
		out = append(out, sym.Clone())
	}
	return out
}

func cloneRefMetadata(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	clone := make(map[string]any, len(src))
	for key, value := range src {
		clone[key] = value
	}
	return clone
}

func cloneKnownExploited(src []sdk.KnownExploited) []sdk.KnownExploited {
	if len(src) == 0 {
		return nil
	}
	out := make([]sdk.KnownExploited, 0, len(src))
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

// LicenseRefsFromGraphLicenses converts graph licenses into output-friendly values.
func LicenseRefsFromGraphLicenses(licenses []sdk.PackageLicense) []LicenseRef {
	if len(licenses) == 0 {
		return []LicenseRef{}
	}
	out := make([]LicenseRef, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, LicenseRef{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           license.Type,
		})
	}
	return out
}

// VulnerabilityRefsFromPackageVulnerabilities converts package vulnerability enrichment into output-friendly values.
func VulnerabilityRefsFromPackageVulnerabilities(vulnerabilities []sdk.Vulnerability) []VulnerabilityRef {
	if len(vulnerabilities) == 0 {
		return []VulnerabilityRef{}
	}
	out := make([]VulnerabilityRef, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		out = append(out, VulnerabilityRef{
			ID:                   vulnerability.ID,
			Source:               vulnerability.Source,
			Title:                vulnerability.Title,
			Severity:             vulnerability.ParsedSeverity,
			SeveritySource:       vulnerability.SeveritySource,
			Aliases:              append([]string(nil), vulnerability.Aliases...),
			Description:          vulnerability.Details,
			Reasons:              append([]string(nil), vulnerability.Reasons...),
			CVSS:                 append([]sdk.CVSSScore(nil), vulnerability.CVSS...),
			FixedIn:              vulnerability.FixedIn,
			FixedVersions:        append([]string(nil), vulnerability.FixedVersions...),
			FixState:             vulnerability.FixState,
			FixAvailable:         append([]sdk.FixAvailable(nil), vulnerability.FixAvailable...),
			AffectedSymbols:      cloneAffectedSymbols(vulnerability.AffectedSymbols),
			Reachability:         vulnerability.Reachability.Clone(),
			AffectedVersionRange: vulnerability.AffectedVersionRange,
			References:           append([]sdk.Reference(nil), vulnerability.References...),
			KEVExploited:         vulnerability.KEVExploited,
			KnownExploited:       cloneKnownExploited(vulnerability.KnownExploited),
			EPSS:                 append([]sdk.EPSSScore(nil), vulnerability.EPSS...),
			CWEs:                 append([]sdk.CWE(nil), vulnerability.CWEs...),
			RiskScore:            vulnerability.RiskScore,
			DataSource:           vulnerability.DataSource,
			Namespace:            vulnerability.Namespace,
			CPEs:                 append([]string(nil), vulnerability.CPEs...),
		})
	}
	return out
}

// FindingPackageRef is an identity-only reference from a finding into the
// top-level packages collection (join key: purl). Advisory enrichment lives
// once, on the referenced ScanPackageEntry — findings never re-embed it.
type FindingPackageRef struct {
	Name      string `json:"name"`
	Org       string `json:"org,omitempty"`
	Version   string `json:"version,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// DisplayLabel returns a human-readable name@version label for the package.
func (p FindingPackageRef) DisplayLabel() string {
	switch {
	case p.Name != "" && p.Version != "":
		return p.Name + "@" + p.Version
	case p.Name != "":
		return p.Name
	default:
		return p.Purl
	}
}

// AuditFinding is the serialized form of one normalized scan finding. It
// mirrors sdk.Finding's three-collection shape: the package is referenced by
// identity (join to packages[] via purl), the advisory by vulnerability_id
// (join to packages[].vulnerabilities), and the introducing graph nodes by
// dependency_refs (join to manifests[].dependencies ids).
type AuditFinding struct {
	ID              string                 `json:"id"`
	Kind            sdk.FindingKind        `json:"kind"`
	Severity        sdk.SeverityLevel      `json:"severity"`
	Package         FindingPackageRef      `json:"package"`
	Title           string                 `json:"title"`
	Reasons         []string               `json:"reasons,omitempty"`
	Source          string                 `json:"source"`
	Auditor         string                 `json:"auditor,omitempty"`
	Disposition     sdk.FindingDisposition `json:"disposition,omitempty"`
	VulnerabilityID string                 `json:"vulnerability_id,omitempty"`
	DependencyRefs  []string               `json:"dependency_refs,omitempty"`
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

// FindingsFromScan converts normalized findings into JSON-friendly DTOs.
// When registry is non-nil the finding's package reference is resolved
// against it for display identity (name/org/version/ecosystem), and a
// missing finding severity is backfilled from the referenced advisory.
func FindingsFromScan(findings []sdk.Finding, registry *sdk.PackageRegistry) []AuditFinding {
	result := make([]AuditFinding, 0, len(findings))
	for _, f := range findings {
		pkg := lookupRegistryPackage(registry, f.PackageRef)
		af := AuditFinding{
			ID:              f.ID,
			Kind:            f.Kind,
			Severity:        f.Severity,
			Package:         findingPackageRefFromRegistryPackage(f.PackageRef, pkg),
			Title:           f.Title,
			Reasons:         f.Reasons,
			Source:          f.Source,
			Auditor:         f.Auditor,
			Disposition:     f.Disposition,
			VulnerabilityID: f.VulnerabilityID,
			DependencyRefs:  append([]string(nil), f.DependencyRefs...),
		}
		if af.Severity == "" {
			if vuln := lookupVulnerability(pkg, f.VulnerabilityID, f.ID); vuln != nil {
				af.Severity = vuln.ParsedSeverity
			}
		}
		result = append(result, af)
	}
	return result
}

// findingPackageRefFromRegistryPackage builds a FindingPackageRef from a
// registry package (PURL-keyed). When the registry has no entry for purl,
// returns a thin ref carrying just the PURL identifier.
func findingPackageRefFromRegistryPackage(purl string, pkg *sdk.Package) FindingPackageRef {
	if pkg == nil {
		return FindingPackageRef{Name: purl, Purl: purl}
	}
	return FindingPackageRef{
		Name:      pkg.DisplayName(),
		Org:       pkg.Org,
		Version:   pkg.Version,
		Purl:      pkg.PURL,
		Ecosystem: string(pkg.Ecosystem),
	}
}

// ResolvedVulnerabilityID returns the advisory id a finding references,
// falling back to the finding id when VulnerabilityID is unset. All joins
// against packages[].vulnerabilities use this precedence rule.
func (f AuditFinding) ResolvedVulnerabilityID() string {
	if f.VulnerabilityID != "" {
		return f.VulnerabilityID
	}
	return f.ID
}

// FindingVulnerabilityInPackages resolves the advisory a finding references
// (finding.package.purl + finding.vulnerability_id) against the top-level
// packages collection. Returns nil when the package or advisory is absent —
// e.g. non-vulnerability findings or unenriched scans.
func FindingVulnerabilityInPackages(f AuditFinding, packages []ScanPackageEntry) *VulnerabilityRef {
	if f.Package.Purl == "" {
		return nil
	}
	vulnID := f.ResolvedVulnerabilityID()
	for idx := range packages {
		if packages[idx].Purl != f.Package.Purl {
			continue
		}
		return MatchVulnerabilityRef(packages[idx].Vulnerabilities, vulnID)
	}
	return nil
}

// MatchVulnerabilityRef finds the vulnerability ref matching id (or one of
// its aliases) in refs. Returns nil when id is empty or no ref matches.
func MatchVulnerabilityRef(refs []VulnerabilityRef, id string) *VulnerabilityRef {
	if id == "" {
		return nil
	}
	for idx := range refs {
		if refs[idx].ID == id {
			return &refs[idx]
		}
		for _, alias := range refs[idx].Aliases {
			if alias == id {
				return &refs[idx]
			}
		}
	}
	return nil
}

// lookupVulnerability resolves a vulnerability ID (or alias) against a
// registry package's Vulnerabilities slice. Returns nil if pkg is nil or no
// match is found.
func lookupVulnerability(pkg *sdk.Package, vulnID, fallbackID string) *sdk.Vulnerability {
	if pkg == nil {
		return nil
	}
	if vulnID == "" {
		vulnID = fallbackID
	}
	if vulnID == "" {
		return nil
	}
	for i := range pkg.Vulnerabilities {
		v := &pkg.Vulnerabilities[i]
		if v.ID == vulnID {
			return v
		}
		for _, alias := range v.Aliases {
			if alias == vulnID {
				return v
			}
		}
	}
	return nil
}

// FailingFindingCount reports how many findings should fail policy evaluation.
func FailingFindingCount(findings []sdk.Finding) int {
	total := 0
	for _, finding := range findings {
		if finding.Disposition == "" || finding.Disposition == sdk.FindingDispositionFail {
			total++
		}
	}
	return total
}

// SummaryFromFindings aggregates finding counts by severity band.
func SummaryFromFindings(findings []sdk.Finding) *AuditSummary {
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

// ScanTargetResponse represents one target-specific scan payload.
type ScanTargetResponse struct {
	Project      ProjectDescriptor `json:"project"`
	Detector     string            `json:"detector,omitempty"`
	Dependencies []ScanDependency  `json:"dependencies"`
}

// ScanDependency is one detection-stage dependency node in a manifest. It is a
// lean projection of sdk.Dependency: identity, scopes, edges, detection-time
// licenses, and a package_ref (PURL) link into the top-level packages
// collection. Matching-stage enrichment (vulnerabilities, scorecard, EOL,
// licenses learned during matching) is NOT carried here — it lives on the
// resolved ScanPackageEntry referenced by PackageRef.
type ScanDependency struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Purl       string        `json:"purl,omitempty"`
	Scopes     []string      `json:"scopes,omitempty"`
	DependsOn  []string      `json:"depends_on"`
	Matched    bool          `json:"matched,omitempty"`
	PackageRef string        `json:"package_ref,omitempty"`
	Locations  []LocationRef `json:"locations,omitempty"`
	Licenses   []LicenseRef  `json:"licenses"`
}

// PrimaryScope returns the merged precedence scope across the dependency's
// recorded scopes, mirroring sdk.Dependency.PrimaryScope so text/markdown
// renderers reproduce the same scope label as before the model split.
func (d ScanDependency) PrimaryScope() string {
	result := sdk.ScopeUnknown
	for _, scope := range d.Scopes {
		result = sdk.MergeScope(result, sdk.Scope(scope))
	}
	return string(result)
}

// ScanPackageEntry is one matching-stage artifact in the top-level packages
// collection: a PURL-keyed, deduplicated projection of sdk.Package carrying the
// enrichment (licenses, vulnerabilities, scorecard, EOL, CPEs, digests) that
// manifest dependencies reference by package_ref.
type ScanPackageEntry struct {
	Purl            string                `json:"purl"`
	Name            string                `json:"name,omitempty"`
	Org             string                `json:"org,omitempty"`
	Version         string                `json:"version,omitempty"`
	Ecosystem       string                `json:"ecosystem,omitempty"`
	Matched         bool                  `json:"matched,omitempty"`
	Licenses        []LicenseRef          `json:"licenses"`
	Vulnerabilities []VulnerabilityRef    `json:"vulnerabilities"`
	Scorecard       *sdk.PackageScorecard `json:"scorecard,omitempty"`
	EOL             *sdk.PackageEOL       `json:"eol,omitempty"`
	CPEs            []string              `json:"cpes,omitempty"`
	Digests         []sdk.Digest          `json:"digests,omitempty"`
	Metadata        map[string]any        `json:"metadata,omitempty"`
}

func (p ScanPackageEntry) withoutReachability() ScanPackageEntry {
	if len(p.Vulnerabilities) > 0 {
		p.Vulnerabilities = append([]VulnerabilityRef(nil), p.Vulnerabilities...)
		for idx := range p.Vulnerabilities {
			p.Vulnerabilities[idx].Reachability = nil
		}
	}
	return p
}

// DependenciesFromGraph converts a graph into stable, lean scan dependency
// payloads. registry, when non-nil, supplies the Matched flag via PURL lookup;
// all richer enrichment is surfaced through PackagesFromRegistry instead.
func DependenciesFromGraph(g *sdk.Graph, registry *sdk.PackageRegistry) []ScanDependency {
	if g == nil {
		return nil
	}

	nodes := g.Nodes()
	payload := make([]ScanDependency, 0, len(nodes))
	for _, dep := range nodes {
		if dep == nil {
			continue
		}
		deps, err := g.DirectDependencies(dep.ID)
		dependencyIDs := make([]string, 0, len(deps))
		if err == nil {
			for _, child := range deps {
				if child == nil {
					continue
				}
				dependencyIDs = append(dependencyIDs, child.ID)
			}
		}
		scopes := make([]string, 0, len(dep.Scopes))
		for _, scope := range dep.Scopes {
			scopes = append(scopes, string(scope))
		}
		matched := dep.Matched
		if pkg := lookupRegistryPackage(registry, dep.PURL); pkg != nil {
			matched = matched || pkg.Matched
		}
		payload = append(payload, ScanDependency{
			ID:         dep.ID,
			Name:       dep.DisplayName(),
			Version:    dep.Version,
			Purl:       dep.PURL,
			Scopes:     scopes,
			DependsOn:  dependencyIDs,
			Matched:    matched,
			PackageRef: dep.PackageRef,
			Locations:  LocationRefsFromGraphLocations(dep.Locations),
			Licenses:   LicenseRefsFromGraphLicenses(sdk.DetectionLicenses(dep)),
		})
	}
	sort.Slice(payload, func(i, j int) bool {
		return payload[i].ID < payload[j].ID
	})
	for idx := range payload {
		sort.Strings(payload[idx].DependsOn)
	}
	return payload
}

// PackagesFromRegistry projects the matching-stage registry into the top-level
// packages collection, deduplicated by PURL. registry.All() is already
// PURL-sorted. Returns a non-nil (possibly empty) slice so JSON consumers
// always see a "packages" array.
func PackagesFromRegistry(registry *sdk.PackageRegistry) []ScanPackageEntry {
	if registry == nil {
		return []ScanPackageEntry{}
	}
	all := registry.All()
	payload := make([]ScanPackageEntry, 0, len(all))
	for _, pkg := range all {
		if pkg == nil {
			continue
		}
		entry := ScanPackageEntry{
			Purl:            pkg.PURL,
			Name:            pkg.DisplayName(),
			Org:             pkg.Org,
			Version:         pkg.Version,
			Ecosystem:       string(pkg.Ecosystem),
			Matched:         pkg.Matched,
			Licenses:        LicenseRefsFromGraphLicenses(pkg.Licenses),
			Vulnerabilities: VulnerabilityRefsFromPackageVulnerabilities(pkg.Vulnerabilities),
			Scorecard:       pkg.Scorecard.Clone(),
			EOL:             pkg.EOL.Clone(),
			CPEs:            append([]string(nil), pkg.CPEs...),
			Digests:         append([]sdk.Digest(nil), pkg.Digests...),
			Metadata:        cloneRefMetadata(pkg.Metadata),
		}
		payload = append(payload, entry)
	}
	return payload
}
