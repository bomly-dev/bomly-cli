package mcp

// CompactSchemaVersion tags the agent-facing MCP response shapes. It is
// versioned independently of the CLI JSON schema: MCP responses are compact
// projections sized for tool-result limits, not the full document contract.
const CompactSchemaVersion = "mcp/1"

// Compact response caps. Anything cut by a cap is counted in TruncationInfo —
// never silently dropped.
const (
	maxFindingsPerGroup    = 15
	maxRemediationGroups   = 40
	maxInformational       = 60
	maxPathNodes           = 6
	maxAliases             = 3
	maxInventoryEntries    = 200
	maxDiagnosticsReported = 20
)

// Diagnostic surfaces one pipeline warning (detector fallback, matcher
// failure, analyzer degradation) so agents can see why results may be
// partial without re-running with -v.
type Diagnostic struct {
	Stage   string `json:"stage"`
	Source  string `json:"source,omitempty"`
	Message string `json:"message"`
}

// PackageIdentity carries the full identity of a package: the
// ecosystem-native display name (e.g. "@tailwindcss/postcss"), the org/scope
// component, and the PURL. Presentation code must never collapse scoped
// names to the bare name.
type PackageIdentity struct {
	Name      string `json:"name"`
	Org       string `json:"org,omitempty"`
	Version   string `json:"version,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Label returns a human-readable name@version label.
func (p PackageIdentity) Label() string {
	switch {
	case p.Name != "" && p.Version != "":
		return p.Name + "@" + p.Version
	case p.Name != "":
		return p.Name
	default:
		return p.Purl
	}
}

// Classification values for CompactFinding.Classification.
const (
	ClassificationFixAvailable  = "fix_available"
	ClassificationNoFixUpstream = "no_fix_upstream"
	ClassificationWontFix       = "wont_fix"
	ClassificationPolicyOnly    = "policy_only"
	ClassificationUnknown       = "unknown"
)

// CompactFinding is one actionable-or-informational finding, sized for agent
// consumption: advisory identifiers and fix data, no descriptions, reference
// URLs, or CVSS vectors. Full advisory detail for one package is available
// via the bomly_explain tool.
type CompactFinding struct {
	VulnID         string          `json:"vuln_id"`
	Kind           string          `json:"kind"`
	Aliases        []string        `json:"aliases,omitempty"`
	Severity       string          `json:"severity,omitempty"`
	Disposition    string          `json:"disposition,omitempty"`
	Classification string          `json:"classification"`
	Package        PackageIdentity `json:"package"`
	Direct         *bool           `json:"direct,omitempty"`
	ShortestPath   []string        `json:"shortest_path,omitempty"`
	FixedIn        string          `json:"fixed_in,omitempty"`
	KEV            bool            `json:"kev,omitempty"`
	EPSS           float64         `json:"epss,omitempty"`
	Reachability   string          `json:"reachability,omitempty"`
	Title          string          `json:"title,omitempty"`
}

// Remediation actions for RemediationGroup.Action.
const (
	ActionDirectBump         = "direct-bump"
	ActionTransitiveOverride = "transitive-override"
	ActionLockfileRefresh    = "lockfile-refresh"
	ActionNoFixUpstream      = "no-fix-upstream"
	ActionPolicyReview       = "policy-review"
)

// RemediationGroup is the integrated fix context: one concrete change (bump
// this direct dependency in this manifest to this version) and every finding
// that change closes. Groups are ranked most-urgent first.
type RemediationGroup struct {
	Action             string           `json:"action"`
	TargetPackage      PackageIdentity  `json:"target_package"`
	ManifestPath       string           `json:"manifest_path,omitempty"`
	PackageManager     string           `json:"package_manager,omitempty"`
	RecommendedVersion string           `json:"recommended_version,omitempty"`
	Recommendation     string           `json:"recommendation,omitempty"`
	Fixes              []CompactFinding `json:"fixes"`
}

// CompactSummary tells the agent what the scan covered and what the compact
// response omitted (clean packages are counted, not listed).
type CompactSummary struct {
	Manifests          int            `json:"manifests"`
	TotalPackages      int            `json:"total_packages"`
	VulnerablePackages int            `json:"vulnerable_packages,omitempty"`
	CleanPackages      int            `json:"clean_packages,omitempty"`
	FindingsBySeverity map[string]int `json:"findings_by_severity,omitempty"`
	Actionable         int            `json:"actionable,omitempty"`
	Informational      int            `json:"informational,omitempty"`
	EnrichRan          bool           `json:"enrich_ran"`
	AuditRan           bool           `json:"audit_ran"`
}

// TruncationInfo reports exactly what the caps cut so the agent knows the
// response is partial and how to drill down.
type TruncationInfo struct {
	Truncated       bool   `json:"truncated"`
	OmittedFindings int    `json:"omitted_findings,omitempty"`
	OmittedGroups   int    `json:"omitted_groups,omitempty"`
	OmittedPackages int    `json:"omitted_packages,omitempty"`
	Note            string `json:"note,omitempty"`
}

// CompactScanResponse is the bomly_scan tool result: remediation-grouped
// actionable findings plus counts of everything omitted. For the complete
// JSON document use the CLI (`bomly scan --format json`); for full advisory
// detail on one package use bomly_explain.
type CompactScanResponse struct {
	SchemaVersion string             `json:"schema_version"`
	Command       string             `json:"command"`
	Project       ProjectSummary     `json:"project"`
	Summary       CompactSummary     `json:"summary"`
	Remediations  []RemediationGroup `json:"remediations,omitempty"`
	Informational []CompactFinding   `json:"informational,omitempty"`
	Packages      []string           `json:"packages,omitempty"`
	Diagnostics   []Diagnostic       `json:"diagnostics,omitempty"`
	Truncation    *TruncationInfo    `json:"truncation,omitempty"`
	Hint          string             `json:"hint,omitempty"`
}

// ProjectSummary is a lean project descriptor for compact responses.
type ProjectSummary struct {
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}
