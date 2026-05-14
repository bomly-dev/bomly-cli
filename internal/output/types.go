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
	DurationMS    int64                            `json:"duration_ms"`
	AnalyzerRuns  []string                         `json:"analyzer_runs,omitempty"`
	AnalyzerStats map[string]sdk.ReachabilityStats `json:"analyzer_stats,omitempty"`
}

// ProjectDescriptor describes the project being analyzed.
type ProjectDescriptor struct {
	Name           string `json:"name,omitempty"`
	Path           string `json:"path"`
	TargetType     string `json:"target_type,omitempty"`
	TargetRef      string `json:"target_ref,omitempty"`
	Ecosystem      string `json:"ecosystem"`
	PackageManager string `json:"package_manager,omitempty"`
}

// LicenseRef identifies one package license in command outputs.
type LicenseRef struct {
	Value          string `json:"value,omitempty"`
	SPDXExpression string `json:"spdxExpression,omitempty"`
	Type           string `json:"type,omitempty"`
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
	Severity             string               `json:"severity,omitempty"`
	SeveritySource       string               `json:"severity_source,omitempty"`
	Aliases              []string             `json:"aliases,omitempty"`
	Description          string               `json:"description,omitempty"`
	Reasons              []string             `json:"reasons,omitempty"`
	CVSS                 []sdk.CVSSScore      `json:"cvss,omitempty"`
	FixedIn              string               `json:"fixed_in,omitempty"`
	AffectedVersionRange string               `json:"affected_version_range,omitempty"`
	References           []sdk.Reference      `json:"references,omitempty"`
	KEVExploited         bool                 `json:"kev_exploited,omitempty"`
	AffectedSymbols      []sdk.AffectedSymbol `json:"affected_symbols,omitempty"`
	Reachability         *sdk.Reachability    `json:"reachability,omitempty"`
}

// PackageRef identifies a package in command outputs.
type PackageRef struct {
	Name            string             `json:"name"`
	Version         string             `json:"version,omitempty"`
	Scope           string             `json:"scope,omitempty"`
	Purl            string             `json:"purl,omitempty"`
	ID              string             `json:"id,omitempty"`
	Metadata        map[string]any     `json:"metadata,omitempty"`
	Locations       []LocationRef      `json:"locations,omitempty"`
	Licenses        []LicenseRef       `json:"licenses"`
	Vulnerabilities []VulnerabilityRef `json:"vulnerabilities"`
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

// PackageFromGraphPackage converts a model package into a PackageRef.
func PackageFromGraphPackage(pkg *sdk.Package) PackageRef {
	if pkg == nil {
		return PackageRef{Licenses: []LicenseRef{}, Vulnerabilities: []VulnerabilityRef{}}
	}
	return PackageRef{
		Name:            pkg.DisplayName(),
		Version:         pkg.Version,
		Scope:           pkg.Scope,
		Purl:            pkg.PURL,
		ID:              pkg.ID,
		Metadata:        cloneRefMetadata(pkg.Metadata),
		Locations:       LocationRefsFromGraphLocations(pkg.Locations),
		Licenses:        LicenseRefsFromGraphLicenses(pkg.Licenses),
		Vulnerabilities: VulnerabilityRefsFromPackageVulnerabilities(pkg.Vulnerabilities),
	}
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
func VulnerabilityRefsFromPackageVulnerabilities(vulnerabilities []sdk.PackageVulnerability) []VulnerabilityRef {
	if len(vulnerabilities) == 0 {
		return []VulnerabilityRef{}
	}
	out := make([]VulnerabilityRef, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		out = append(out, VulnerabilityRef{
			ID:                   vulnerability.ID,
			Source:               vulnerability.Source,
			Title:                vulnerability.Title,
			Severity:             vulnerability.Severity,
			SeveritySource:       vulnerability.SeveritySource,
			Aliases:              append([]string(nil), vulnerability.Aliases...),
			Description:          vulnerability.Description,
			Reasons:              append([]string(nil), vulnerability.Reasons...),
			CVSS:                 append([]sdk.CVSSScore(nil), vulnerability.CVSS...),
			FixedIn:              vulnerability.FixedIn,
			AffectedSymbols:      cloneAffectedSymbols(vulnerability.AffectedSymbols),
			Reachability:         vulnerability.Reachability.Clone(),
			AffectedVersionRange: vulnerability.AffectedVersionRange,
			References:           append([]sdk.Reference(nil), vulnerability.References...),
			KEVExploited:         vulnerability.KEVExploited,
		})
	}
	return out
}

// AuditFinding is the serialized form of one normalized scan finding.
type AuditFinding struct {
	ID           string            `json:"id"`
	Kind         string            `json:"kind"`
	Severity     string            `json:"severity"`
	Package      PackageRef        `json:"package"`
	Title        string            `json:"title"`
	Reasons      []string          `json:"reasons,omitempty"`
	Source       string            `json:"source"`
	Reachability *sdk.Reachability `json:"reachability,omitempty"`
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
func FindingsFromScan(findings []sdk.Finding) []AuditFinding {
	result := make([]AuditFinding, 0, len(findings))
	for _, f := range findings {
		result = append(result, AuditFinding{
			ID:           f.ID,
			Kind:         string(f.Kind),
			Severity:     f.Severity,
			Package:      PackageFromGraphPackage(f.Package),
			Title:        f.Title,
			Reasons:      f.Reasons,
			Source:       f.Source,
			Reachability: f.Reachability.Clone(),
		})
	}
	return result
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
	Project  ProjectDescriptor `json:"project"`
	Detector string            `json:"detector,omitempty"`
	Packages []ScanPackage     `json:"packages"`
}

// ScanPackage is one dependency plus its direct dependency IDs.
type ScanPackage struct {
	PackageRef
	Dependencies []string `json:"dependencies"`
}

// PackagesFromGraph converts a graph into stable scan package payloads.
func PackagesFromGraph(g *sdk.Graph) []ScanPackage {
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
			PackageRef:   PackageFromGraphPackage(pkg),
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
