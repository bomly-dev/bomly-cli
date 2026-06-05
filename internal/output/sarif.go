package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	osvHelpBase  = "https://osv.dev/vulnerability/"
)

// sarifLog is the root SARIF 2.1.0 document.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  sarifMessage    `json:"fullDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
	HelpURI          string          `json:"helpUri,omitempty"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifMessage     `json:"message"`
	Locations  []sarifLocation  `json:"locations"`
	CodeFlows  []sarifCodeFlow  `json:"codeFlows,omitempty"`
	Properties *sarifProperties `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifMessage         `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// sarifRegion is the SARIF 2.1.0 region descriptor. All numeric
// fields are 1-based; omitted when unknown. Used to deep-link from
// a result to the line in the lockfile where the affected
// dependency is declared.
type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// sarifCodeFlow carries Reachability call paths as SARIF 2.1.0 codeFlows.
// One CallPath becomes one threadFlow; one CallFrame becomes one location
// in that threadFlow with file/line/column from the analyzer's evidence.
type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}

// sarifProperties exposes Bomly-specific finding metadata SARIF consumers
// can surface. SARIF 2.1.0 allows arbitrary `properties` per result;
// these fields give consumers everything needed to triage a finding
// without parsing the parallel JSON output.
type sarifProperties struct {
	FixedIn                string               `json:"fixed_in,omitempty"`
	FixedVersions          []string             `json:"fixed_versions,omitempty"`
	FixState               string               `json:"fix_state,omitempty"`
	FixAvailable           []sdk.FixAvailable   `json:"fix_available,omitempty"`
	SeveritySource         string               `json:"severity_source,omitempty"`
	CVSS                   []sdk.CVSSScore      `json:"cvss,omitempty"`
	Aliases                []string             `json:"aliases,omitempty"`
	AffectedVersionRange   string               `json:"affected_version_range,omitempty"`
	References             []sdk.Reference      `json:"references,omitempty"`
	KEVExploited           bool                 `json:"kev_exploited,omitempty"`
	KnownExploited         []sdk.KnownExploited `json:"known_exploited,omitempty"`
	EPSS                   []sdk.EPSSScore      `json:"epss,omitempty"`
	CWEs                   []sdk.CWE            `json:"cwes,omitempty"`
	RiskScore              float64              `json:"risk_score,omitempty"`
	DataSource             string               `json:"data_source,omitempty"`
	Namespace              string               `json:"namespace,omitempty"`
	CPEs                   []string             `json:"cpes,omitempty"`
	Reachability           string               `json:"reachability,omitempty"`
	ReachabilityTier       string               `json:"reachability_tier,omitempty"`
	ReachabilityReason     string               `json:"reachability_reason,omitempty"`
	Analyzer               string               `json:"analyzer,omitempty"`
	ReachabilityConfidence string               `json:"reachability_confidence,omitempty"`
	ReachabilityHops       *int                 `json:"reachability_hops,omitempty"`
	DynamicImportsDetected bool                 `json:"reachability_dynamic_imports_detected,omitempty"`
}

// SARIFOptions controls optional experimental data in SARIF output.
type SARIFOptions struct {
	IncludeReachability bool
}

// WriteSARIF writes findings as a SARIF 2.1.0 document to w.
// toolName and toolVersion are used to populate the driver section.
// registry, when non-nil, is used to resolve f.PackageRef →
// *sdk.Package and f.VulnerabilityID → *sdk.Vulnerability so each result
// carries the rich properties (CVSS / EPSS / KEV / CWE / fix state /
// reachability call paths) as SARIF `properties` / `codeFlows`.
func WriteSARIF(w io.Writer, findings []sdk.Finding, registry *sdk.PackageRegistry, toolName, toolVersion string, options ...SARIFOptions) error {
	includeReachability := false
	if len(options) > 0 {
		includeReachability = options[0].IncludeReachability
	}
	// Deduplicate rules by finding ID.
	seen := map[string]bool{}
	rules := make([]sarifRule, 0, len(findings))
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		helpURI := ""
		if f.Source == "osv" {
			helpURI = osvHelpBase + f.ID
		}
		rules = append(rules, sarifRule{
			ID:               f.ID,
			ShortDescription: sarifMessage{Text: f.Title},
			FullDescription:  sarifMessage{Text: joinReasons(f.Reasons)},
			DefaultConfig:    sarifRuleConfig{Level: severityToSARIFLevel(f.Severity)},
			HelpURI:          helpURI,
		})
	}

	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		pkg := lookupRegistryPackage(registry, f.PackageRef)
		vuln := lookupVulnerability(pkg, f.VulnerabilityID, f.ID)
		msgText := f.Title
		if f.PackageRef != "" {
			msgText = fmt.Sprintf("%s in %s", f.Title, f.PackageRef)
		}
		result := sarifResult{
			RuleID:    f.ID,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: msgText},
			Locations: sarifLocationsForFinding(f, pkg, f.PackageRef),
		}
		if vuln != nil {
			props := sarifPropertiesFromVulnerability(vuln, includeReachability)
			if !sarifPropertiesEmpty(props) {
				result.Properties = &props
			}
			if includeReachability && vuln.Reachability != nil && len(vuln.Reachability.CallPaths) > 0 {
				result.CodeFlows = buildSARIFCodeFlows(vuln.Reachability.CallPaths)
			}
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           toolName,
						Version:        toolVersion,
						InformationURI: "https://bomly.dev",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifPropertiesEmpty(props sarifProperties) bool {
	return props.FixedIn == "" &&
		len(props.FixedVersions) == 0 &&
		props.FixState == "" &&
		len(props.FixAvailable) == 0 &&
		props.SeveritySource == "" &&
		len(props.CVSS) == 0 &&
		len(props.Aliases) == 0 &&
		props.AffectedVersionRange == "" &&
		len(props.References) == 0 &&
		!props.KEVExploited &&
		len(props.KnownExploited) == 0 &&
		len(props.EPSS) == 0 &&
		len(props.CWEs) == 0 &&
		props.RiskScore == 0 &&
		props.DataSource == "" &&
		props.Namespace == "" &&
		len(props.CPEs) == 0 &&
		props.Reachability == "" &&
		props.ReachabilityTier == "" &&
		props.ReachabilityReason == "" &&
		props.Analyzer == "" &&
		props.ReachabilityConfidence == "" &&
		props.ReachabilityHops == nil &&
		!props.DynamicImportsDetected
}

// buildSARIFCodeFlows converts reachability call paths into SARIF
// codeFlows. Returns nil if every path lacks frames so the final SARIF
// document keeps the codeFlows array absent for affected rules.
func buildSARIFCodeFlows(paths []sdk.CallPath) []sarifCodeFlow {
	flows := make([]sarifCodeFlow, 0, len(paths))
	for _, path := range paths {
		if len(path.Frames) == 0 {
			continue
		}
		locs := make([]sarifThreadFlowLocation, 0, len(path.Frames))
		for _, frame := range path.Frames {
			locs = append(locs, sarifThreadFlowLocation{
				Location: sarifLocation{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: frame.Position.File},
						Region:           sarifRegionFromPosition(frame.Position),
					},
					Message: &sarifMessage{Text: sarifFrameDescription(frame)},
				},
			})
		}
		flows = append(flows, sarifCodeFlow{ThreadFlows: []sarifThreadFlow{{Locations: locs}}})
	}
	if len(flows) == 0 {
		return nil
	}
	return flows
}

func sarifRegionFromPosition(p sdk.SourcePosition) *sarifRegion {
	if p.Line == 0 && p.Column == 0 && p.EndLine == 0 {
		return nil
	}
	return &sarifRegion{StartLine: p.Line, StartColumn: p.Column, EndLine: p.EndLine}
}

func sarifFrameDescription(frame sdk.CallFrame) string {
	switch {
	case frame.Function != "" && frame.Package != "":
		return frame.Package + "." + frame.Function
	case frame.Function != "":
		return frame.Function
	case frame.Package != "":
		return frame.Package
	default:
		return ""
	}
}

// sarifLocationsForFinding builds the SARIF Locations array for a
// finding. When the finding's package carries one or more
// PackageLocation entries with a non-nil Position, one SARIF
// location per entry is emitted with artifactLocation pointing at
// the source file and a region carrying the line / column. When the
// package has no positions, a single synthetic location is emitted
// with the package's qualified name as URI — preserves backward
// compat for SARIF consumers that already keyed on the package URI.
//
// PackageLocations without a Position but with a non-empty RealPath
// still get a SARIF location with artifactLocation.uri = RealPath
// and no region. This is honest: we know which file the dep lives
// in but not exactly where.
func sarifLocationsForFinding(f sdk.Finding, _ *sdk.Package, fallbackURI string) []sarifLocation {
	// Locations are a detection-time concern on *sdk.Dependency; the registry
	// Package carries the PURL identity used here as the synthetic SARIF URI.
	// SARIF requires a non-empty Locations array, so we always emit one.
	uri := strings.TrimSpace(fallbackURI)
	if uri == "" {
		uri = f.ID
	}
	return []sarifLocation{
		{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: uri},
			},
		},
	}
}

// sarifPropertiesFromVulnerability converts a registry Vulnerability into
// the SARIF properties bag. Reachability-related fields are omitted unless
// includeReachability is true.
func sarifPropertiesFromVulnerability(v *sdk.Vulnerability, includeReachability bool) sarifProperties {
	props := sarifProperties{
		FixedIn:              v.FixedIn,
		FixedVersions:        append([]string(nil), v.FixedVersions...),
		FixState:             v.FixState,
		FixAvailable:         append([]sdk.FixAvailable(nil), v.FixAvailable...),
		SeveritySource:       v.SeveritySource,
		CVSS:                 append([]sdk.CVSSScore(nil), v.CVSS...),
		Aliases:              append([]string(nil), v.Aliases...),
		AffectedVersionRange: v.AffectedVersionRange,
		References:           append([]sdk.Reference(nil), v.References...),
		KEVExploited:         v.KEVExploited,
		KnownExploited:       cloneKnownExploited(v.KnownExploited),
		EPSS:                 append([]sdk.EPSSScore(nil), v.EPSS...),
		CWEs:                 append([]sdk.CWE(nil), v.CWEs...),
		RiskScore:            v.RiskScore,
		DataSource:           v.DataSource,
		Namespace:            v.Namespace,
		CPEs:                 append([]string(nil), v.CPEs...),
	}
	if includeReachability && v.Reachability != nil {
		r := v.Reachability
		props.Reachability = string(r.Status)
		props.ReachabilityTier = string(r.Tier)
		props.ReachabilityReason = r.Reason
		props.Analyzer = r.Analyzer
		props.ReachabilityConfidence = string(r.Confidence)
		if r.Hops != nil {
			hops := *r.Hops
			props.ReachabilityHops = &hops
		}
		props.DynamicImportsDetected = r.DynamicImportsDetected
	}
	return props
}

func severityToSARIFLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func joinReasons(reasons []string) string {
	return strings.Join(reasons, " ")
}
