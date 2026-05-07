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
// can surface (reachability status, tier, analyzer name).
type sarifProperties struct {
	Reachability       string `json:"reachability,omitempty"`
	ReachabilityTier   string `json:"reachability_tier,omitempty"`
	ReachabilityReason string `json:"reachability_reason,omitempty"`
	Analyzer           string `json:"analyzer,omitempty"`
}

// WriteSARIF writes findings as a SARIF 2.1.0 document to w.
// toolName and toolVersion are used to populate the driver section.
func WriteSARIF(w io.Writer, findings []sdk.Finding, toolName, toolVersion string) error {
	// Deduplicate rules by finding ID.
	seen := map[string]bool{}
	var rules []sarifRule
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
		pkgName := ""
		pkgVersion := ""
		if f.Package != nil {
			pkgName = f.Package.QualifiedName()
			pkgVersion = f.Package.Version
		}
		msgText := f.Title
		if pkgName != "" {
			msgText = fmt.Sprintf("%s in %s@%s", f.Title, pkgName, pkgVersion)
		}
		artifactURI := pkgName
		if artifactURI == "" {
			artifactURI = f.ID
		}
		result := sarifResult{
			RuleID:  f.ID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: msgText},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
					},
				},
			},
		}
		if f.Reachability != nil {
			result.Properties = &sarifProperties{
				Reachability:       string(f.Reachability.Status),
				ReachabilityTier:   string(f.Reachability.Tier),
				ReachabilityReason: f.Reachability.Reason,
				Analyzer:           f.Reachability.Analyzer,
			}
			if flows := buildSARIFCodeFlows(f.Reachability.CallPaths); len(flows) > 0 {
				result.CodeFlows = flows
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
