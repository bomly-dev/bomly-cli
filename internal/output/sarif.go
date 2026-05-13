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
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
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
		results = append(results, sarifResult{
			RuleID:    f.ID,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: msgText},
			Locations: sarifLocationsForFinding(f, pkgName),
		})
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
func sarifLocationsForFinding(f sdk.Finding, fallbackURI string) []sarifLocation {
	if f.Package != nil && len(f.Package.Locations) > 0 {
		locations := make([]sarifLocation, 0, len(f.Package.Locations))
		for _, loc := range f.Package.Locations {
			uri := strings.TrimSpace(loc.RealPath)
			if uri == "" {
				uri = strings.TrimSpace(loc.AccessPath)
			}
			if uri == "" {
				continue
			}
			pl := sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: uri},
			}
			if loc.Position != nil && (loc.Position.Line > 0 || loc.Position.Column > 0 || loc.Position.EndLine > 0) {
				pl.Region = &sarifRegion{
					StartLine:   loc.Position.Line,
					StartColumn: loc.Position.Column,
					EndLine:     loc.Position.EndLine,
				}
			}
			locations = append(locations, sarifLocation{PhysicalLocation: pl})
		}
		if len(locations) > 0 {
			return locations
		}
	}
	// Fallback: emit a synthetic location keyed on the package name
	// so SARIF consumers always have a non-empty Locations array
	// (the SARIF spec requires one).
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
