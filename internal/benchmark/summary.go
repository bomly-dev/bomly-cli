package benchmark

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
)

const summarySchemaVersion = "bomly.benchmark.v1"

// PackageMetrics describes PURL-normalized package overlap.
type PackageMetrics struct {
	BomlyCount      int     `json:"bomly_count"`
	SourceCount     int     `json:"source_count"`
	ExactMatches    int     `json:"exact_matches"`
	VersionMismatch int     `json:"version_mismatches"`
	BomlyOnly       int     `json:"bomly_only"`
	SourceOnly      int     `json:"source_only"`
	BomlyIgnored    int     `json:"bomly_ignored_without_purl"`
	SourceIgnored   int     `json:"source_ignored_without_purl"`
	Score           float64 `json:"score"`
}

// RelationshipMetrics describes PURL-normalized dependency-edge overlap.
type RelationshipMetrics struct {
	BomlyCount  int      `json:"bomly_count"`
	SourceCount int      `json:"source_count"`
	Matched     int      `json:"matched"`
	BomlyOnly   int      `json:"bomly_only"`
	SourceOnly  int      `json:"source_only"`
	Score       *float64 `json:"score,omitempty"`
}

// ScoreSummary contains the benchmark scores for one comparison or aggregate.
type ScoreSummary struct {
	Package      float64  `json:"package"`
	Relationship *float64 `json:"relationship,omitempty"`
	Overall      float64  `json:"overall"`
}

// SourceArtifacts records paths relative to one benchmark case directory.
type SourceArtifacts struct {
	SBOM     string `json:"sbom,omitempty"`
	RawSBOM  string `json:"raw_sbom,omitempty"`
	Diff     string `json:"diff,omitempty"`
	Log      string `json:"log,omitempty"`
	Response string `json:"response,omitempty"`
	Summary  string `json:"summary,omitempty"`
}

// SourceSummary describes one baseline comparison.
type SourceSummary struct {
	Source        string               `json:"source"`
	Status        string               `json:"status"`
	Reason        string               `json:"reason,omitempty"`
	Artifacts     SourceArtifacts      `json:"artifacts,omitempty"`
	Detectors     []string             `json:"used_detectors,omitempty"`
	Packages      *PackageMetrics      `json:"packages,omitempty"`
	Relationships *RelationshipMetrics `json:"relationships,omitempty"`
	BomlyScope    *ScopeSummary        `json:"bomly_scope,omitempty"`
	SourceScope   *ScopeSummary        `json:"source_scope,omitempty"`
	Scores        *ScoreSummary        `json:"scores,omitempty"`
}

// ScopeSummary describes scope metadata availability for one SBOM source.
type ScopeSummary struct {
	KnownScopeCount   int            `json:"known_scope_count"`
	UnknownScopeCount int            `json:"unknown_scope_count"`
	Scopes            map[string]int `json:"scopes,omitempty"`
}

// CaseSummary describes one repository comparison case.
type CaseSummary struct {
	SchemaVersion string          `json:"schema_version"`
	Case          string          `json:"case"`
	Repository    string          `json:"repository"`
	HeadSHA       string          `json:"head_sha,omitempty"`
	Ecosystem     sdk.Ecosystem   `json:"ecosystem"`
	Status        string          `json:"status"`
	Reason        string          `json:"reason,omitempty"`
	Detectors     []string        `json:"used_detectors,omitempty"`
	Sources       []SourceSummary `json:"sources,omitempty"`
	Scores        *ScoreSummary   `json:"scores,omitempty"`
}

// RunSummary describes a complete hidden benchmark invocation.
type RunSummary struct {
	SchemaVersion string        `json:"schema_version"`
	Status        string        `json:"status"`
	Reason        string        `json:"reason,omitempty"`
	RunDir        string        `json:"run_dir"`
	Cases         []CaseSummary `json:"cases,omitempty"`
	Scores        *ScoreSummary `json:"scores,omitempty"`
}

// BuildSourceSummary compares two filtered SBOM documents.
func BuildSourceSummary(source string, bomlyDoc, sourceDoc *sbom.Document, artifacts SourceArtifacts) SourceSummary {
	packages := comparePackages(bomlyDoc, sourceDoc)
	relationships := compareRelationships(bomlyDoc, sourceDoc)
	return SourceSummary{
		Source:        source,
		Status:        "completed",
		Artifacts:     artifacts,
		Detectors:     detectorCreators(bomlyDoc),
		Packages:      &packages,
		Relationships: &relationships,
		BomlyScope:    summarizeScopes(bomlyDoc),
		SourceScope:   summarizeScopes(sourceDoc),
		Scores:        scoreSummary(packages.Score, relationships.Score),
	}
}

func comparePackages(bomlyDoc, sourceDoc *sbom.Document) PackageMetrics {
	bomly, bomlyIgnored := packagePURLs(bomlyDoc)
	source, sourceIgnored := packagePURLs(sourceDoc)
	metrics := PackageMetrics{
		BomlyCount:    len(bomly),
		SourceCount:   len(source),
		BomlyIgnored:  bomlyIgnored,
		SourceIgnored: sourceIgnored,
	}
	for purl := range bomly {
		if _, ok := source[purl]; !ok {
			continue
		}
		metrics.ExactMatches++
		delete(bomly, purl)
		delete(source, purl)
	}
	bomlyByBase := purlsByBase(bomly)
	sourceByBase := purlsByBase(source)
	for base, bomlyPURLs := range bomlyByBase {
		sourcePURLs := sourceByBase[base]
		matched := len(bomlyPURLs)
		if len(sourcePURLs) < matched {
			matched = len(sourcePURLs)
		}
		metrics.VersionMismatch += matched
		metrics.BomlyOnly += len(bomlyPURLs) - matched
		metrics.SourceOnly += len(sourcePURLs) - matched
		delete(sourceByBase, base)
	}
	for _, sourcePURLs := range sourceByBase {
		metrics.SourceOnly += len(sourcePURLs)
	}
	denominator := metrics.BomlyCount + metrics.SourceCount
	if denominator > 0 {
		metrics.Score = roundScore(100 * float64(2*metrics.ExactMatches+metrics.VersionMismatch) / float64(denominator))
	}
	return metrics
}

func compareRelationships(bomlyDoc, sourceDoc *sbom.Document) RelationshipMetrics {
	bomly := purlDependencyEdges(bomlyDoc)
	source := purlDependencyEdges(sourceDoc)
	metrics := RelationshipMetrics{BomlyCount: len(bomly), SourceCount: len(source)}
	for edge := range bomly {
		if _, ok := source[edge]; ok {
			metrics.Matched++
		} else {
			metrics.BomlyOnly++
		}
	}
	for edge := range source {
		if _, ok := bomly[edge]; !ok {
			metrics.SourceOnly++
		}
	}
	if denominator := metrics.BomlyCount + metrics.SourceCount; denominator > 0 {
		metrics.Score = new(roundScore(100 * float64(2*metrics.Matched) / float64(denominator)))
	}
	return metrics
}

func scoreSummary(packageScore float64, relationshipScore *float64) *ScoreSummary {
	out := &ScoreSummary{Package: packageScore, Relationship: relationshipScore, Overall: packageScore}
	if relationshipScore != nil {
		out.Overall = roundScore((packageScore + *relationshipScore) / 2)
	}
	return out
}

func averageScores(items []*ScoreSummary) *ScoreSummary {
	if len(items) == 0 {
		return nil
	}
	var packageTotal, relationshipTotal, overallTotal float64
	relationshipCount := 0
	for _, item := range items {
		packageTotal += item.Package
		overallTotal += item.Overall
		if item.Relationship != nil {
			relationshipTotal += *item.Relationship
			relationshipCount++
		}
	}
	out := &ScoreSummary{
		Package: roundScore(packageTotal / float64(len(items))),
		Overall: roundScore(overallTotal / float64(len(items))),
	}
	if relationshipCount > 0 {
		out.Relationship = new(roundScore(relationshipTotal / float64(relationshipCount)))
	}
	return out
}

// FilterDocument returns a copy containing only packages from ecosystem and their relationships.
func FilterDocument(doc *sbom.Document, ecosystem sdk.Ecosystem) *sbom.Document {
	if doc == nil {
		return nil
	}
	out := *doc
	out.Components = nil
	out.Dependencies = nil
	out.Roots = nil
	kept := make(map[string]struct{})
	for _, component := range doc.Components {
		if componentEcosystem(component) != ecosystem {
			continue
		}
		out.Components = append(out.Components, component)
		kept[component.ID] = struct{}{}
	}
	for _, dependency := range doc.Dependencies {
		if _, ok := kept[dependency.Ref]; !ok {
			continue
		}
		filtered := sbom.Dependency{Ref: dependency.Ref}
		for _, child := range dependency.DependsOn {
			if _, ok := kept[child]; ok {
				filtered.DependsOn = append(filtered.DependsOn, child)
			}
		}
		out.Dependencies = append(out.Dependencies, filtered)
	}
	for _, root := range doc.Roots {
		if _, ok := kept[root]; ok {
			out.Roots = append(out.Roots, root)
		}
	}
	return &out
}

func componentEcosystem(component sbom.Component) sdk.Ecosystem {
	if value, err := sdk.ParseEcosystem(component.Ecosystem); err == nil {
		return value
	}
	if purl := sdk.ParsePackageURL(component.PURL); purl != nil {
		switch strings.ToLower(strings.TrimSpace(purl.Type)) {
		case "golang":
			return sdk.EcosystemGo
		case "pypi":
			return sdk.EcosystemPython
		case "nuget":
			return sdk.EcosystemDotNet
		case "cargo":
			return sdk.EcosystemRust
		case "composer":
			return sdk.EcosystemPHP
		case "gem":
			return sdk.EcosystemRuby
		case "cocoapods", "swift":
			return sdk.EcosystemSwift
		case "pub":
			return sdk.EcosystemDart
		case "hex":
			return sdk.EcosystemElixir
		case "conan":
			return sdk.EcosystemCPP
		case "githubactions":
			return sdk.EcosystemGitHub
		default:
			value, _ := sdk.ParseEcosystem(purl.Type)
			return value
		}
	}
	return sdk.EcosystemUnknown
}

func packagePURLs(doc *sbom.Document) (map[string]struct{}, int) {
	out := make(map[string]struct{})
	ignored := 0
	if doc == nil {
		return out, ignored
	}
	for _, component := range doc.Components {
		purl := sdk.CanonicalizePackageURL(component.PURL)
		if purl == "" {
			ignored++
			continue
		}
		out[purl] = struct{}{}
	}
	return out, ignored
}

func purlsByBase(purls map[string]struct{}) map[string][]string {
	out := make(map[string][]string)
	for purl := range purls {
		base := sdk.PackageURLBase(purl)
		out[base] = append(out[base], purl)
	}
	return out
}

func purlDependencyEdges(doc *sbom.Document) map[string]struct{} {
	edges := make(map[string]struct{})
	if doc == nil {
		return edges
	}
	purlsByID := make(map[string]string, len(doc.Components))
	for _, component := range doc.Components {
		if purl := sdk.CanonicalizePackageURL(component.PURL); purl != "" {
			purlsByID[component.ID] = purl
		}
	}
	for _, dependency := range doc.Dependencies {
		from := purlsByID[dependency.Ref]
		if from == "" {
			continue
		}
		for _, child := range dependency.DependsOn {
			if to := purlsByID[child]; to != "" {
				edges[from+" -> "+to] = struct{}{}
			}
		}
	}
	return edges
}

func detectorCreators(doc *sbom.Document) []string {
	if doc == nil {
		return nil
	}
	out := make([]string, 0)
	for _, tool := range doc.Tools {
		if name := strings.TrimPrefix(tool, "bomly-detector:"); name != tool {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func summarizeScopes(doc *sbom.Document) *ScopeSummary {
	summary := &ScopeSummary{Scopes: make(map[string]int)}
	if doc == nil {
		return summary
	}
	for _, component := range doc.Components {
		scope := strings.TrimSpace(component.Scope)
		if scope == "" {
			summary.UnknownScopeCount++
			continue
		}
		summary.KnownScopeCount++
		summary.Scopes[scope]++
	}
	if len(summary.Scopes) == 0 {
		summary.Scopes = nil
	}
	return summary
}

func roundScore(value float64) float64 {
	return math.Round(value*100) / 100
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
