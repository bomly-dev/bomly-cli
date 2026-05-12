package qa

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// PackageDiffSummary is copied from bomly diff's deterministic JSON summary.
type PackageDiffSummary struct {
	AddedManifestCount     int `json:"added_manifest_count"`
	ChangedManifestCount   int `json:"changed_manifest_count"`
	RemovedManifestCount   int `json:"removed_manifest_count"`
	UnchangedManifestCount int `json:"unchanged_manifest_count"`
	AddedPackageCount      int `json:"added_package_count"`
	ChangedPackageCount    int `json:"changed_package_count"`
	RemovedPackageCount    int `json:"removed_package_count"`
}

// RelationshipSummary describes PURL-normalized dependency edge overlap.
type RelationshipSummary struct {
	BomlyRelationshipCount  int `json:"bomly_relationship_count"`
	SourceRelationshipCount int `json:"source_relationship_count"`
	MatchedCount            int `json:"matched_count"`
	BomlyOnlyCount          int `json:"bomly_only_count"`
	SourceOnlyCount         int `json:"source_only_count"`
}

// ScopeSummary describes scope metadata availability for one SBOM source.
type ScopeSummary struct {
	KnownScopeCount   int            `json:"known_scope_count"`
	UnknownScopeCount int            `json:"unknown_scope_count"`
	Scopes            map[string]int `json:"scopes,omitempty"`
}

// QASummary is the deterministic per-case dependency graph QA summary.
type QASummary struct {
	Case      string            `json:"case"`
	Status    string            `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	Sources   []QASourceSummary `json:"sources,omitempty"`
	Detectors []string          `json:"used_detectors,omitempty"`
}

// QASourceSummary is the deterministic comparison summary for one baseline source.
type QASourceSummary struct {
	Case          string               `json:"case"`
	Source        string               `json:"source"`
	Status        string               `json:"status"`
	Reason        string               `json:"reason,omitempty"`
	Artifacts     SourceArtifacts      `json:"artifacts,omitempty"`
	Detectors     []string             `json:"used_detectors,omitempty"`
	PackageDiff   *PackageDiffSummary  `json:"package_diff,omitempty"`
	Relationships *RelationshipSummary `json:"relationships,omitempty"`
	BomlyScope    *ScopeSummary        `json:"bomly_scope,omitempty"`
	SourceScope   *ScopeSummary        `json:"source_scope,omitempty"`
}

// SourceArtifacts records source-specific QA artifact paths relative to a case directory.
type SourceArtifacts struct {
	SBOM    string `json:"sbom,omitempty"`
	Diff    string `json:"diff,omitempty"`
	DiffLog string `json:"diff_log,omitempty"`
	Log     string `json:"log,omitempty"`
	Summary string `json:"summary,omitempty"`
}

// WriteStatusSummary writes a skipped or failed summary without requiring SBOM inputs.
func WriteStatusSummary(path, caseName, status, reason string) error {
	summary := QASummary{Case: caseName, Status: status, Reason: reason}
	return writeJSON(path, summary)
}

// WriteSourceStatusSummary writes a skipped or failed source summary.
func WriteSourceStatusSummary(path, caseName, sourceName, status, reason string, artifacts SourceArtifacts, detectors []string) error {
	summary := QASourceSummary{Case: caseName, Source: sourceName, Status: status, Reason: reason, Artifacts: artifacts, Detectors: detectors}
	return writeJSON(path, summary)
}

// BuildQASummary aggregates source summaries for one case.
func BuildQASummary(caseName string, sourceSummaries []QASourceSummary, detectors []string) QASummary {
	status := "completed"
	for _, sourceSummary := range sourceSummaries {
		if sourceSummary.Status == "failed" {
			status = "failed"
			break
		}
	}
	return QASummary{
		Case:      caseName,
		Status:    status,
		Sources:   sourceSummaries,
		Detectors: detectors,
	}
}

// BuildQASourceSummary derives deterministic package, relationship, and scope counts.
func BuildQASourceSummary(caseName, sourceName, bomlySBOMPath, sourceSBOMPath, diffPath string, artifacts SourceArtifacts) (QASourceSummary, error) {
	diffSummary, err := loadPackageDiffSummary(diffPath)
	if err != nil {
		return QASourceSummary{}, err
	}
	bomlyDoc, err := loadSBOMDocument(bomlySBOMPath)
	if err != nil {
		return QASourceSummary{}, fmt.Errorf("load bomly sbom: %w", err)
	}
	sourceDoc, err := loadSBOMDocument(sourceSBOMPath)
	if err != nil {
		return QASourceSummary{}, fmt.Errorf("load %s sbom: %w", sourceName, err)
	}
	relationshipSummary := compareRelationships(bomlyDoc, sourceDoc)
	bomlyScope := summarizeScopes(bomlyDoc)
	sourceScope := summarizeScopes(sourceDoc)
	return QASourceSummary{
		Case:          caseName,
		Source:        sourceName,
		Status:        "completed",
		Artifacts:     artifacts,
		Detectors:     detectorCreators(bomlyDoc),
		PackageDiff:   &diffSummary,
		Relationships: &relationshipSummary,
		BomlyScope:    &bomlyScope,
		SourceScope:   &sourceScope,
	}, nil
}

// WriteQASummary writes a completed per-case summary to path.
func WriteQASummary(path string, summary QASummary) error {
	return writeJSON(path, summary)
}

// WriteQASourceSummary writes a completed per-source summary to path.
func WriteQASourceSummary(path string, summary QASourceSummary) error {
	return writeJSON(path, summary)
}

// UnwrapGitHubSBOM writes the SPDX SBOM object from GitHub's REST response.
func UnwrapGitHubSBOM(inputPath, outputPath string) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read github sbom response: %w", err)
	}
	var payload struct {
		SBOM json.RawMessage `json:"sbom"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("parse github sbom response: %w", err)
	}
	if len(payload.SBOM) == 0 {
		return fmt.Errorf("github sbom response is missing sbom")
	}
	var normalized any
	if err := json.Unmarshal(payload.SBOM, &normalized); err != nil {
		return fmt.Errorf("parse github sbom document: %w", err)
	}
	return writeJSON(outputPath, normalized)
}

func loadPackageDiffSummary(path string) (PackageDiffSummary, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PackageDiffSummary{}, fmt.Errorf("read diff json: %w", err)
	}
	var payload struct {
		Summary PackageDiffSummary `json:"summary"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return PackageDiffSummary{}, fmt.Errorf("parse diff json: %w", err)
	}
	return payload.Summary, nil
}

func loadSBOMDocument(path string) (*sbom.Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, target, err := sbom.UnmarshalAutoJSON(raw)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, fmt.Errorf("unsupported sbom target %s", target)
	}
	return doc, nil
}

func detectorsFromSBOM(path string) ([]string, error) {
	doc, err := loadSBOMDocument(path)
	if err != nil {
		return nil, err
	}
	return detectorCreators(doc), nil
}
func compareRelationships(bomlyDoc, githubDoc *sbom.Document) RelationshipSummary {
	bomlyEdges := purlDependencyEdges(bomlyDoc)
	githubEdges := purlDependencyEdges(githubDoc)
	summary := RelationshipSummary{
		BomlyRelationshipCount:  len(bomlyEdges),
		SourceRelationshipCount: len(githubEdges),
	}
	for edge := range bomlyEdges {
		if _, ok := githubEdges[edge]; ok {
			summary.MatchedCount++
		} else {
			summary.BomlyOnlyCount++
		}
	}
	for edge := range githubEdges {
		if _, ok := bomlyEdges[edge]; !ok {
			summary.SourceOnlyCount++
		}
	}
	return summary
}

func detectorCreators(doc *sbom.Document) []string {
	if doc == nil {
		return nil
	}
	out := make([]string, 0)
	for _, tool := range doc.Tools {
		name := strings.TrimPrefix(tool, "bomly-detector:")
		if name == tool {
			continue
		}
		out = append(out, name)
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
		purl := sdk.CanonicalizePackageURL(component.PURL)
		if purl == "" {
			continue
		}
		purlsByID[component.ID] = purl
	}
	for _, dep := range doc.Dependencies {
		from := purlsByID[dep.Ref]
		if from == "" {
			continue
		}
		for _, depID := range dep.DependsOn {
			to := purlsByID[depID]
			if to == "" {
				continue
			}
			edges[from+" -> "+to] = struct{}{}
		}
	}
	return edges
}

func summarizeScopes(doc *sbom.Document) ScopeSummary {
	summary := ScopeSummary{Scopes: make(map[string]int)}
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
