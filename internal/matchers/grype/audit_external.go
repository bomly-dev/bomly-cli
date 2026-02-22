//go:build bomly_external_grype

package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bomly/bomly-cli/internal/logging"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/sbom"
	"github.com/bomly/bomly-cli/internal/scan"
	"github.com/bomly/bomly-cli/internal/system"
)

// Match attaches Grype vulnerability matches by shelling out to the grype CLI binary.
func (a Matcher) Match(_ context.Context, req scan.MatchRequest) (scan.MatchResult, error) {
	started := time.Now()
	if req.Graph == nil {
		return scan.MatchResult{}, nil
	}

	logger := a.logger()

	// Serialize graph as SPDX JSON to feed to grype stdin.
	spdxBytes, err := sbom.MarshalDepGraphJSON(req.Graph, sbom.TargetSPDX23JSON, sbom.BuildOptions{}, sbom.EncodeOptions{})
	if err != nil {
		return scan.MatchResult{}, fmt.Errorf("grype: serialize sbom: %w", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := system.Command("grype", "-o", "json")
	cmd.Stdin = bytes.NewReader(spdxBytes)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Debug("running external grype matcher")
	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("grype CLI failed: %v (stderr: %s)", err, stderr.String()))
		return scan.MatchResult{Graph: req.Graph, Target: req.Target}, fmt.Errorf("grype match failed: %w", err)
	}

	err = parseGrypeJSONOutput(stdout.Bytes(), req.Graph)
	if err != nil {
		return scan.MatchResult{}, fmt.Errorf("grype: parse output: %w", err)
	}

	logger.Info(fmt.Sprintf("External grype enrichment completed in %s", logging.FormatDuration(time.Since(started))))
	return scan.MatchResult{
		Graph:  req.Graph,
		Target: req.Target,
	}, nil
}

// grypeJSONOutput represents the top-level structure of grype JSON output.
type grypeJSONOutput struct {
	Matches []grypeJSONMatch `json:"matches"`
}

type grypeJSONMatch struct {
	Vulnerability grypeJSONVuln     `json:"vulnerability"`
	Artifact      grypeJSONArtifact `json:"artifact"`
}

type grypeJSONVuln struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	URLs        []string `json:"urls"`
}

type grypeJSONArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

func parseGrypeJSONOutput(data []byte, g *model.Graph) error {
	var out grypeJSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("decode grype json: %w", err)
	}

	pkgByPURL := make(map[string]*model.Package)
	for _, p := range g.Packages() {
		if p.PURL != "" {
			pkgByPURL[p.PURL] = p
		}
	}

	for _, m := range out.Matches {
		graphPkg := pkgByPURL[m.Artifact.PURL]
		if graphPkg == nil {
			graphPkg = &model.Package{
				Name:    m.Artifact.Name,
				Version: m.Artifact.Version,
				PURL:    m.Artifact.PURL,
			}
		}

		title := m.Vulnerability.ID
		if m.Vulnerability.Description != "" {
			title = m.Vulnerability.Description
		}

		graphPkg.Matched = true
		graphPkg.Vulnerabilities = appendUniqueVulnerability(graphPkg.Vulnerabilities, model.PackageVulnerability{
			ID:          m.Vulnerability.ID,
			Title:       title,
			Severity:    strings.ToLower(m.Vulnerability.Severity),
			Description: m.Vulnerability.Description,
			Reasons:     append([]string(nil), m.Vulnerability.URLs...),
			Source:      matcherName,
		})
	}
	return nil
}
