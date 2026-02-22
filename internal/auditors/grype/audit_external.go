//go:build !bomly_builtin_grype

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
	"github.com/bomly/bomly-cli/pkg/system"
)

// Audit matches packages against vulnerabilities by shelling out to the grype CLI binary.
func (a Auditor) Audit(_ context.Context, req scan.AuditRequest) (scan.AuditResult, error) {
	started := time.Now()
	if req.Graph == nil {
		return scan.AuditResult{}, nil
	}

	logger := a.logger()

	// Serialize graph as SPDX JSON to feed to grype stdin.
	spdxBytes, err := sbom.MarshalDepGraphJSON(req.Graph, sbom.TargetSPDX23JSON, sbom.BuildOptions{}, sbom.EncodeOptions{})
	if err != nil {
		return scan.AuditResult{}, fmt.Errorf("grype: serialize sbom: %w", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := system.Command("grype", "-o", "json")
	cmd.Stdin = bytes.NewReader(spdxBytes)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Debug("running external grype auditor")
	if err := cmd.Run(); err != nil {
		logger.Warn(fmt.Sprintf("grype CLI failed: %v (stderr: %s)", err, stderr.String()))
		return scan.AuditResult{Graph: req.Graph, Target: req.Target}, fmt.Errorf("grype audit failed: %w", err)
	}

	findings, err := parseGrypeJSONOutput(stdout.Bytes(), req.Graph)
	if err != nil {
		return scan.AuditResult{}, fmt.Errorf("grype: parse output: %w", err)
	}

	logger.Info(fmt.Sprintf("External grype audit found %d findings in %s", len(findings), logging.FormatDuration(time.Since(started))))
	return scan.AuditResult{
		Graph:    req.Graph,
		Target:   req.Target,
		Findings: findings,
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

func parseGrypeJSONOutput(data []byte, g *model.Graph) ([]scan.Finding, error) {
	var out grypeJSONOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode grype json: %w", err)
	}

	pkgByPURL := make(map[string]*model.Package)
	for _, p := range g.Packages() {
		if p.PURL != "" {
			pkgByPURL[p.PURL] = p
		}
	}

	findings := make([]scan.Finding, 0, len(out.Matches))
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

		findings = append(findings, scan.Finding{
			ID:       m.Vulnerability.ID,
			Kind:     scan.FindingKindVulnerability,
			Package:  graphPkg,
			Title:    title,
			Severity: strings.ToLower(m.Vulnerability.Severity),
			Reasons:  m.Vulnerability.URLs,
			Source:   auditorName,
		})
	}
	return findings, nil
}
