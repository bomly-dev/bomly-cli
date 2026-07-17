package mcp

import (
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// maxExplainPaths caps how many root-to-target chains one match reports.
const maxExplainPaths = 10

// explainHint tells agents what this response covers.
const explainHint = "Vulnerabilities carries the full advisory detail (description, references, CVSS, affected ranges) for the queried package only — this tool is the drill-down for one package at a time."

// CompactExplainMatch is one resolved target for the queried package:
// where it sits in the graph, its full advisory detail, and the remediation
// context for its findings.
type CompactExplainMatch struct {
	Package        output.PackageRef  `json:"package"`
	Direct         *bool              `json:"direct,omitempty"`
	Paths          [][]string         `json:"paths,omitempty"`
	Remediations   []RemediationGroup `json:"remediations,omitempty"`
	Findings       []CompactFinding   `json:"findings,omitempty"`
	ManifestPath   string             `json:"manifest_path,omitempty"`
	PackageManager string             `json:"package_manager,omitempty"`
}

// CompactExplainResponse is the bomly_explain tool result: dependency paths
// plus full advisory detail and integrated fix context for one package.
// Bounded by construction — one package's advisories are a few KB.
type CompactExplainResponse struct {
	SchemaVersion string                `json:"schema_version"`
	Command       string                `json:"command"`
	Query         string                `json:"query"`
	Matches       []CompactExplainMatch `json:"matches"`
	Diagnostics   []Diagnostic          `json:"diagnostics,omitempty"`
	Truncation    *TruncationInfo       `json:"truncation,omitempty"`
	Hint          string                `json:"hint,omitempty"`
}

// BuildCompactExplain projects an explain run into the agent-facing shape.
// The full ExplainResponse target payloads stay the source of paths and
// package identity; the raw findings/graph/registry attach remediation.
func BuildCompactExplain(query string, run ExplainRunResult) CompactExplainResponse {
	response := CompactExplainResponse{
		SchemaVersion: CompactSchemaVersion,
		Command:       "explain",
		Query:         query,
		Diagnostics:   capDiagnostics(run.Diagnostics),
		Hint:          explainHint,
	}

	trunc := &TruncationInfo{}
	for _, target := range run.Response.Targets {
		match := CompactExplainMatch{
			// The full PackageRef — including its Vulnerabilities with
			// descriptions, references, CVSS, and affected ranges — IS the
			// drill-down payload this tool exists for.
			Package:        target.Dependency,
			PackageManager: target.PackageManager.Name(),
		}
		match.Paths, match.Direct = compactExplainPaths(target.Paths, trunc)
		if manifest := manifestForPurl(run.Manifests, target.Dependency.Purl); manifest != nil {
			match.ManifestPath = manifest.Path
		}

		remediation := buildRemediations(remediationInput{
			Findings:            findingsForPackage(run.Findings, target.Dependency.Purl),
			Graph:               run.Graph,
			Registry:            run.Registry,
			Manifests:           run.Manifests,
			IncludeReachability: run.Response.Metadata.ReachabilityEnabled,
		})
		match.Remediations = remediation.Remediations
		match.Findings = remediation.Informational
		mergeTruncation(trunc, remediation.Truncation)

		response.Matches = append(response.Matches, match)
	}

	if trunc.OmittedFindings > 0 || trunc.OmittedGroups > 0 || trunc.OmittedPackages > 0 || trunc.OmittedPaths > 0 {
		trunc.Truncated = true
		response.Truncation = trunc
	}
	return response
}

// compactExplainPaths flattens explain dependency paths into name@version
// chains, capped at maxExplainPaths and maxPathNodes per chain. Directness
// is derived from the shortest relationship seen.
func compactExplainPaths(paths []output.DependencyPath, trunc *TruncationInfo) ([][]string, *bool) {
	if len(paths) == 0 {
		return nil, nil
	}
	direct := false
	known := false
	out := make([][]string, 0, len(paths))
	for idx, path := range paths {
		switch path.Relationship {
		case "direct":
			direct = true
			known = true
		case "transitive":
			known = true
		}
		if idx >= maxExplainPaths {
			trunc.OmittedPaths++
			continue
		}
		chain := make([]string, 0, len(path.Packages))
		for nodeIdx, pkg := range path.Packages {
			if nodeIdx == maxPathNodes-1 && len(path.Packages) > maxPathNodes {
				chain = append(chain, "…")
				last := path.Packages[len(path.Packages)-1]
				chain = append(chain, packageRefLabel(last))
				break
			}
			chain = append(chain, packageRefLabel(pkg))
		}
		out = append(out, chain)
	}
	if !known {
		return out, nil
	}
	return out, &direct
}

func packageRefLabel(pkg output.PackageRef) string {
	switch {
	case pkg.Name != "" && pkg.Version != "":
		return pkg.Name + "@" + pkg.Version
	case pkg.Name != "":
		return pkg.Name
	default:
		return pkg.ID
	}
}

// findingsForPackage filters findings to those referencing purl. An empty
// purl keeps everything (identity could not be resolved).
func findingsForPackage(findings []sdk.Finding, purl string) []sdk.Finding {
	if purl == "" {
		return findings
	}
	out := make([]sdk.Finding, 0, len(findings))
	for _, f := range findings {
		if f.PackageRef == purl {
			out = append(out, f)
		}
	}
	return out
}

// manifestForPurl finds the first manifest declaring a dependency with purl.
func manifestForPurl(manifests []output.ScanManifest, purl string) *output.ScanManifest {
	if purl == "" {
		return nil
	}
	for idx := range manifests {
		for _, dep := range manifests[idx].Dependencies {
			if dep.Purl == purl {
				return &manifests[idx]
			}
		}
	}
	return nil
}
