package mcp

import (
	"sort"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// scanHint tells agents where the omitted detail lives.
const scanHint = "This is a compact remediation-focused view. Use bomly_explain for full advisory detail and dependency paths of one package; run `bomly scan --format json -o <file>` via the CLI when you need the complete document."

// BuildCompactScan projects a full scan run into the agent-facing compact
// response: ranked remediation groups, informational findings, coverage
// counts, and pipeline diagnostics. Without audit it returns a summary plus
// a capped package inventory.
func BuildCompactScan(run ScanRunResult) CompactScanResponse {
	response := CompactScanResponse{
		SchemaVersion: CompactSchemaVersion,
		Command:       "scan",
		Project: ProjectSummary{
			Name: run.Response.Project.Name,
			Path: run.Response.Project.Path,
		},
		Diagnostics: capDiagnostics(run.Diagnostics),
		Hint:        scanHint,
	}

	vulnerablePackages := map[string]struct{}{}
	for _, entry := range run.Response.Packages {
		if len(entry.Vulnerabilities) > 0 {
			vulnerablePackages[entry.Purl] = struct{}{}
		}
	}
	totalPackages := len(run.Response.Packages)
	if totalPackages == 0 {
		// Unenriched runs have an empty packages projection; count graph
		// dependencies instead so the summary stays meaningful.
		totalPackages = countManifestDependencies(run.Response.Manifests)
	}
	hierarchy := output.BuildHierarchy(run.Response.Manifests)
	response.Summary = CompactSummary{
		Manifests:          len(run.Response.Manifests),
		Subprojects:        hierarchy.CountKind(output.ManifestNodeSubproject),
		Modules:            hierarchy.CountKind(output.ManifestNodeModule),
		TotalPackages:      totalPackages,
		VulnerablePackages: len(vulnerablePackages),
		CleanPackages:      totalPackages - len(vulnerablePackages),
		EnrichRan:          run.EnrichRan,
		AuditRan:           run.AuditRan,
	}

	if !run.AuditRan {
		inventory, omitted := packageInventory(run.Response.Manifests)
		response.Packages = inventory
		if omitted > 0 {
			response.Truncation = &TruncationInfo{
				Truncated:       true,
				OmittedPackages: omitted,
				Note:            "package inventory capped; run `bomly scan --format json -o <file>` via the CLI for the full list",
			}
		}
		return response
	}

	result := buildRemediations(remediationInput{
		Findings:            run.Findings,
		Graph:               run.Graph,
		Registry:            run.Registry,
		Manifests:           run.Response.Manifests,
		IncludeReachability: run.Response.Metadata.ReachabilityEnabled,
	})
	response.Remediations = result.Remediations
	response.Informational = result.Informational
	response.Truncation = result.Truncation

	severityCounts := map[string]int{}
	actionable := 0
	for _, group := range result.Remediations {
		actionable += len(group.Fixes)
		for _, fix := range group.Fixes {
			severityCounts[severityBucket(fix.Severity)]++
		}
	}
	for _, fix := range result.Informational {
		severityCounts[severityBucket(fix.Severity)]++
	}
	response.Summary.FindingsBySeverity = severityCounts
	response.Summary.Actionable = actionable
	response.Summary.Informational = len(result.Informational)
	return response
}

func severityBucket(severity string) string {
	switch sdk.SeverityLevel(severity) {
	case sdk.SeverityCritical, sdk.SeverityHigh, sdk.SeverityMedium, sdk.SeverityLow:
		return severity
	default:
		if sdk.SeverityRank(sdk.SeverityLevel(severity)) > 0 {
			return severity
		}
		return "unknown"
	}
}

func countManifestDependencies(manifests []output.ScanManifest) int {
	seen := map[string]struct{}{}
	for _, manifest := range manifests {
		for _, dep := range manifest.Dependencies {
			key := dep.Purl
			if key == "" {
				key = dep.ID
			}
			seen[key] = struct{}{}
		}
	}
	return len(seen)
}

// packageInventory returns a deduplicated, sorted name@version list of every
// detected dependency, capped at maxInventoryEntries.
func packageInventory(manifests []output.ScanManifest) ([]string, int) {
	seen := map[string]struct{}{}
	for _, manifest := range manifests {
		for _, dep := range manifest.Dependencies {
			label := dep.Name
			if dep.Version != "" {
				label += "@" + dep.Version
			}
			if label == "" {
				continue
			}
			seen[label] = struct{}{}
		}
	}
	inventory := make([]string, 0, len(seen))
	for label := range seen {
		inventory = append(inventory, label)
	}
	sort.Strings(inventory)
	if len(inventory) > maxInventoryEntries {
		omitted := len(inventory) - maxInventoryEntries
		return inventory[:maxInventoryEntries], omitted
	}
	return inventory, 0
}

func capDiagnostics(diagnostics []Diagnostic) []Diagnostic {
	if len(diagnostics) <= maxDiagnosticsReported {
		return diagnostics
	}
	capped := append([]Diagnostic(nil), diagnostics[:maxDiagnosticsReported]...)
	capped = append(capped, Diagnostic{
		Stage:   "meta",
		Message: "additional diagnostics omitted; run the CLI with -v for the full set",
	})
	return capped
}
