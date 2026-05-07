package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const auditorName = "severity-policy"

// Auditor evaluates enriched vulnerability data against a severity threshold.
type Auditor struct {
	FailOn string
}

// Descriptor returns the registration metadata for the policy auditor.
func (a Auditor) Descriptor() sdk.AuditorDescriptor {
	return sdk.AuditorDescriptor{
		Name:                auditorName,
		Enabled:             true,
		Origin:              sdk.CoreOrigin,
		SupportedEcosystems: nil,
		SupportedModes:      []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
	}
}

func (a Auditor) Ready() bool {
	return true
}

func (a Auditor) Applicable(_ context.Context, req sdk.AuditRequest) (bool, error) {
	if len(req.AuditorFilter.Exclude) > 0 && req.AuditorFilter.Excludes(auditorName) {
		return false, nil
	}
	if len(req.AuditorFilter.Include) > 0 && !req.AuditorFilter.Includes(auditorName) {
		return false, nil
	}
	return true, nil
}

// Audit evaluates enriched vulnerabilities and emits findings for entries that meet the configured threshold.
func (a Auditor) Audit(_ context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
	if req.Graph == nil {
		return sdk.AuditResult{}, nil
	}

	threshold, err := ParseSeverityThreshold(a.FailOn)
	if err != nil {
		return sdk.AuditResult{}, fmt.Errorf("parse fail-on severity: %w", err)
	}

	packages := req.Graph.Packages()
	if req.Mode == sdk.TargetModeComponent && req.Target != nil {
		packages = []*sdk.Package{req.Target}
	}

	findings := make([]sdk.Finding, 0)
	for _, pkg := range packages {
		if pkg == nil {
			continue
		}
		for _, vulnerability := range collapsePreferredVulnerabilities(pkg.Vulnerabilities) {
			if !threshold.Matches(vulnerability.Severity) {
				continue
			}
			title := strings.TrimSpace(vulnerability.Title)
			if title == "" {
				title = vulnerability.ID
			}
			findings = append(findings, sdk.Finding{
				ID:                   vulnerability.ID,
				Kind:                 sdk.FindingKindVulnerability,
				Package:              pkg,
				Title:                title,
				Severity:             strings.ToLower(strings.TrimSpace(vulnerability.Severity)),
				Reasons:              append([]string(nil), vulnerability.Reasons...),
				Source:               vulnerability.Source,
				Aliases:              append([]string(nil), vulnerability.Aliases...),
				Description:          vulnerability.Description,
				SeveritySource:       vulnerability.SeveritySource,
				CVSS:                 append([]sdk.CVSSScore(nil), vulnerability.CVSS...),
				FixedIn:              vulnerability.FixedIn,
				AffectedVersionRange: vulnerability.AffectedVersionRange,
				References:           append([]sdk.Reference(nil), vulnerability.References...),
				KEVExploited:         vulnerability.KEVExploited,
			})
		}
	}

	return sdk.AuditResult{
		Graph:    req.Graph,
		Target:   req.Target,
		Findings: findings,
	}, nil
}

// SeverityThreshold controls which severities should create findings.
type SeverityThreshold string

const (
	SeverityAny      SeverityThreshold = "any"
	SeverityLow      SeverityThreshold = "low"
	SeverityMedium   SeverityThreshold = "medium"
	SeverityHigh     SeverityThreshold = "high"
	SeverityCritical SeverityThreshold = "critical"
)

// ParseSeverityThreshold validates a fail-on severity value.
func ParseSeverityThreshold(value string) (SeverityThreshold, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		normalized = string(SeverityAny)
	}
	switch SeverityThreshold(normalized) {
	case SeverityAny, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return SeverityThreshold(normalized), nil
	default:
		return "", fmt.Errorf("unsupported severity %q", value)
	}
}

// Matches reports whether the configured threshold should emit a finding for the provided severity.
func (s SeverityThreshold) Matches(severity string) bool {
	if s == SeverityAny {
		return true
	}
	return severityRank(severity) >= severityRank(string(s))
}

// severityRank returns a value that can be used to sort vulnerabilities by severity.
func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// collapsePreferredVulnerabilities collapses multiple vulnerabilities with the same ID into a single entry.
func collapsePreferredVulnerabilities(vulnerabilities []sdk.PackageVulnerability) []sdk.PackageVulnerability {
	type key struct {
		id string
	}
	type choice struct {
		entry sdk.PackageVulnerability
		rank  int
	}
	best := make(map[key]choice, len(vulnerabilities))
	order := make([]key, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		k := key{id: vulnerability.ID}
		rank := sourceRank(vulnerability.Source)
		current, exists := best[k]
		if !exists {
			best[k] = choice{entry: vulnerability, rank: rank}
			order = append(order, k)
			continue
		}
		if rank < current.rank {
			best[k] = choice{entry: vulnerability, rank: rank}
		}
	}

	out := make([]sdk.PackageVulnerability, 0, len(best))
	for _, k := range order {
		out = append(out, best[k].entry)
	}
	return out
}

// sourceRank returns a value that can be used to sort vulnerabilities by source.
// The lower the value, the higher the priority.
func sourceRank(source string) int {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "grype":
		return 0
	case "osv":
		return 1
	default:
		return 2
	}
}
