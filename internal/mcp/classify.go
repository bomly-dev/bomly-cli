package mcp

import (
	"github.com/bomly-dev/bomly-sdk/model"
)

// classifyFinding buckets a finding by what an agent can do about it.
// vuln is the advisory the finding references, resolved from the registry;
// nil when the package or advisory is missing (e.g. unenriched runs).
func classifyFinding(f model.Finding, vuln *model.Vulnerability) string {
	if f.Kind != model.FindingKindVulnerability {
		return ClassificationPolicyOnly
	}
	if vuln == nil {
		return ClassificationUnknown
	}
	switch {
	case vuln.FixState == model.FixStateFixed,
		vuln.FixedIn != "",
		len(vuln.FixedVersions) > 0,
		len(vuln.FixAvailable) > 0:
		return ClassificationFixAvailable
	case vuln.FixState == model.FixStateWontFix:
		return ClassificationWontFix
	case vuln.FixState == model.FixStateNotFixed:
		return ClassificationNoFixUpstream
	default:
		return ClassificationUnknown
	}
}
