package mcp

import "github.com/bomly-dev/bomly-cli/sdk"

// classifyFinding buckets a finding by what an agent can do about it.
// vuln is the advisory the finding references, resolved from the registry;
// nil when the package or advisory is missing (e.g. unenriched runs).
func classifyFinding(f sdk.Finding, vuln *sdk.Vulnerability) string {
	if f.Kind != sdk.FindingKindVulnerability {
		return ClassificationPolicyOnly
	}
	if vuln == nil {
		return ClassificationUnknown
	}
	switch {
	case vuln.FixState == sdk.FixStateFixed,
		vuln.FixedIn != "",
		len(vuln.FixedVersions) > 0,
		len(vuln.FixAvailable) > 0:
		return ClassificationFixAvailable
	case vuln.FixState == sdk.FixStateWontFix:
		return ClassificationWontFix
	case vuln.FixState == sdk.FixStateNotFixed:
		return ClassificationNoFixUpstream
	default:
		return ClassificationUnknown
	}
}

// findingFails mirrors output.FailingFindingCount semantics: an empty
// disposition counts as failing.
func findingFails(f sdk.Finding) bool {
	return f.Disposition == "" || f.Disposition == sdk.FindingDispositionFail
}
