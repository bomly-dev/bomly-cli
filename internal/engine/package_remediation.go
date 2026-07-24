package engine

import (
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/sdk"
)

type vulnerabilityRemediationEvidence struct {
	version        string
	hasFixEvidence bool
	unavailable    bool
	contradictory  bool
}

// derivePackageRemediations replaces package remediation values with summaries
// derived solely from the consolidated vulnerability evidence in the registry.
func derivePackageRemediations(registry *sdk.PackageRegistry) {
	if registry == nil {
		return
	}
	for _, pkg := range registry.All() {
		pkg.Remediation = derivePackageRemediation(pkg.Vulnerabilities)
	}
}

func derivePackageRemediation(vulnerabilities []sdk.Vulnerability) *sdk.PackageRemediation {
	if len(vulnerabilities) == 0 {
		return nil
	}

	evidence := make([]vulnerabilityRemediationEvidence, 0, len(vulnerabilities))
	hasFixEvidence := false
	allUnavailable := true
	for _, vulnerability := range vulnerabilities {
		item := remediationEvidenceForVulnerability(vulnerability)
		evidence = append(evidence, item)
		hasFixEvidence = hasFixEvidence || item.hasFixEvidence
		allUnavailable = allUnavailable && item.unavailable
		if item.contradictory {
			return &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown}
		}
	}

	if allUnavailable {
		return &sdk.PackageRemediation{Status: sdk.PackageRemediationUnavailable}
	}
	if !hasFixEvidence {
		return &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown}
	}

	versions := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.version == "" {
			return &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial}
		}
		versions = append(versions, item.version)
	}
	recommended, comparable := highestComparableVersion(versions)
	if !comparable {
		return &sdk.PackageRemediation{Status: sdk.PackageRemediationPartial}
	}
	return &sdk.PackageRemediation{
		Status:             sdk.PackageRemediationComplete,
		RecommendedVersion: recommended,
	}
}

func remediationEvidenceForVulnerability(vulnerability sdk.Vulnerability) vulnerabilityRemediationEvidence {
	values := preferredFixVersions(vulnerability)
	explicitlyUnavailable := vulnerability.FixState == sdk.FixStateNotFixed ||
		vulnerability.FixState == sdk.FixStateWontFix
	if len(values) == 0 {
		return vulnerabilityRemediationEvidence{unavailable: explicitlyUnavailable}
	}
	if explicitlyUnavailable {
		return vulnerabilityRemediationEvidence{
			hasFixEvidence: true,
			contradictory:  true,
		}
	}

	version, comparable := lowestComparableVersion(values)
	if !comparable {
		return vulnerabilityRemediationEvidence{hasFixEvidence: true}
	}
	return vulnerabilityRemediationEvidence{
		version:        version,
		hasFixEvidence: true,
	}
}

func preferredFixVersions(vulnerability sdk.Vulnerability) []string {
	if value := strings.TrimSpace(vulnerability.FixedIn); value != "" {
		return []string{value}
	}

	available := make([]string, 0, len(vulnerability.FixAvailable))
	for _, fix := range vulnerability.FixAvailable {
		if value := strings.TrimSpace(fix.Version); value != "" {
			available = append(available, value)
		}
	}
	if len(available) > 0 {
		return uniqueSortedVersions(available)
	}

	fixed := make([]string, 0, len(vulnerability.FixedVersions))
	for _, version := range vulnerability.FixedVersions {
		if value := strings.TrimSpace(version); value != "" {
			fixed = append(fixed, value)
		}
	}
	return uniqueSortedVersions(fixed)
}

func uniqueSortedVersions(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func lowestComparableVersion(values []string) (string, bool) {
	return selectComparableVersion(values, false)
}

func highestComparableVersion(values []string) (string, bool) {
	return selectComparableVersion(values, true)
}

func selectComparableVersion(values []string, highest bool) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	selected := strings.TrimSpace(values[0])
	if selected == "" {
		return "", false
	}
	if len(values) == 1 {
		return selected, true
	}

	selectedSemver, err := semver.NewVersion(selected)
	if err != nil {
		for _, value := range values[1:] {
			if strings.TrimSpace(value) != selected {
				return "", false
			}
		}
		return selected, true
	}
	for _, value := range values[1:] {
		candidate := strings.TrimSpace(value)
		candidateSemver, err := semver.NewVersion(candidate)
		if err != nil {
			return "", false
		}
		comparison := candidateSemver.Compare(selectedSemver)
		if (highest && comparison > 0) || (!highest && comparison < 0) {
			selected = candidate
			selectedSemver = candidateSemver
		}
	}
	return selected, true
}
