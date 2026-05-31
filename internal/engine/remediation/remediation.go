// Package remediation proposes locally evidenced dependency upgrades for
// packages with attached vulnerability data.
package remediation

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// Status describes whether a package has enough local data for a proposal.
type Status string

const (
	// StatusProposed means a locally evidenced upgrade candidate is available.
	StatusProposed Status = "proposed"
	// StatusInsufficientLocalData means local vulnerability metadata could not
	// support a conservative proposal.
	StatusInsufficientLocalData Status = "insufficient_local_data"
)

// ConstraintCompatibility describes whether a proposal satisfies the
// dependency constraint declared by the package manager manifest.
type ConstraintCompatibility string

const (
	// ConstraintCompatibilityUnknown is used because the consolidated graph
	// does not retain portable package-manager dependency constraints.
	ConstraintCompatibilityUnknown ConstraintCompatibility = "unknown"
)

// Proposal describes the minimum locally evidenced upgrade candidate for one
// vulnerable package.
type Proposal struct {
	PackageID               string
	PackageName             string
	CurrentVersion          string
	ProposedVersion         string
	VulnerabilityIDs        []string
	Status                  Status
	ConstraintCompatibility ConstraintCompatibility
	Reason                  string
}

// Result contains deterministic package remediation proposals.
type Result struct {
	Proposals   []Proposal
	ByPackageID map[string]Proposal
}

// ProposalForPackageID returns the proposal for packageID when one exists.
func (r Result) ProposalForPackageID(packageID string) (Proposal, bool) {
	proposal, ok := r.ByPackageID[packageID]
	return proposal, ok
}

// ProposedCount returns the number of packages with locally evidenced
// remediation candidates.
func (r Result) ProposedCount() int {
	count := 0
	for _, proposal := range r.Proposals {
		if proposal.Status == StatusProposed {
			count++
		}
	}
	return count
}

// UnavailableCount returns the number of vulnerable packages without enough
// local data for a remediation candidate.
func (r Result) UnavailableCount() int {
	return len(r.Proposals) - r.ProposedCount()
}

// Evaluate returns one deterministic proposal for each vulnerable package in
// graph. It uses only vulnerability metadata already attached to the graph.
func Evaluate(graph *sdk.Graph) Result {
	result := Result{ByPackageID: make(map[string]Proposal)}
	if graph == nil {
		return result
	}
	for _, pkg := range graph.Packages() {
		if pkg == nil || len(pkg.Vulnerabilities) == 0 {
			continue
		}
		proposal := ProposePackage(pkg, pkg.Vulnerabilities)
		result.Proposals = append(result.Proposals, proposal)
		result.ByPackageID[proposal.PackageID] = proposal
	}
	sort.Slice(result.Proposals, func(i, j int) bool {
		return result.Proposals[i].PackageID < result.Proposals[j].PackageID
	})
	return result
}

// ProposePackage returns a conservative proposal for pkg based on
// vulnerabilities already attached by local graph enrichment.
func ProposePackage(pkg *sdk.Package, vulnerabilities []sdk.PackageVulnerability) Proposal {
	proposal := Proposal{
		Status:                  StatusInsufficientLocalData,
		ConstraintCompatibility: ConstraintCompatibilityUnknown,
	}
	if pkg == nil {
		proposal.Reason = "package is nil"
		return proposal
	}
	proposal.PackageID = pkg.ID
	proposal.PackageName = pkg.DisplayName()
	proposal.CurrentVersion = pkg.Version
	proposal.VulnerabilityIDs = vulnerabilityIDs(vulnerabilities)
	if len(vulnerabilities) == 0 {
		proposal.Reason = "package has no locally attached vulnerabilities"
		return proposal
	}

	current, err := semver.NewVersion(strings.TrimSpace(pkg.Version))
	if err != nil {
		proposal.Reason = fmt.Sprintf("installed version %q is not semver-compatible", pkg.Version)
		return proposal
	}

	var packageMinimum *semver.Version
	var packageMinimumRaw string
	for _, vulnerability := range sortedVulnerabilities(vulnerabilities) {
		minimum, raw, reason := minimumFixedVersionAfter(current, vulnerability)
		if reason != "" {
			proposal.Reason = reason
			return proposal
		}
		if packageMinimum == nil || minimum.GreaterThan(packageMinimum) {
			packageMinimum = minimum
			packageMinimumRaw = raw
		}
	}
	if packageMinimum == nil {
		proposal.Reason = "no locally attached fixed version is available"
		return proposal
	}

	proposal.Status = StatusProposed
	proposal.ProposedVersion = packageMinimumRaw
	return proposal
}

func minimumFixedVersionAfter(current *semver.Version, vulnerability sdk.PackageVulnerability) (*semver.Version, string, string) {
	candidates := append([]string{vulnerability.FixedIn}, vulnerability.FixedVersions...)
	candidates = uniqueNonEmptyStrings(candidates)
	if len(candidates) == 0 {
		return nil, "", fmt.Sprintf("vulnerability %q has no locally attached fixed version", vulnerability.ID)
	}

	var minimum *semver.Version
	var minimumRaw string
	for _, raw := range candidates {
		parsed, err := semver.NewVersion(raw)
		if err != nil {
			return nil, "", fmt.Sprintf("vulnerability %q fixed version %q is not semver-compatible", vulnerability.ID, raw)
		}
		if !parsed.GreaterThan(current) {
			continue
		}
		if minimum == nil || parsed.LessThan(minimum) {
			minimum = parsed
			minimumRaw = raw
		}
	}
	if minimum == nil {
		return nil, "", fmt.Sprintf("vulnerability %q has no locally attached fixed version newer than installed version %q", vulnerability.ID, current.Original())
	}
	return minimum, minimumRaw, ""
}

func vulnerabilityIDs(vulnerabilities []sdk.PackageVulnerability) []string {
	ids := make([]string, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		if id := strings.TrimSpace(vulnerability.ID); id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return uniqueNonEmptyStrings(ids)
}

func sortedVulnerabilities(vulnerabilities []sdk.PackageVulnerability) []sdk.PackageVulnerability {
	out := append([]sdk.PackageVulnerability(nil), vulnerabilities...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
