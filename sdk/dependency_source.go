package sdk

import (
	"fmt"
	"strings"
)

// DependencySource describes how a dependency occurrence is resolved.
type DependencySource string

const (
	DependencySourceRegistry  DependencySource = "registry"
	DependencySourceProject   DependencySource = "project"
	DependencySourceWorkspace DependencySource = "workspace"
	DependencySourceFile      DependencySource = "file"
	DependencySourceGit       DependencySource = "git"
	DependencySourceURL       DependencySource = "url"
)

// DependencySourceChangePolicyAny selects every source type supported by the
// dependency source-change policy.
const DependencySourceChangePolicyAny = "any"

// ParseDependencySourceChangePolicies parses source types accepted by the
// dependency source-change policy.
func ParseDependencySourceChangePolicies(values []string) ([]DependencySource, error) {
	includeGit := false
	includeURL := false
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch normalized {
		case DependencySourceChangePolicyAny:
			includeGit = true
			includeURL = true
		case string(DependencySourceGit):
			includeGit = true
		case string(DependencySourceURL):
			includeURL = true
		default:
			return nil, fmt.Errorf("unsupported dependency source change %q (accepted: any, git, url)", value)
		}
	}
	parsed := make([]DependencySource, 0, 2)
	if includeGit {
		parsed = append(parsed, DependencySourceGit)
	}
	if includeURL {
		parsed = append(parsed, DependencySourceURL)
	}
	return parsed, nil
}

// RegistryMatchEligible reports whether this dependency occurrence may be
// enriched as a published registry release. First-party and manifest nodes
// are never eligible. Project, workspace, file, Git, and arbitrary URL
// occurrences remain in the graph and package registry but are not sent to
// external registry matchers. An application type imported from an SBOM is an
// artifact kind rather than proof of ownership and remains eligible unless it
// is marked first-party. An omitted source stays eligible for protocol-v1 and
// legacy detector compatibility.
func (d *Dependency) RegistryMatchEligible() bool {
	if !NodeIsEnrichable(d) {
		return false
	}
	switch d.Source {
	case DependencySourceProject, DependencySourceWorkspace, DependencySourceFile, DependencySourceGit, DependencySourceURL:
		return false
	case DependencySourceRegistry, "":
		return true
	default:
		// Custom plugin source values predate this classification. Preserve
		// matching until the plugin explicitly adopts a non-registry source.
		return true
	}
}
