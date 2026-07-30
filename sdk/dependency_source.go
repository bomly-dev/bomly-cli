package sdk

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

// RegistryMatchEligible reports whether this dependency occurrence may be
// sent to external package matchers. First-party and manifest nodes are never
// eligible. Project, workspace, file, Git, and arbitrary URL occurrences are
// normally excluded. Swift source-control packages remain eligible because
// their repository URL is the canonical SwiftURL package identity used by
// vulnerability sources. An application type imported from an SBOM is an
// artifact kind rather than proof of ownership and remains eligible unless it
// is marked first-party. An omitted source stays eligible for protocol-v1 and
// legacy detector compatibility.
func (d *Dependency) RegistryMatchEligible() bool {
	if !NodeIsEnrichable(d) {
		return false
	}
	if d.Ecosystem == EcosystemSwift && d.Source == DependencySourceGit {
		return true
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
