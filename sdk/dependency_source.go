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
// enriched as a published registry release. Application and manifest nodes
// are never eligible. Project, workspace, file, Git, and arbitrary URL
// occurrences remain in the graph and package registry but are not sent to
// external registry matchers. An omitted source stays eligible for protocol-v1
// and legacy detector compatibility.
func (d *Dependency) RegistryMatchEligible() bool {
	if d == nil || d.Type == PackageTypeApplication || d.Type == PackageTypeManifest {
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
