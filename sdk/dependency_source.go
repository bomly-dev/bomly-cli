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
