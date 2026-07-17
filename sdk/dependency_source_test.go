package sdk

import "testing"

func TestDependencyRegistryMatchEligible(t *testing.T) {
	for _, tc := range []struct {
		name string
		dep  *Dependency
		want bool
	}{
		{name: "registry release", dep: &Dependency{Source: DependencySourceRegistry}, want: true},
		{name: "registry mirror", dep: &Dependency{Source: DependencySourceRegistry, ResolvedURL: "https://mirror.example.test/pkg.tgz"}, want: true},
		{name: "legacy unspecified", dep: &Dependency{}, want: true},
		{name: "plugin custom unspecified semantics", dep: &Dependency{Source: DependencySource("custom")}, want: true},
		{name: "project", dep: &Dependency{Source: DependencySourceProject}},
		{name: "workspace", dep: &Dependency{Source: DependencySourceWorkspace}},
		{name: "file", dep: &Dependency{Source: DependencySourceFile}},
		{name: "git", dep: &Dependency{Source: DependencySourceGit}},
		{name: "url", dep: &Dependency{Source: DependencySourceURL}},
		{name: "first-party application", dep: &Dependency{Coordinates: Coordinates{Type: PackageTypeApplication, FirstParty: true}, Source: DependencySourceRegistry}},
		{name: "imported application", dep: &Dependency{Coordinates: Coordinates{Type: PackageTypeApplication}, Source: DependencySourceRegistry}, want: true},
		{name: "manifest regardless of source", dep: &Dependency{Coordinates: Coordinates{Type: PackageTypeManifest}, Source: DependencySourceRegistry}},
		{name: "first-party untyped", dep: &Dependency{Coordinates: Coordinates{FirstParty: true}, Source: DependencySourceRegistry}},
		{name: "nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.dep.RegistryMatchEligible(); got != tc.want {
				t.Fatalf("RegistryMatchEligible() = %v, want %v", got, tc.want)
			}
		})
	}
}
