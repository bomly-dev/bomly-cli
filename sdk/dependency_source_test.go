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

func TestParseDependencySourceChangePolicies(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    []DependencySource
		wantErr bool
	}{
		{name: "empty"},
		{name: "Git", values: []string{"git"}, want: []DependencySource{DependencySourceGit}},
		{name: "URL", values: []string{"url"}, want: []DependencySource{DependencySourceURL}},
		{name: "both", values: []string{"url", "git"}, want: []DependencySource{DependencySourceGit, DependencySourceURL}},
		{name: "any", values: []string{"ANY"}, want: []DependencySource{DependencySourceGit, DependencySourceURL}},
		{name: "deduplicated", values: []string{"any", "git", "url"}, want: []DependencySource{DependencySourceGit, DependencySourceURL}},
		{name: "unsupported", values: []string{"workspace"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseDependencySourceChangePolicies(test.values)
			if test.wantErr {
				if err == nil {
					t.Fatalf("ParseDependencySourceChangePolicies(%#v) expected error", test.values)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseDependencySourceChangePolicies(%#v) error = %v", test.values, err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("ParseDependencySourceChangePolicies(%#v) = %#v, want %#v", test.values, got, test.want)
			}
			for i := range test.want {
				if got[i] != test.want[i] {
					t.Fatalf("ParseDependencySourceChangePolicies(%#v) = %#v, want %#v", test.values, got, test.want)
				}
			}
		})
	}
}
