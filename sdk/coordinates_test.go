package sdk

import "testing"

func TestCoordinatesSharedView(t *testing.T) {
	dep := NewDependency(Dependency{
		Coordinates: Coordinates{
			Ecosystem:      EcosystemMaven,
			PackageManager: PackageManagerGradle,
			Type:           PackageTypePackage,
			Org:            "com.example",
			Name:           "demo",
			Version:        "1.2.3",
			Language:       LanguageJava,
		},
	})
	pkg := &Package{
		Coordinates: dep.Coordinates,
	}

	if dep.Coordinates != pkg.Coordinates {
		t.Fatalf("dependency and coordinates differ:\ndep=%#v\npkg=%#v", dep.Coordinates, pkg.Coordinates)
	}
	if got, want := dep.Coordinates.QualifiedName(), "com.example:demo"; got != want {
		t.Fatalf("QualifiedName() = %q, want %q", got, want)
	}
	if got, want := dep.Coordinates.StableID(), "com.example:demo@1.2.3"; got != want {
		t.Fatalf("StableID() = %q, want %q", got, want)
	}
	if dep.IdentityKey() != pkg.IdentityKey() {
		t.Fatalf("identity keys differ: dep=%q pkg=%q", dep.IdentityKey(), pkg.IdentityKey())
	}
}

func TestCoordinatesCanonicalPURL(t *testing.T) {
	identity := Coordinates{
		Ecosystem:      EcosystemGo,
		PackageManager: PackageManagerGoMod,
		Name:           "github.com/Example/Lib/v2",
		Version:        "v2.1.0",
	}

	if got, want := identity.CanonicalPURL(), "pkg:golang/github.com/example/lib/v2@v2.1.0"; got != want {
		t.Fatalf("CanonicalPURL() = %q, want %q", got, want)
	}
}
