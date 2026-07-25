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

func TestCoordinatesEcosystemName(t *testing.T) {
	cases := []struct {
		name  string
		coord Coordinates
		want  string
	}{
		{"npm scoped", Coordinates{Ecosystem: EcosystemNPM, Org: "tailwindcss", Name: "postcss"}, "@tailwindcss/postcss"},
		{"npm scope already prefixed", Coordinates{Ecosystem: EcosystemNPM, Org: "@types", Name: "node"}, "@types/node"},
		{"npm unscoped", Coordinates{Ecosystem: EcosystemNPM, Name: "postcss"}, "postcss"},
		{"npm via package manager only", Coordinates{PackageManager: PackageManagerPNPM, Org: "scope", Name: "pkg"}, "@scope/pkg"},
		{"maven", Coordinates{Ecosystem: EcosystemMaven, Org: "com.example", Name: "demo"}, "com.example:demo"},
		{"scala", Coordinates{Ecosystem: EcosystemScala, Org: "org.typelevel", Name: "cats-core_2.13"}, "org.typelevel:cats-core_2.13"},
		{"go", Coordinates{Ecosystem: EcosystemGo, Org: "github.com/spf13", Name: "cobra"}, "github.com/spf13/cobra"},
		{"go without org", Coordinates{Ecosystem: EcosystemGo, Name: "github.com/spf13/cobra"}, "github.com/spf13/cobra"},
		{"composer", Coordinates{Ecosystem: EcosystemPHP, Org: "monolog", Name: "monolog"}, "monolog/monolog"},
		{"swift", Coordinates{Ecosystem: EcosystemSwift, Org: "github.com/apple", Name: "swift-nio"}, "github.com/apple/swift-nio"},
		{"github actions", Coordinates{Ecosystem: EcosystemGitHub, Org: "actions", Name: "checkout"}, "actions/checkout"},
		// OS packages carry the distro in Org; it is not part of the name the
		// distro-namespace advisories are keyed under.
		{"apk keeps bare name", Coordinates{Ecosystem: EcosystemAPK, Org: "alpine", Name: "libcrypto3"}, "libcrypto3"},
		{"dpkg keeps bare name", Coordinates{Ecosystem: EcosystemDPKG, Org: "debian", Name: "bash"}, "bash"},
		{"rpm keeps bare name", Coordinates{Ecosystem: EcosystemRPM, Org: "redhat", Name: "openssl"}, "openssl"},
		{"conan keeps bare name", Coordinates{Ecosystem: EcosystemCPP, Org: "bincrafters", Name: "openssl"}, "openssl"},
		{"no org", Coordinates{Ecosystem: EcosystemPython, Name: "requests"}, "requests"},
		{"no name", Coordinates{Ecosystem: EcosystemNPM, Org: "scope"}, "scope"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.coord.EcosystemName(); got != tc.want {
				t.Fatalf("EcosystemName() = %q, want %q", got, tc.want)
			}
		})
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
