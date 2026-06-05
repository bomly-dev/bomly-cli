package sdk

import (
	"reflect"
	"testing"
)

func TestNormalizePackageIdentityPython(t *testing.T) {
	pkg := &Dependency{Ecosystem: string(EcosystemPython), Name: " Requests_Toolbelt ", Version: "1.0.0RC1"}

	NormalizeDependencyIdentity(pkg)

	if pkg.Name != "requests-toolbelt" {
		normReturnNameMismatch(t, pkg.Name, "requests-toolbelt")
	}
	if pkg.Version != "1.0.0rc1" {
		normReturnNameMismatch(t, pkg.Version, "1.0.0rc1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func TestNormalizePackageIdentityRust(t *testing.T) {
	pkg := &Dependency{BuildSystem: "cargo", Name: "Serde_JSON", Version: "1.0.0-RC1"}

	NormalizeDependencyIdentity(pkg)

	if pkg.Name != "serde-json" {
		normReturnNameMismatch(t, pkg.Name, "serde-json")
	}
	if pkg.Version != "1.0.0-rc1" {
		normReturnNameMismatch(t, pkg.Version, "1.0.0-rc1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func TestNormalizePackageIdentityNPMScopedName(t *testing.T) {
	pkg := &Dependency{Ecosystem: string(EcosystemNPM), Name: "@Types/Node", Version: "20.11.30"}

	NormalizeDependencyIdentity(pkg)

	if pkg.Org != "types" {
		normReturnNameMismatch(t, pkg.Org, "types")
	}
	if pkg.Name != "node" {
		normReturnNameMismatch(t, pkg.Name, "node")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"npm-scope", "org", "name"})
}

func TestNormalizePackageIdentityGoPath(t *testing.T) {
	pkg := &Dependency{Ecosystem: string(EcosystemGo), Name: "github.com\\Example\\lib//v2", Version: "V2.1.0-RC1"}

	NormalizeDependencyIdentity(pkg)

	if pkg.Name != "github.com/Example/lib/v2" {
		normReturnNameMismatch(t, pkg.Name, "github.com/Example/lib/v2")
	}
	if pkg.Version != "v2.1.0-rc1" {
		normReturnNameMismatch(t, pkg.Version, "v2.1.0-rc1")
	}
	normAssertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func normAssertAppliedMetadata(t *testing.T, metadata map[string]any, want []string) {
	t.Helper()
	if metadata == nil {
		t.Fatal("expected metadata to be recorded")
	}
	got, ok := metadata[normMetadataAppliedKey].([]string)
	if !ok {
		t.Fatalf("expected %q metadata to be []string, got %#v", normMetadataAppliedKey, metadata[normMetadataAppliedKey])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected normalization metadata %#v, got %#v", want, got)
	}
}

func normReturnNameMismatch(t *testing.T, got, want string) {
	t.Helper()
	t.Fatalf("expected %q, got %q", want, got)
}
