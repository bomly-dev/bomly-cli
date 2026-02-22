package normalization

import (
	"reflect"
	"testing"

	"github.com/bomly/bomly-cli/internal/model"
)

func TestNormalizePackageIdentityPython(t *testing.T) {
	pkg := &model.Package{Ecosystem: string(model.EcosystemPython), Name: " Requests_Toolbelt ", Version: "1.0.0RC1"}

	NormalizePackageIdentity(pkg)

	if pkg.Name != "requests-toolbelt" {
		returnNameMismatch(t, pkg.Name, "requests-toolbelt")
	}
	if pkg.Version != "1.0.0rc1" {
		returnNameMismatch(t, pkg.Version, "1.0.0rc1")
	}
	assertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func TestNormalizePackageIdentityRust(t *testing.T) {
	pkg := &model.Package{BuildSystem: "cargo", Name: "Serde_JSON", Version: "1.0.0-RC1"}

	NormalizePackageIdentity(pkg)

	if pkg.Name != "serde-json" {
		returnNameMismatch(t, pkg.Name, "serde-json")
	}
	if pkg.Version != "1.0.0-rc1" {
		returnNameMismatch(t, pkg.Version, "1.0.0-rc1")
	}
	assertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func TestNormalizePackageIdentityNPMScopedName(t *testing.T) {
	pkg := &model.Package{Ecosystem: string(model.EcosystemNPM), Name: "@Types/Node", Version: "20.11.30"}

	NormalizePackageIdentity(pkg)

	if pkg.Org != "types" {
		returnNameMismatch(t, pkg.Org, "types")
	}
	if pkg.Name != "node" {
		returnNameMismatch(t, pkg.Name, "node")
	}
	assertAppliedMetadata(t, pkg.Metadata, []string{"npm-scope", "org", "name"})
}

func TestNormalizePackageIdentityGoPath(t *testing.T) {
	pkg := &model.Package{Ecosystem: string(model.EcosystemGo), Name: "github.com\\Example\\lib//v2", Version: "V2.1.0-RC1"}

	NormalizePackageIdentity(pkg)

	if pkg.Name != "github.com/Example/lib/v2" {
		returnNameMismatch(t, pkg.Name, "github.com/Example/lib/v2")
	}
	if pkg.Version != "v2.1.0-rc1" {
		returnNameMismatch(t, pkg.Version, "v2.1.0-rc1")
	}
	assertAppliedMetadata(t, pkg.Metadata, []string{"name", "version"})
}

func assertAppliedMetadata(t *testing.T, metadata map[string]any, want []string) {
	t.Helper()
	if metadata == nil {
		t.Fatal("expected metadata to be recorded")
	}
	got, ok := metadata[metadataAppliedKey].([]string)
	if !ok {
		t.Fatalf("expected %q metadata to be []string, got %#v", metadataAppliedKey, metadata[metadataAppliedKey])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected normalization metadata %#v, got %#v", want, got)
	}
}

func returnNameMismatch(t *testing.T, got, want string) {
	t.Helper()
	t.Fatalf("expected %q, got %q", want, got)
}