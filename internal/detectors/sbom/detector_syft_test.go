//go:build bomly_builtin_syft

package sbom

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	syftfile "github.com/anchore/syft/syft/file"
	syftjson "github.com/anchore/syft/syft/format/syftjson"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/bomly/bomly-cli/internal/model"
)

func TestDetectorResolveGraph_SyftJSON(t *testing.T) {
	path := writeSyftJSONFixture(t)
	result := resolveFixture(t, path)

	g, err := result.ConsolidatedGraph()
	if err != nil {
		t.Fatalf("ConsolidatedGraph() error = %v", err)
	}
	var react *model.Package
	for _, pkg := range g.Packages() {
		if pkg != nil && pkg.Name == "react" && pkg.Version == "18.2.0" {
			react = pkg
			break
		}
	}
	if react == nil {
		t.Fatalf("expected syft graph to contain react@18.2.0, got %s", g.PrettyString())
	}
	if licenses := react.LicenseValues(); len(licenses) != 1 || licenses[0] != "MIT" {
		t.Fatalf("expected syft json licenses to be preserved, got %#v", licenses)
	}
}

func writeSyftJSONFixture(t *testing.T) string {
	t.Helper()
	app := syftpkg.Package{
		Name:      "demo-app",
		Version:   "1.0.0",
		Type:      syftpkg.NpmPkg,
		PURL:      "pkg:npm/demo-app@1.0.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("package-lock.json")),
	}
	app.SetID()

	react := syftpkg.Package{
		Name:      "react",
		Version:   "18.2.0",
		Type:      syftpkg.NpmPkg,
		PURL:      "pkg:npm/react@18.2.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("package-lock.json")),
		Licenses:  syftpkg.NewLicenseSet(syftpkg.NewLicense("MIT")),
	}
	react.SetID()

	doc := syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(app, react),
		},
		Relationships: []artifact.Relationship{
			{From: react, To: app, Type: artifact.DependencyOfRelationship},
		},
	}

	encoder, err := syftjson.NewFormatEncoderWithConfig(syftjson.EncoderConfig{Pretty: true})
	if err != nil {
		t.Fatalf("new syft encoder: %v", err)
	}
	var out bytes.Buffer
	if err := encoder.Encode(&out, doc); err != nil {
		t.Fatalf("encode syft fixture: %v", err)
	}
	path := filepath.Join(t.TempDir(), "input.syft.json")
	if err := os.WriteFile(path, bytes.TrimSpace(out.Bytes()), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}
