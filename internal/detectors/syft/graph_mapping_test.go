//go:build !bomly_external_syft

package syft

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// TestGraphFromSyftSBOMMapsPackagesEdgesLicenses exercises the builtin Syft →
// sdk.Graph mapping with a hand-built SBOM. The Syft graph builder consumes the
// Syft library's SBOM struct (not a text manifest), so the fixture is the struct
// itself; the test invokes no Syft binary.
func TestGraphFromSyftSBOMMapsPackagesEdgesLicenses(t *testing.T) {
	requests := syftpkg.Package{
		Name:    "requests",
		Version: "2.32.3",
		Type:    syftpkg.PythonPkg,
		PURL:    "pkg:pypi/requests@2.32.3",
	}
	requests.SetID()

	certifi := syftpkg.Package{
		Name:     "certifi",
		Version:  "2024.8.30",
		Type:     syftpkg.PythonPkg,
		PURL:     "pkg:pypi/certifi@2024.8.30",
		Licenses: syftpkg.NewLicenseSet(syftpkg.NewLicense("MPL-2.0")),
	}
	certifi.SetID()

	sb := &syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(requests, certifi),
		},
		Relationships: []artifact.Relationship{
			// certifi is a dependency-of requests → edge requests → certifi.
			{From: certifi, To: requests, Type: artifact.DependencyOfRelationship},
		},
	}

	g, err := graphFromSyftSBOM(sb)
	if err != nil {
		t.Fatalf("graphFromSyftSBOM: %v", err)
	}
	if g.Size() != 2 {
		t.Fatalf("graph size = %d, want 2", g.Size())
	}

	requestsNode := nodeByName(t, g, "requests")
	certifiNode := nodeByName(t, g, "certifi")

	if requestsNode.Version != "2.32.3" || requestsNode.PURL != "pkg:pypi/requests@2.32.3" {
		t.Errorf("unexpected requests coordinates: %+v", requestsNode.Coordinates)
	}

	// Dependency-of relationship becomes a parent → child edge.
	deps, err := g.DirectDependencies(requestsNode.ID)
	if err != nil {
		t.Fatalf("dependencies(requests): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != certifiNode.ID {
		t.Errorf("expected requests → certifi edge, got %+v", deps)
	}

	// License carried through from the Syft package.
	licenses := sdk.DetectionLicenses(certifiNode)
	if len(licenses) == 0 || licenses[0].Value != "MPL-2.0" {
		t.Errorf("expected MPL-2.0 license on certifi, got %+v", licenses)
	}
}

func nodeByName(t *testing.T, g *sdk.Graph, name string) *sdk.Dependency {
	t.Helper()
	for _, n := range g.Nodes() {
		if n.Name == name {
			return n
		}
	}
	t.Fatalf("no node named %q", name)
	return nil
}
