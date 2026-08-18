package output

import (
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

// Origin metadata is a transport between detection and SBOM export. It must not
// surface in scan/diff/explain payloads, where it would be noise in every
// package entry and churn every golden.
func TestPackageRefOmitsOriginMetadata(t *testing.T) {
	dep := sdk.NewDependencyWithID("npm:react", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL:      "pkg:npm/react@18.2.0",
			Ecosystem: sdk.EcosystemNPM,
			Name:      "react",
			Version:   "18.2.0",
		},
	})
	detectors.SetOriginArtifact(dep, "https://registry.npmjs.org/react/-/react-18.2.0.tgz")
	dep.Metadata["npm"] = &sdk.NPMPackageMetadata{Bundled: true}

	ref := PackageFromDependencyAndRegistry(dep, nil)

	if _, found := ref.Metadata[detectors.MetadataKeyOriginArtifactURL]; found {
		t.Fatalf("origin metadata reached command output: %v", ref.Metadata)
	}
	if _, found := ref.Metadata["npm"]; !found {
		t.Fatalf("unrelated metadata was dropped: %v", ref.Metadata)
	}
}

// A dependency whose only metadata is origin must render no metadata object at
// all, or `omitempty` stops firing and every such package grows an empty block.
func TestPackageRefMetadataAbsentWhenOnlyOrigin(t *testing.T) {
	dep := sdk.NewDependencyWithID("npm:react", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			PURL:      "pkg:npm/react@18.2.0",
			Ecosystem: sdk.EcosystemNPM,
			Name:      "react",
			Version:   "18.2.0",
		},
	})
	detectors.SetOriginVCS(dep, "https://github.com/facebook/react", "9f8e7d6c5b4a3928176554433221100ffeeddcc0")

	if ref := PackageFromDependencyAndRegistry(dep, nil); ref.Metadata != nil {
		t.Fatalf("metadata = %v, want nil so the field is omitted", ref.Metadata)
	}
}

// The same filter guards the registry-sourced package listing.
func TestScanPackageEntriesOmitOriginMetadata(t *testing.T) {
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:      "pkg:npm/react@18.2.0",
			Ecosystem: sdk.EcosystemNPM,
			Name:      "react",
			Version:   "18.2.0",
		},
		Metadata: map[string]any{
			detectors.MetadataKeyOriginArtifactURL: "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
			"npm":                                  &sdk.NPMPackageMetadata{Bundled: true},
		},
	})

	entries := PackagesFromRegistry(registry)
	if len(entries) != 1 {
		t.Fatalf("got %d package entries, want 1", len(entries))
	}
	if _, found := entries[0].Metadata[detectors.MetadataKeyOriginArtifactURL]; found {
		t.Fatalf("origin metadata reached the package listing: %v", entries[0].Metadata)
	}
	if _, found := entries[0].Metadata["npm"]; !found {
		t.Fatalf("unrelated metadata was dropped: %v", entries[0].Metadata)
	}
}
