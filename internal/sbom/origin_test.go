package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

// originGraph builds a two-package graph whose nodes carry whatever origin
// metadata a case wants to exercise.
func originGraph(t *testing.T, mutate func(app, pkg *sdk.Dependency)) *sdk.Graph {
	t.Helper()

	g := sdk.New()
	app := sdk.NewDependencyRef("app", "1.0.0")
	pkg := sdk.NewDependencyRef("react", "18.2.0")
	mutate(app, pkg)
	for _, n := range []*sdk.Dependency{app, pkg} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, pkg.ID); err != nil {
		t.Fatalf("add edge: %v", err)
	}
	return g
}

// spdxPackageByName decodes an SPDX document and returns one package object.
func spdxPackageByName(t *testing.T, raw []byte, name string) map[string]any {
	t.Helper()
	var doc struct {
		Packages []map[string]any `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode SPDX: %v", err)
	}
	for _, pkg := range doc.Packages {
		if pkg["name"] == name {
			return pkg
		}
	}
	t.Fatalf("package %q not found in SPDX document", name)
	return nil
}

// cycloneDXReferences decodes a CycloneDX document and returns one component's
// external references as type→URL pairs.
func cycloneDXReferences(t *testing.T, raw []byte, name string) map[string]string {
	t.Helper()
	var doc struct {
		Components []struct {
			Name               string `json:"name"`
			ExternalReferences []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"externalReferences"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode CycloneDX: %v", err)
	}
	for _, component := range doc.Components {
		if component.Name != name {
			continue
		}
		refs := make(map[string]string, len(component.ExternalReferences))
		for _, ref := range component.ExternalReferences {
			refs[ref.Type] = ref.URL
		}
		return refs
	}
	t.Fatalf("component %q not found in CycloneDX document", name)
	return nil
}

func marshalBoth(t *testing.T, g *sdk.Graph) (spdxRaw, cdxRaw []byte) {
	t.Helper()
	opts := BuildOptions{DocumentName: "origin-test", ToolVersion: "test"}
	spdxRaw, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, opts, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal SPDX: %v", err)
	}
	cdxRaw, err = MarshalDepGraphJSON(g, TargetCycloneDX17JSON, opts, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal CycloneDX: %v", err)
	}
	return spdxRaw, cdxRaw
}

func TestArtifactOriginIsPublishedInBothFormats(t *testing.T) {
	const artifact = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
	g := originGraph(t, func(_, pkg *sdk.Dependency) {
		detectors.SetOriginArtifact(pkg, artifact)
	})

	spdxRaw, cdxRaw := marshalBoth(t, g)

	if got := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"]; got != artifact {
		t.Errorf("SPDX downloadLocation = %v, want %q", got, artifact)
	}
	if got := cycloneDXReferences(t, cdxRaw, "react")["distribution"]; got != artifact {
		t.Errorf("CycloneDX distribution ref = %q, want %q", got, artifact)
	}
}

func TestRepositoryOriginIsPublishedInBothFormats(t *testing.T) {
	const (
		repository = "https://github.com/facebook/react"
		revision   = "b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7"
	)
	g := originGraph(t, func(_, pkg *sdk.Dependency) {
		detectors.SetOriginVCS(pkg, repository, revision)
	})

	spdxRaw, cdxRaw := marshalBoth(t, g)

	// SPDX 2.3's version-control form carries the revision after "@".
	want := "git+" + repository + "@" + revision
	if got := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"]; got != want {
		t.Errorf("SPDX downloadLocation = %v, want %q", got, want)
	}
	// CycloneDX external references have no revision slot, so the reference is
	// the plain repository URL.
	if got := cycloneDXReferences(t, cdxRaw, "react")["vcs"]; got != repository {
		t.Errorf("CycloneDX vcs ref = %q, want %q", got, repository)
	}
	if got := cycloneDXReferences(t, cdxRaw, "react")["distribution"]; got != "" {
		t.Errorf("repository origin also emitted a distribution ref: %q", got)
	}
}

func TestUnpinnedRepositoryOriginOmitsTheRevisionSuffix(t *testing.T) {
	const repository = "https://github.com/facebook/react"
	g := originGraph(t, func(_, pkg *sdk.Dependency) {
		detectors.SetOriginVCS(pkg, repository, "")
	})

	spdxRaw, _ := marshalBoth(t, g)

	if got := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"]; got != "git+"+repository {
		t.Errorf("SPDX downloadLocation = %v, want %q", got, "git+"+repository)
	}
}

// A package whose detector asserted nothing must say so, not guess.
func TestPackageWithoutOriginKeepsNOASSERTION(t *testing.T) {
	g := originGraph(t, func(_, _ *sdk.Dependency) {})

	spdxRaw, cdxRaw := marshalBoth(t, g)

	if got := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"]; got != "NOASSERTION" {
		t.Errorf("SPDX downloadLocation = %v, want NOASSERTION", got)
	}
	if refs := cycloneDXReferences(t, cdxRaw, "react"); len(refs) != 0 {
		t.Errorf("CycloneDX emitted references for a package with no origin: %v", refs)
	}
}

// Origin metadata can reach export from a plugin or a hand-built graph that
// never went through the setters. Export re-validates rather than trusting it,
// so a bad value is dropped instead of published.
func TestExportRevalidatesOriginMetadata(t *testing.T) {
	hostile := []struct {
		name     string
		metadata map[string]any
	}{
		{name: "credentialed artifact", metadata: map[string]any{
			detectors.MetadataKeyOriginArtifactURL: "https://build:s3cret-token-value@nexus.corp/repo/react-18.2.0.tgz",
		}},
		{name: "local path", metadata: map[string]any{
			detectors.MetadataKeyOriginArtifactURL: "/Users/someone/src/project/react.tgz",
		}},
		{name: "file url", metadata: map[string]any{
			detectors.MetadataKeyOriginVCSURL: "file:///Users/someone/src/react",
		}},
		{name: "revision breaking the locator grammar", metadata: map[string]any{
			detectors.MetadataKeyOriginVCSURL:      "https://github.com/facebook/react",
			detectors.MetadataKeyOriginVCSRevision: "main@evil.test/x",
		}},
		{name: "non-string value", metadata: map[string]any{
			detectors.MetadataKeyOriginArtifactURL: 42,
		}},
	}

	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			g := originGraph(t, func(_, pkg *sdk.Dependency) {
				pkg.Metadata = tc.metadata
			})

			spdxRaw, cdxRaw := marshalBoth(t, g)

			download, _ := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"].(string)
			refs := cycloneDXReferences(t, cdxRaw, "react")
			published := append([]string{download}, refs["distribution"], refs["vcs"])
			for _, value := range published {
				for _, forbidden := range []string{"s3cret", "@nexus.corp", "/Users/", "file://", "evil.test"} {
					if strings.Contains(value, forbidden) {
						t.Fatalf("published %q, which contains %q", value, forbidden)
					}
				}
			}
			// The revision case keeps a valid repository; the rest publish nothing.
			if tc.name == "revision breaking the locator grammar" {
				if download != "git+https://github.com/facebook/react" {
					t.Fatalf("downloadLocation = %q, want the repository without a revision", download)
				}
				return
			}
			if download != "NOASSERTION" {
				t.Fatalf("downloadLocation = %q, want NOASSERTION", download)
			}
		})
	}
}

// The scorecard matcher resolves a canonical source repository during
// enrichment. It fills the gap when a lockfile named no repository, and never
// overrides one the detector asserted.
func TestScorecardRepositoryFillsTheOriginGap(t *testing.T) {
	const purl = "pkg:npm/react@18.2.0"

	build := func(t *testing.T, detectorRepository string) []byte {
		t.Helper()
		g := sdk.New()
		react := sdk.NewDependencyWithID("react@18.2.0", sdk.Dependency{Coordinates: sdk.Coordinates{
			Name: "react", Version: "18.2.0", PURL: purl, Ecosystem: "npm"}})
		if detectorRepository != "" {
			detectors.SetOriginVCS(react, detectorRepository, "")
		}
		if err := g.AddNode(react); err != nil {
			t.Fatalf("add node: %v", err)
		}
		registry := sdk.NewPackageRegistry()
		pkg := registry.Ensure(purl)
		pkg.Name, pkg.Version, pkg.Matched = "react", "18.2.0", true
		pkg.Scorecard = &sdk.PackageScorecard{Source: "api.scorecard.dev", Repository: "github.com/facebook/react"}

		raw, err := MarshalDepGraphJSON(g, TargetCycloneDX17JSON, BuildOptions{Registry: registry}, EncodeOptions{})
		if err != nil {
			t.Fatalf("marshal CycloneDX: %v", err)
		}
		return raw
	}

	t.Run("fills the gap", func(t *testing.T) {
		if got := cycloneDXReferences(t, build(t, ""), "react")["vcs"]; got != "https://github.com/facebook/react" {
			t.Errorf("vcs ref = %q, want the scorecard repository as an https URL", got)
		}
	})

	t.Run("never overrides the detector", func(t *testing.T) {
		const asserted = "https://github.com/facebook/react-fork"
		if got := cycloneDXReferences(t, build(t, asserted), "react")["vcs"]; got != asserted {
			t.Errorf("vcs ref = %q, want the detector-asserted repository %q", got, asserted)
		}
	})

	t.Run("absent without enrichment", func(t *testing.T) {
		g := originGraph(t, func(_, _ *sdk.Dependency) {})
		_, cdxRaw := marshalBoth(t, g)
		if refs := cycloneDXReferences(t, cdxRaw, "react"); len(refs) != 0 {
			t.Errorf("unenriched export emitted references: %v", refs)
		}
	})
}
