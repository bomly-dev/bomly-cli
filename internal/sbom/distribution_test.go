package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// graphWithResolvedURL builds a one-node graph carrying a detector-supplied
// resolved URL, the shape every distribution assertion is derived from.
func graphWithResolvedURL(t *testing.T, resolved string, source sdk.DependencySource, ecosystem sdk.Ecosystem) *sdk.Graph {
	t.Helper()
	g := sdk.New()
	node := sdk.NewDependencyWithID("pkg@1.0.0", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name:      "pkg",
			Version:   "1.0.0",
			PURL:      "pkg:npm/pkg@1.0.0",
			Ecosystem: ecosystem,
		},
		Source:      source,
		ResolvedURL: resolved,
	})
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}
	return g
}

func spdxPackageFor(t *testing.T, g *sdk.Graph, opts BuildOptions) *v23.Package {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, opts, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	var doc v23.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	for _, p := range doc.Packages {
		if p != nil && p.PackageName == "pkg" {
			return p
		}
	}
	t.Fatal("package not found in spdx output")
	return nil
}

func cycloneDXComponentFor(t *testing.T, g *sdk.Graph, opts BuildOptions) cdx.Component {
	t.Helper()
	out, err := MarshalDepGraphJSON(g, TargetCycloneDX17JSON, opts, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if bom.Components == nil {
		t.Fatal("no components in cyclonedx output")
	}
	for _, comp := range *bom.Components {
		if comp.Name == "pkg" {
			return comp
		}
	}
	t.Fatal("component not found in cyclonedx output")
	return cdx.Component{}
}

func externalRefURL(comp cdx.Component, refType cdx.ExternalReferenceType) string {
	if comp.ExternalReferences == nil {
		return ""
	}
	for _, ref := range *comp.ExternalReferences {
		if ref.Type == refType {
			return ref.URL
		}
	}
	return ""
}

func TestDistributionProjection(t *testing.T) {
	cases := []struct {
		name         string
		resolved     string
		source       sdk.DependencySource
		ecosystem    sdk.Ecosystem
		wantDownload string
		wantDistRef  string
		wantVCSRef   string
	}{
		{
			name:         "npm tarball becomes a download location",
			resolved:     "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
			source:       sdk.DependencySourceRegistry,
			ecosystem:    sdk.EcosystemNPM,
			wantDownload: "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
			wantDistRef:  "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
		},
		{
			// The single most important regression case: a registry root is
			// a valid URL that both validators accept, and reading it as the
			// artifact's origin would be wrong.
			name:         "rubygems registry root never becomes a download location",
			resolved:     "https://rubygems.org/",
			source:       sdk.DependencySourceRegistry,
			ecosystem:    sdk.EcosystemRuby,
			wantDownload: "NOASSERTION",
			wantDistRef:  "https://rubygems.org/",
		},
		{
			name:         "cargo registry index never becomes a download location",
			resolved:     "registry+https://github.com/rust-lang/crates.io-index",
			source:       sdk.DependencySourceRegistry,
			ecosystem:    sdk.EcosystemRust,
			wantDownload: "NOASSERTION",
			wantDistRef:  "https://github.com/rust-lang/crates.io-index",
		},
		{
			name:         "cargo git pin normalizes to the spdx vcs form",
			resolved:     "git+https://github.com/a/b?rev=deadbeef",
			source:       sdk.DependencySourceGit,
			ecosystem:    sdk.EcosystemRust,
			wantDownload: "git+https://github.com/a/b@deadbeef",
			wantVCSRef:   "git+https://github.com/a/b@deadbeef",
		},
		{
			name:         "uv editable local path is never emitted",
			resolved:     "/Users/ahmed/dev/mylib",
			source:       sdk.DependencySourceFile,
			ecosystem:    sdk.EcosystemPython,
			wantDownload: "NOASSERTION",
		},
		{
			name:         "credential bearing url is never emitted",
			resolved:     "https://tok:s3cret@nexus.corp/pkg-1.0.0.tgz",
			source:       sdk.DependencySourceRegistry,
			ecosystem:    sdk.EcosystemNPM,
			wantDownload: "NOASSERTION",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := graphWithResolvedURL(t, tc.resolved, tc.source, tc.ecosystem)

			pkg := spdxPackageFor(t, g, BuildOptions{})
			if pkg.PackageDownloadLocation != tc.wantDownload {
				t.Fatalf("downloadLocation = %q, want %q", pkg.PackageDownloadLocation, tc.wantDownload)
			}

			comp := cycloneDXComponentFor(t, g, BuildOptions{})
			if got := externalRefURL(comp, cdx.ERTypeDistribution); got != tc.wantDistRef {
				t.Fatalf("distribution ref = %q, want %q", got, tc.wantDistRef)
			}
			if got := externalRefURL(comp, cdx.ERTypeVCS); got != tc.wantVCSRef {
				t.Fatalf("vcs ref = %q, want %q", got, tc.wantVCSRef)
			}
		})
	}
}

// TestDistributionNeverLeaksLocalPaths asserts on the encoded bytes, the way a
// consumer would see them. A path leak is the one genuinely dangerous failure
// mode of this feature.
func TestDistributionNeverLeaksLocalPaths(t *testing.T) {
	secrets := []string{
		"/Users/ahmed/secret-project",
		"../../etc/passwd",
		"file:///Users/ahmed/x",
		"https://tok:s3cret@nexus.corp/a-1.0.tgz",
	}
	for _, secret := range secrets {
		g := graphWithResolvedURL(t, secret, sdk.DependencySourceRegistry, sdk.EcosystemNPM)
		for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX17JSON} {
			out, err := MarshalDepGraphJSON(g, target, BuildOptions{}, EncodeOptions{})
			if err != nil {
				t.Fatalf("marshal %s: %v", target, err)
			}
			needle := secret
			if idx := strings.Index(needle, "://"); idx >= 0 {
				needle = needle[idx+3:]
			}
			if strings.Contains(string(out), needle) {
				t.Fatalf("%s output leaked %q", target, secret)
			}
		}
	}
}

func TestScorecardRepositoryProjection(t *testing.T) {
	const purl = "pkg:npm/pkg@1.0.0"
	g := graphWithResolvedURL(t, "", sdk.DependencySourceRegistry, sdk.EcosystemNPM)

	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Name, pkg.Version = "pkg", "1.0.0"
	pkg.Scorecard = &sdk.PackageScorecard{Repository: "github.com/owner/repo"}

	opts := BuildOptions{Registry: registry}
	comp := cycloneDXComponentFor(t, g, opts)
	if got := externalRefURL(comp, cdx.ERTypeVCS); got != "https://github.com/owner/repo" {
		t.Fatalf("vcs ref = %q, want the normalized scorecard repository", got)
	}

	spdxPkg := spdxPackageFor(t, g, opts)
	if want := "Source repository: https://github.com/owner/repo"; spdxPkg.PackageSourceInfo != want {
		t.Fatalf("sourceInfo = %q, want %q", spdxPkg.PackageSourceInfo, want)
	}
}

// TestScorecardRepositoryAbsentWithoutEnrichment covers the registry-less call
// shape used by the benchmark, where every registry-sourced field must degrade
// to omitted rather than panic or invent a value.
func TestScorecardRepositoryAbsentWithoutEnrichment(t *testing.T) {
	g := graphWithResolvedURL(t, "", sdk.DependencySourceRegistry, sdk.EcosystemNPM)

	comp := cycloneDXComponentFor(t, g, BuildOptions{})
	if comp.ExternalReferences != nil {
		t.Fatalf("expected no external references, got %+v", *comp.ExternalReferences)
	}
	if spdxPkg := spdxPackageFor(t, g, BuildOptions{}); spdxPkg.PackageSourceInfo != "" {
		t.Fatalf("expected no sourceInfo, got %q", spdxPkg.PackageSourceInfo)
	}
}

// TestDetectorVCSWinsOverScorecardRepository keeps the two sources from each
// asserting the same repository twice.
func TestDetectorVCSWinsOverScorecardRepository(t *testing.T) {
	const purl = "pkg:npm/pkg@1.0.0"
	g := graphWithResolvedURL(t, "git+https://github.com/a/b?rev=deadbeef", sdk.DependencySourceGit, sdk.EcosystemNPM)

	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Name, pkg.Version = "pkg", "1.0.0"
	pkg.Scorecard = &sdk.PackageScorecard{Repository: "github.com/owner/repo"}

	comp := cycloneDXComponentFor(t, g, BuildOptions{Registry: registry})
	vcsRefs := 0
	for _, ref := range *comp.ExternalReferences {
		if ref.Type == cdx.ERTypeVCS {
			vcsRefs++
			if ref.URL != "git+https://github.com/a/b@deadbeef" {
				t.Fatalf("vcs ref = %q, want the detector-supplied pin", ref.URL)
			}
		}
	}
	if vcsRefs != 1 {
		t.Fatalf("expected exactly one vcs reference, got %d", vcsRefs)
	}
}
