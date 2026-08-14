package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
	"github.com/spdx/tools-golang/spdx/v2/common"
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

// TestDetectorRevisionPinsVCSLocator covers the detectors (bundler, pub, the
// python family) that keep a git dependency's resolved commit in metadata
// while leaving ResolvedURL as the bare remote. Without folding it in, the
// export names a moving branch for a package whose commit is known.
func TestDetectorRevisionPinsVCSLocator(t *testing.T) {
	g := sdk.New()
	node := sdk.NewDependencyWithID("pkg@1.0.0", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name: "pkg", Version: "1.0.0",
			PURL: "pkg:gem/pkg@1.0.0", Ecosystem: sdk.EcosystemRuby,
		},
		Source:      sdk.DependencySourceGit,
		ResolvedURL: "https://github.com/owner/repo",
		Metadata:    map[string]any{"source_revision": "9f8e7d6c5b4a"},
	})
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	pkg := spdxPackageFor(t, g, BuildOptions{})
	if want := "git+https://github.com/owner/repo@9f8e7d6c5b4a"; pkg.PackageDownloadLocation != want {
		t.Fatalf("downloadLocation = %q, want the detector-resolved commit pinned (%q)",
			pkg.PackageDownloadLocation, want)
	}
}

// TestUnsafeDetectorRevisionIsIgnored keeps an unusable metadata value from
// producing a malformed locator.
func TestUnsafeDetectorRevisionIsIgnored(t *testing.T) {
	g := sdk.New()
	node := sdk.NewDependencyWithID("pkg@1.0.0", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name: "pkg", Version: "1.0.0",
			PURL: "pkg:gem/pkg@1.0.0", Ecosystem: sdk.EcosystemRuby,
		},
		Source:      sdk.DependencySourceGit,
		ResolvedURL: "https://github.com/owner/repo",
		Metadata:    map[string]any{"source_revision": "bad revision\x00"},
	})
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	pkg := spdxPackageFor(t, g, BuildOptions{})
	if want := "git+https://github.com/owner/repo"; pkg.PackageDownloadLocation != want {
		t.Fatalf("downloadLocation = %q, want the unpinned repository (%q)",
			pkg.PackageDownloadLocation, want)
	}
}

// TestBlake2bDigestsSurviveRoundTrip pairs with normalizeDigestAlgorithm: the
// canonical names it preserves must exist in both encoders, or the checksum is
// silently discarded after the graph hop.
//
// Both encoders skip an algorithm they cannot map, so a count check already
// catches a missing case. The algorithm is asserted as well to catch the other
// direction — a case mapped to the wrong constant, which would keep the count
// at one while relabelling the digest as a different family.
func TestBlake2bDigestsSurviveRoundTrip(t *testing.T) {
	cases := []struct {
		algorithm string
		// hexLen is the digest's real hex width. A wrong-width value is not
		// merely unrealistic: normalizeDigestValue would read it as an
		// npm-style base64 SRI digest and rewrite it, so the assertion would
		// compare against something the encoder never saw.
		hexLen   int
		wantSPDX common.ChecksumAlgorithm
		wantCDX  cdx.HashAlgorithm
	}{
		{"blake2b-256", 64, common.BLAKE2b_256, cdx.HashAlgoBlake2b_256},
		{"blake2b-384", 96, common.BLAKE2b_384, cdx.HashAlgoBlake2b_384},
		{"blake2b-512", 128, common.BLAKE2b_512, cdx.HashAlgoBlake2b_512},
		{"sha3-256", 64, common.SHA3_256, cdx.HashAlgoSHA3_256},
		{"sha256", 64, common.SHA256, cdx.HashAlgoSHA256},
	}

	for _, tc := range cases {
		t.Run(tc.algorithm, func(t *testing.T) {
			value := strings.Repeat("a", tc.hexLen)
			g := sdk.New()
			node := sdk.NewDependencyWithID("pkg@1.0.0", sdk.Dependency{
				Coordinates: sdk.Coordinates{
					Name: "pkg", Version: "1.0.0",
					PURL: "pkg:npm/pkg@1.0.0", Ecosystem: sdk.EcosystemNPM,
				},
				Digests: []sdk.Digest{{Algorithm: sdk.DigestAlgorithm(tc.algorithm), Value: value}},
			})
			if err := g.AddNode(node); err != nil {
				t.Fatalf("add node: %v", err)
			}

			pkg := spdxPackageFor(t, g, BuildOptions{})
			if len(pkg.PackageChecksums) != 1 {
				t.Fatalf("spdx dropped a %s checksum: %+v", tc.algorithm, pkg.PackageChecksums)
			}
			if got := pkg.PackageChecksums[0]; got.Algorithm != tc.wantSPDX || got.Value != value {
				t.Fatalf("spdx checksum = %+v, want %s with the asserted value", got, tc.wantSPDX)
			}

			comp := cycloneDXComponentFor(t, g, BuildOptions{})
			if comp.Hashes == nil || len(*comp.Hashes) != 1 {
				t.Fatalf("cyclonedx dropped a %s hash: %+v", tc.algorithm, comp.Hashes)
			}
			if got := (*comp.Hashes)[0]; got.Algorithm != tc.wantCDX || got.Value != value {
				t.Fatalf("cyclonedx hash = %+v, want %s with the asserted value", got, tc.wantCDX)
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

// TestEnrichmentDoesNotClobberIngestedSets covers `scan --sbom --enrich`.
// CPEs and digests are set-valued, so a matcher-supplied value must be added
// to the source document's assertions rather than replacing them — the
// ingest-wins / enrichment-fills-gaps ordering applies to sets too.
func TestEnrichmentDoesNotClobberIngestedSets(t *testing.T) {
	const purl = "pkg:npm/a@1.0.0"
	const ingestedCPE = "cpe:2.3:a:ingested:a:1.0.0:*:*:*:*:*:*:*"
	const matcherCPE = "cpe:2.3:a:matcher:a:1.0.0:*:*:*:*:*:*:*"
	ingestedHash := strings.Repeat("a", 64)
	matcherHash := strings.Repeat("b", 64)

	g := sdk.New()
	node := sdk.NewDependencyWithID(purl, sdk.Dependency{
		Coordinates: sdk.Coordinates{Name: "a", Version: "1.0.0", PURL: purl, Ecosystem: sdk.EcosystemNPM},
		CPEs:        []string{ingestedCPE},
		Digests:     []sdk.Digest{{Algorithm: sdk.DigestAlgorithmSHA256, Value: ingestedHash}},
	})
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Name, pkg.Version = "a", "1.0.0"
	pkg.CPEs = []string{matcherCPE}
	pkg.Digests = []sdk.Digest{{Algorithm: sdk.DigestAlgorithmSHA256, Value: matcherHash}}

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{Registry: registry}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for name, want := range map[string]string{
		"ingested CPE":  ingestedCPE,
		"matcher CPE":   matcherCPE,
		"ingested hash": ingestedHash,
		"matcher hash":  matcherHash,
	} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("%s was discarded by enrichment:\n%s", name, out)
		}
	}
}

// TestBlake3DigestSurvivesRoundTrip pairs with the BLAKE3 encoder mappings:
// parseSPDXChecksums accepts the algorithm, so both encoders must know it or
// the checksum is silently dropped after the graph hop.
func TestBlake3DigestSurvivesRoundTrip(t *testing.T) {
	value := strings.Repeat("d", 64)
	g := sdk.New()
	node := sdk.NewDependencyWithID("pkg@1.0.0", sdk.Dependency{
		Coordinates: sdk.Coordinates{Name: "pkg", Version: "1.0.0", PURL: "pkg:npm/pkg@1.0.0", Ecosystem: sdk.EcosystemNPM},
		Digests:     []sdk.Digest{{Algorithm: "blake3", Value: value}},
	})
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	pkg := spdxPackageFor(t, g, BuildOptions{})
	if len(pkg.PackageChecksums) != 1 ||
		pkg.PackageChecksums[0].Algorithm != common.BLAKE3 ||
		pkg.PackageChecksums[0].Value != value {
		t.Fatalf("spdx blake3 checksum = %+v, want it preserved with its value", pkg.PackageChecksums)
	}
	comp := cycloneDXComponentFor(t, g, BuildOptions{})
	if comp.Hashes == nil || len(*comp.Hashes) != 1 ||
		(*comp.Hashes)[0].Algorithm != cdx.HashAlgoBlake3 ||
		(*comp.Hashes)[0].Value != value {
		t.Fatalf("cyclonedx blake3 hash = %+v, want it preserved with its value", comp.Hashes)
	}
}

// TestEveryAcceptedDigestAlgorithmRoundTrips closes the class of bug that
// produced three separate one-line fixes (BLAKE2b, BLAKE3, and the SHA-3
// hyphen): an algorithm the decoder normalizes but an encoder does not know is
// silently dropped, and an algorithm without a length entry skips validation.
//
// Rather than another per-algorithm test, this asserts the invariant directly
// over the whole table, so a future addition cannot land half-wired.
func TestEveryAcceptedDigestAlgorithmRoundTrips(t *testing.T) {
	for algorithm, size := range digestHexSizes {
		canonical := normalizeDigestAlgorithm(algorithm)
		t.Run(algorithm, func(t *testing.T) {
			// The formats do not agree on their algorithm sets — SHA-224 is
			// SPDX-only, Streebog is CycloneDX-only — so the invariant is
			// that a validated algorithm reaches at least one encoder. An
			// entry reaching neither is dead weight that silently drops
			// every value it accepts.
			if spdxChecksumAlgorithm(canonical) == "" && cycloneDXHashAlgorithm(canonical) == "" {
				t.Fatalf("%q has a length entry but no encoder mapping in either format", algorithm)
			}

			// A value of the declared width must survive; a short one must not.
			value := strings.Repeat("a", size*2)
			if _, ok := ingestedDigest(algorithm, value); !ok {
				t.Fatalf("a correctly sized %q digest was rejected", algorithm)
			}
			if _, ok := ingestedDigest(algorithm, "ab"); ok {
				t.Fatalf("a short %q digest was accepted", algorithm)
			}
		})
	}
}

// TestNormalizedAlgorithmsHaveLengthEntries is the other direction: an
// algorithm an encoder can emit must also be length-validated on ingest, or a
// malformed value reaches the output unchecked.
func TestNormalizedAlgorithmsHaveLengthEntries(t *testing.T) {
	for _, algorithm := range []string{
		"md5", "md2", "md4", "md6", "adler32",
		"sha1", "sha224", "sha256", "sha384", "sha512",
		"sha3-256", "sha3-384", "sha3-512",
		"blake2b-256", "blake2b-384", "blake2b-512", "blake3",
		"streebog-256", "streebog-512",
	} {
		canonical := normalizeDigestAlgorithm(algorithm)
		if _, variable := variableLengthDigests[canonical]; variable {
			continue
		}
		if _, ok := digestHexSizes[canonical]; !ok {
			t.Fatalf("%q is emitted by the encoders but has no length entry, so ingest cannot validate it", algorithm)
		}
	}
}

// TestSwiftPMRevisionKeyIsRead covers the detector that records its resolved
// commit under "revision" rather than "source_revision". Reading only the
// latter exported a reproducible SwiftPM pin as a moving repository.
func TestSwiftPMRevisionKeyIsRead(t *testing.T) {
	g := sdk.New()
	node := sdk.NewDependencyWithID("pkg@1.0.0", sdk.Dependency{
		Coordinates: sdk.Coordinates{
			Name: "swift-nio", Version: "2.0.0",
			PURL: "pkg:swift/github.com/apple/swift-nio@2.0.0", Ecosystem: sdk.EcosystemSwift,
		},
		Source:      sdk.DependencySourceGit,
		ResolvedURL: "https://github.com/apple/swift-nio",
		Metadata:    map[string]any{"revision": "9f8e7d6c5b4a"},
	})
	if err := g.AddNode(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), "git+https://github.com/apple/swift-nio@9f8e7d6c5b4a") {
		t.Fatalf("swiftpm resolved revision was not pinned:\n%s", out)
	}
}
