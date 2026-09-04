package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"github.com/bomly-dev/bomly-sdk"
)

// originGraph builds a two-package graph whose nodes carry whatever origin
// metadata a case wants to exercise.
func originGraph(t *testing.T, mutate func(app, pkg *sdk.DependencyNode)) *sdk.Graph {
	t.Helper()

	g := sdk.New()
	app := testnodes.Ref("app", "1.0.0")
	pkg := testnodes.Ref("react", "18.2.0")
	mutate(app, pkg)
	for _, n := range []*sdk.DependencyNode{app, pkg} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), pkg.NodeID()); err != nil {
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
	g := originGraph(t, func(_, pkg *sdk.DependencyNode) {
		pkg.Origins = sdk.MergeOrigins(nil, originsFor(artifact))
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
	g := originGraph(t, func(_, pkg *sdk.DependencyNode) {
		pkg.Origins = sdk.MergeOrigins(nil, repositoryOriginsFor(repository, revision))
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
	g := originGraph(t, func(_, pkg *sdk.DependencyNode) {
		pkg.Origins = sdk.MergeOrigins(nil, repositoryOriginsFor(repository, ""))
	})

	spdxRaw, _ := marshalBoth(t, g)

	if got := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"]; got != "git+"+repository {
		t.Errorf("SPDX downloadLocation = %v, want %q", got, "git+"+repository)
	}
}

// A package whose detector asserted nothing must say so, not guess.
func TestPackageWithoutOriginKeepsNOASSERTION(t *testing.T) {
	g := originGraph(t, func(_, _ *sdk.DependencyNode) {})

	spdxRaw, cdxRaw := marshalBoth(t, g)

	if got := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"]; got != "NOASSERTION" {
		t.Errorf("SPDX downloadLocation = %v, want NOASSERTION", got)
	}
	if refs := cycloneDXReferences(t, cdxRaw, "react"); len(refs) != 0 {
		t.Errorf("CycloneDX emitted references for a package with no origin: %v", refs)
	}
}

// A hand-built origin can reach export from a plugin or a caller that never
// went through the constructors. Export re-validates rather than trusting it,
// so a bad value is dropped instead of published.
func TestExportRevalidatesOrigin(t *testing.T) {
	hostile := []struct {
		name   string
		origin *sdk.DependencyOrigin
	}{
		{name: "credentialed artifact", origin: &sdk.DependencyOrigin{ArtifactURL: "https://build:s3cret-token-value@nexus.corp/repo/react-18.2.0.tgz"}},
		{name: "local path", origin: &sdk.DependencyOrigin{ArtifactURL: "/Users/someone/src/project/react.tgz"}},
		{name: "file url", origin: &sdk.DependencyOrigin{Repository: "file:///Users/someone/src/react"}},
		{name: "registry root", origin: &sdk.DependencyOrigin{ArtifactURL: "https://registry.npmjs.org/"}},
		{name: "revision breaking the locator grammar", origin: &sdk.DependencyOrigin{
			Repository: "https://github.com/facebook/react", Revision: "main@evil.test/x",
		}},
	}

	for _, tc := range hostile {
		t.Run(tc.name, func(t *testing.T) {
			g := originGraph(t, func(_, pkg *sdk.DependencyNode) {
				pkg.Origins = []sdk.DependencyOrigin{*tc.origin}
			})

			spdxRaw, cdxRaw := marshalBoth(t, g)

			download, _ := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"].(string)
			refs := cycloneDXReferences(t, cdxRaw, "react")
			published := []string{download, refs["distribution"], refs["vcs"]}
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
		react := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
			Name: "react", Version: "18.2.0", PURL: purl, Ecosystem: "npm"}})
		if detectorRepository != "" {
			react.Origins = sdk.MergeOrigins(nil, repositoryOriginsFor(detectorRepository, ""))
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

	// An artifact says where the file was fetched; a repository says where the
	// source lives. They are complementary, so an enriched package can carry
	// both -- the repository as a vcs reference in CycloneDX, and as source
	// info in SPDX, whose single download location the artifact holds.
	t.Run("a repository accompanies an artifact", func(t *testing.T) {
		g := sdk.New()
		react := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
			Name: "react", Version: "18.2.0", PURL: purl, Ecosystem: "npm"}})
		react.Origins = sdk.MergeOrigins(nil, originsFor("https://registry.npmjs.org/react/-/react-18.2.0.tgz"))
		if err := g.AddNode(react); err != nil {
			t.Fatal(err)
		}
		registry := sdk.NewPackageRegistry()
		pkg := registry.Ensure(purl)
		pkg.Name, pkg.Version, pkg.Matched = "react", "18.2.0", true
		pkg.Scorecard = &sdk.PackageScorecard{Source: "api.scorecard.dev", Repository: "github.com/facebook/react"}

		opts := BuildOptions{Registry: registry}
		cdxRaw, err := MarshalDepGraphJSON(g, TargetCycloneDX17JSON, opts, EncodeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		spdxRaw, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, opts, EncodeOptions{})
		if err != nil {
			t.Fatal(err)
		}

		refs := cycloneDXReferences(t, cdxRaw, "react")
		if refs["distribution"] != "https://registry.npmjs.org/react/-/react-18.2.0.tgz" {
			t.Errorf("distribution ref = %q, want the detector artifact", refs["distribution"])
		}
		if refs["vcs"] != "https://github.com/facebook/react" {
			t.Errorf("vcs ref = %q, want the scorecard repository", refs["vcs"])
		}

		spdxPkg := spdxPackageByName(t, spdxRaw, "react")
		if spdxPkg["downloadLocation"] != "https://registry.npmjs.org/react/-/react-18.2.0.tgz" {
			t.Errorf("downloadLocation = %v, want the artifact", spdxPkg["downloadLocation"])
		}
		if got, _ := spdxPkg["sourceInfo"].(string); got != "Source repository: git+https://github.com/facebook/react" {
			t.Errorf("sourceInfo = %q, want the repository", got)
		}
	})

	// With no artifact, the repository is the download location, so repeating
	// it as source info would say the same thing twice.
	t.Run("a repository alone is not repeated as source info", func(t *testing.T) {
		g := originGraph(t, func(_, pkg *sdk.DependencyNode) {
			pkg.Origins = sdk.MergeOrigins(nil, repositoryOriginsFor("https://github.com/facebook/react", ""))
		})
		spdxRaw, _ := marshalBoth(t, g)
		spdxPkg := spdxPackageByName(t, spdxRaw, "react")
		if got, found := spdxPkg["sourceInfo"]; found && got != "" {
			t.Errorf("sourceInfo = %v, want none: the repository is the download location", got)
		}
	})

	t.Run("absent without enrichment", func(t *testing.T) {
		g := originGraph(t, func(_, _ *sdk.DependencyNode) {})
		_, cdxRaw := marshalBoth(t, g)
		if refs := cycloneDXReferences(t, cdxRaw, "react"); len(refs) != 0 {
			t.Errorf("unenriched export emitted references: %v", refs)
		}
	})
}

// Origin is written on export and not read back on ingest: it describes what a
// lockfile said, and an ingested document is not a lockfile. Scanning an SBOM
// therefore yields packages with no origin, and re-exporting that graph says
// NOASSERTION rather than repeating a claim Bomly did not resolve itself.
//
// This pins the documented limitation; preserving third-party origin across
// ingest is tracked separately.
func TestOriginIsNotReadBackFromAnIngestedDocument(t *testing.T) {
	g := originGraph(t, func(_, pkg *sdk.DependencyNode) {
		pkg.Origins = sdk.MergeOrigins(nil, repositoryOriginsFor("https://github.com/facebook/react", "d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"))
	})

	exported, _ := marshalBoth(t, g)
	if got := spdxPackageByName(t, exported, "react")["downloadLocation"]; got == "NOASSERTION" {
		t.Fatal("precondition failed: the first export carried no origin")
	}

	ingested, _, err := UnmarshalAutoJSON(exported)
	if err != nil {
		t.Fatalf("ingest SPDX: %v", err)
	}
	reingestedGraph, err := ToGraph(ingested)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	reexported, err := MarshalDepGraphJSON(reingestedGraph, TargetSPDX23JSON, BuildOptions{DocumentName: "origin-test", ToolVersion: "test"}, EncodeOptions{})
	if err != nil {
		t.Fatalf("re-export SPDX: %v", err)
	}

	if got := spdxPackageByName(t, reexported, "react")["downloadLocation"]; got != "NOASSERTION" {
		t.Fatalf("re-exported downloadLocation = %v, want NOASSERTION; if origin now survives ingest, docs/SBOM.md and dev-docs/adr/0033-package-origin-is-detector-asserted.md must say so", got)
	}

	// The rule is about ingest, not about a format, so CycloneDX loses it too.
	_, exportedCDX := marshalBoth(t, g)
	ingestedCDX, _, err := UnmarshalAutoJSON(exportedCDX)
	if err != nil {
		t.Fatalf("ingest CycloneDX: %v", err)
	}
	reingestedCDXGraph, err := ToGraph(ingestedCDX)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	reexportedCDX, err := MarshalDepGraphJSON(reingestedCDXGraph, TargetCycloneDX17JSON, BuildOptions{DocumentName: "origin-test", ToolVersion: "test"}, EncodeOptions{})
	if err != nil {
		t.Fatalf("re-export CycloneDX: %v", err)
	}
	if refs := cycloneDXReferences(t, reexportedCDX, "react"); len(refs) != 0 {
		t.Fatalf("re-exported CycloneDX carried references %v, want none", refs)
	}
}

// The project's own records never publish an external origin. Under ADR-0041
// that holds by construction -- a module node has no Origins field for a
// plugin-supplied graph to write into -- and export is where the guarantee is
// visible: the component for a module asserts nothing about where it came
// from, in either format.
func TestProjectOwnedComponentsPublishNoOrigin(t *testing.T) {
	g := sdk.New()
	app := testnodes.Module("package.json", "app", "1.0.0")
	member := testnodes.ModuleFrom("packages/react/package.json", sdk.Coordinates{
		Ecosystem: "npm", Name: "react", Version: "18.2.0",
	})
	for _, node := range []sdk.GraphNode{app, member} {
		if err := g.AddNode(node); err != nil {
			t.Fatalf("add node %s: %v", node.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), member.NodeID()); err != nil {
		t.Fatalf("add edge: %v", err)
	}

	spdxRaw, cdxRaw := marshalBoth(t, g)

	if got := spdxPackageByName(t, spdxRaw, "react")["downloadLocation"]; got != "NOASSERTION" {
		t.Fatalf("downloadLocation = %v, want NOASSERTION for the project's own record", got)
	}
	if refs := cycloneDXReferences(t, cdxRaw, "react"); len(refs) != 0 {
		t.Fatalf("project-owned component published references: %v", refs)
	}
}

// The registry package is shared by every occurrence of a PURL, so a scorecard
// repository resolved for a consumed package must not be projected onto the
// project's own record -- a workspace member or fork that shares the identity.
func TestScorecardRepositoryIsNotAttributedToProjectOwnedComponents(t *testing.T) {
	const purl = "pkg:npm/helper@1.0.0"

	g := sdk.New()
	// The workspace member and the consumed package share a package URL, so
	// they are separated by kind: the member is a module declared by its own
	// manifest, and its ID cannot collide with the consumed package's.
	member := testnodes.ModuleFrom("packages/helper/package.json", sdk.Coordinates{
		Name: "helper", Version: "1.0.0", PURL: purl, Ecosystem: "npm"})
	consumed := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Name: "helper", Version: "1.0.0", PURL: purl, Ecosystem: "npm"}})
	for _, node := range []sdk.GraphNode{member, consumed} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}

	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Name, pkg.Version, pkg.Matched = "helper", "1.0.0", true
	pkg.Scorecard = &sdk.PackageScorecard{Source: "api.scorecard.dev", Repository: "github.com/upstream/helper"}

	raw, err := MarshalDepGraphJSON(g, TargetCycloneDX17JSON, BuildOptions{Registry: registry}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var doc struct {
		Components []struct {
			BOMRef             string `json:"bom-ref"`
			ExternalReferences []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"externalReferences"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var memberChecked, consumedChecked bool
	for _, component := range doc.Components {
		hasVCS := false
		for _, ref := range component.ExternalReferences {
			if ref.Type == "vcs" {
				hasVCS = true
			}
		}
		switch component.BOMRef {
		case member.NodeID():
			memberChecked = true
			if hasVCS {
				t.Fatal("the project's own component was attributed to the upstream repository")
			}
		case consumed.NodeID():
			consumedChecked = true
			if !hasVCS {
				t.Fatal("the consumed component should carry the scorecard repository")
			}
		}
	}
	if !memberChecked || !consumedChecked {
		t.Fatalf("expected both components in the document (member %v, consumed %v)", memberChecked, consumedChecked)
	}
}

// originsFor builds the origin list an artifact URL asserts, or nothing when
// the URL is not one the publication gates accept.
func originsFor(artifactURL string) []sdk.DependencyOrigin {
	origin := sdk.ArtifactOrigin(artifactURL)
	if origin == nil {
		return nil
	}
	return []sdk.DependencyOrigin{*origin}
}

// repositoryOriginsFor builds the origin list a repository and revision
// assert, or nothing when they are not a pair the publication gates accept.
func repositoryOriginsFor(repository, revision string) []sdk.DependencyOrigin {
	origin := sdk.RepositoryOrigin(repository, revision)
	if origin == nil {
		return nil
	}
	return []sdk.DependencyOrigin{*origin}
}

// A component's purl field is a Package URL in both formats, and a module's
// node ID is not one -- it is the module grammar, which carries the declaring
// manifest path so two workspace members cannot collide.
//
// Publishing the ID there shipped "module:apps/web/package.json#pkg:npm/web@1.0.0"
// as a purl, which no consumer can parse. The bom-ref is where the identity
// belongs; this pins both halves.
func TestModuleComponentsPublishAPackageURLNotTheirNodeID(t *testing.T) {
	g := sdk.New()
	module := testnodes.ModuleFrom("apps/web/package.json", sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "web", Version: "1.0.0", Type: sdk.PackageTypeApplication,
	})
	dependency := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "left-pad", Version: "1.3.0",
	}})
	for _, node := range []sdk.GraphNode{module, dependency} {
		if err := g.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.AddEdge(module.NodeID(), dependency.NodeID()); err != nil {
		t.Fatal(err)
	}

	_, cdxRaw := marshalBoth(t, g)

	var doc struct {
		Components []struct {
			BOMRef string `json:"bom-ref"`
			Name   string `json:"name"`
			PURL   string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(cdxRaw, &doc); err != nil {
		t.Fatalf("decode CycloneDX: %v", err)
	}

	var checked int
	for _, component := range doc.Components {
		if component.Name != "web" {
			continue
		}
		checked++
		if component.PURL != "pkg:npm/web@1.0.0" {
			t.Errorf("module purl = %q, want the package URL its coordinates mint", component.PURL)
		}
		if component.BOMRef != module.NodeID() {
			t.Errorf("module bom-ref = %q, want the node identity %q", component.BOMRef, module.NodeID())
		}
	}
	if checked != 1 {
		t.Fatalf("found %d web components, want 1", checked)
	}
}

// A package resolved from two registries keeps both in the exported document.
//
// ADR-0041 folds equal-identity records into one node and keeps the
// disagreement as a list of origins; that list is the dependency-confusion
// signal the fold exists to preserve. Publishing only the first discarded it
// at the export boundary -- the document then described a package that
// resolved from two places as though it had come from one, which is exactly
// backwards for the case that matters most.
func TestExportKeepsEveryFoldedOrigin(t *testing.T) {
	const (
		first  = "https://registry.npmjs.org/react/-/react-18.2.0.tgz"
		second = "https://npm.internal.example.com/react/-/react-18.2.0.tgz"
	)
	g := originGraph(t, func(_, pkg *sdk.DependencyNode) {
		for _, raw := range []string{first, second} {
			if origin := sdk.ArtifactOrigin(raw); origin != nil {
				pkg.Origins = sdk.MergeOrigins(pkg.Origins, []sdk.DependencyOrigin{*origin})
			}
		}
	})
	if got := len(g.DependencyNodes()); got != 2 {
		t.Fatalf("graph holds %d dependency nodes; want the fixture's two", got)
	}

	for _, target := range []Target{TargetCycloneDX16JSON, TargetSPDX23JSON} {
		out, err := MarshalDepGraphJSON(g, target, BuildOptions{}, EncodeOptions{})
		if err != nil {
			t.Fatalf("marshal %v: %v", target, err)
		}
		encoded := string(out)
		for _, want := range []string{first, second} {
			if !strings.Contains(encoded, want) {
				t.Fatalf("%v document dropped origin %q; both resolutions must survive export:\n%s",
					target, want, encoded)
			}
		}
		// Well-formed output, not just a string match.
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("%v document is not valid JSON: %v", target, err)
		}
	}
}
