package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/syft/syft/artifact"
	syftfile "github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func TestMarshalDepGraphJSON_SPDX23(t *testing.T) {
	g := mustGraph(t)
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{
		DocumentName: "test-doc",
		DocumentNS:   "https://example.com/spdx/test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if d.SPDXVersion != v23.Version {
		t.Fatalf("unexpected spdx version: %s", d.SPDXVersion)
	}
	if len(d.Packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(d.Packages))
	}

	dependsOn := 0
	describes := 0
	for _, rel := range d.Relationships {
		if rel == nil {
			continue
		}
		if rel.Relationship == common.TypeRelationshipDependsOn {
			dependsOn++
		}
		if rel.Relationship == common.TypeRelationshipDescribe {
			describes++
		}
	}
	if dependsOn != 2 {
		t.Fatalf("expected 2 DEPENDS_ON relationships, got %d", dependsOn)
	}
	if describes != 1 {
		t.Fatalf("expected 1 DESCRIBES relationship, got %d", describes)
	}
}

func TestMarshalDepGraphJSON_SPDX23ToolCreators(t *testing.T) {
	g := mustGraph(t)
	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{
		ToolName:  "bomly-cli-test",
		ToolNames: []string{"bomly-detector:npm-detector", "bomly-detector:go-detector"},
		Created:   time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	got := make([]string, 0, len(d.CreationInfo.Creators))
	for _, creator := range d.CreationInfo.Creators {
		if creator.CreatorType == "Tool" {
			got = append(got, creator.Creator)
		}
	}
	want := []string{"bomly-cli-test", "bomly-detector:npm-detector", "bomly-detector:go-detector"}
	if !equalStringSlices(got, want) {
		t.Fatalf("tools = %#v, want %#v", got, want)
	}
	doc, _, err := UnmarshalAutoJSON(out)
	if err != nil {
		t.Fatalf("unmarshal auto: %v", err)
	}
	if !equalStringSlices(doc.Tools, want) {
		t.Fatalf("decoded tools = %#v, want %#v", doc.Tools, want)
	}
}

func TestMarshalDepGraphJSON_SPDX23Scope(t *testing.T) {
	g := sdk.New()
	app := sdk.NewDependencyRef("app", "1.0.0")
	react := sdk.NewDependency(sdk.Dependency{Name: "react", Version: "18.2.0", Scopes: sdk.ScopesOf("runtime")})
	vitest := sdk.NewDependency(sdk.Dependency{Name: "vitest", Version: "2.0.0", Scopes: sdk.ScopesOf("development")})
	for _, n := range []*sdk.Dependency{app, react, vitest} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, react.ID); err != nil {
		t.Fatalf("add edge app->react: %v", err)
	}
	if err := g.AddEdge(app.ID, vitest.ID); err != nil {
		t.Fatalf("add edge app->vitest: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{
		DocumentName: "test-doc",
		DocumentNS:   "https://example.com/spdx/test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}

	comments := map[string]string{}
	for _, pkg := range d.Packages {
		if pkg == nil {
			continue
		}
		comments[pkg.PackageName] = pkg.PackageComment
	}
	if comments["react"] != "bomly:scope=runtime" {
		t.Fatalf("expected react SPDX package comment to include runtime scope, got %q", comments["react"])
	}
	if comments["vitest"] != "bomly:scope=development" {
		t.Fatalf("expected vitest SPDX package comment to include development scope, got %q", comments["vitest"])
	}
}

func TestMarshalDepGraphJSON_SPDX23PreservesPackageType(t *testing.T) {
	g := sdk.New()
	app := sdk.NewDependency(sdk.Dependency{
		Ecosystem: "npm",
		Name:      "demo",
		Version:   "1.0.0",
		Type:      "application",
		PURL:      "pkg:npm/demo@1.0.0",
	})

	if err := g.AddNode(app); err != nil {
		t.Fatalf("add app: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{
		DocumentName: "test-doc",
		DocumentNS:   "https://example.com/spdx/test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	doc, _, err := UnmarshalAutoJSON(out)
	if err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	graph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	pkg, ok := graph.Node("pkg:npm/demo@1.0.0")
	if !ok {
		t.Fatalf("expected demo package, got %v", graph.Nodes())
	}
	if pkg.Type != "application" {
		t.Fatalf("expected application type, got %q", pkg.Type)
	}
}

func TestMarshalDepGraphJSON_SPDX23PreservesPURLAndCopyright(t *testing.T) {
	g := sdk.New()
	pkg := sdk.NewDependency(sdk.Dependency{
		Ecosystem:      "npm",
		PackageManager: "npm",
		Name:           "accept",
		Version:        "1.1.0",
		PURL:           "pkg:npm/accept@1.1.0",
		Copyright:      "Copyright (c) 2014, Walmart and other contributors.",
	})
	sdk.SetDetectionLicenses(pkg, []sdk.PackageLicense{{SPDXExpression: "BSD-3-Clause"}})

	if err := g.AddNode(pkg); err != nil {
		t.Fatalf("add package: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{
		DocumentName: "test-doc",
		DocumentNS:   "https://example.com/spdx/test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if len(d.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(d.Packages))
	}
	ref := d.Packages[0].PackageExternalReferences
	if len(ref) != 1 || ref[0] == nil {
		t.Fatalf("expected one purl external reference, got %#v", ref)
	}
	if ref[0].Category != "PACKAGE-MANAGER" || ref[0].RefType != "purl" || ref[0].Locator != "pkg:npm/accept@1.1.0" {
		t.Fatalf("unexpected external ref: %#v", ref[0])
	}
	if d.Packages[0].PackageCopyrightText != "Copyright (c) 2014, Walmart and other contributors." {
		t.Fatalf("unexpected copyright text: %q", d.Packages[0].PackageCopyrightText)
	}
}

func TestMarshalDepGraphJSON_CycloneDXVersions(t *testing.T) {
	g := mustGraph(t)
	targets := []struct {
		target  Target
		version cdx.SpecVersion
	}{
		{target: TargetCycloneDX14JSON, version: cdx.SpecVersion1_4},
		{target: TargetCycloneDX15JSON, version: cdx.SpecVersion1_5},
		{target: TargetCycloneDX16JSON, version: cdx.SpecVersion1_6},
	}

	for _, tc := range targets {
		out, err := MarshalDepGraphJSON(g, tc.target, BuildOptions{
			DocumentName: "test-doc",
			ToolName:     "bomly-cli-test",
			Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
		}, EncodeOptions{})
		if err != nil {
			t.Fatalf("%s marshal failed: %v", tc.target, err)
		}

		var bom cdx.BOM
		dec := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON)
		if err := dec.Decode(&bom); err != nil {
			t.Fatalf("%s decode failed: %v", tc.target, err)
		}
		if bom.SpecVersion != tc.version {
			t.Fatalf("%s expected spec %s got %s", tc.target, tc.version, bom.SpecVersion)
		}
		if bom.Components == nil || len(*bom.Components) != 3 {
			t.Fatalf("%s expected 3 components", tc.target)
		}
	}
}

func TestMarshalDepGraphJSON_CycloneDXScope(t *testing.T) {
	g := sdk.New()
	app := sdk.NewDependencyRef("app", "1.0.0")
	runtimeDep := sdk.NewDependency(sdk.Dependency{Name: "react", Version: "18.2.0", Scopes: sdk.ScopesOf("runtime")})
	devDep := sdk.NewDependency(sdk.Dependency{Name: "vitest", Version: "2.0.0", Scopes: sdk.ScopesOf("development")})
	for _, n := range []*sdk.Dependency{app, runtimeDep, devDep} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, runtimeDep.ID); err != nil {
		t.Fatalf("add runtime edge: %v", err)
	}
	if err := g.AddEdge(app.ID, devDep.ID); err != nil {
		t.Fatalf("add development edge: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{
		DocumentName: "test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(bytes.NewReader(out), cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		t.Fatalf("decode cyclonedx: %v", err)
	}

	if bom.Components == nil {
		t.Fatal("expected components")
	}
	scopes := map[string]cdx.Scope{}
	for _, comp := range *bom.Components {
		scopes[comp.Name] = comp.Scope
	}
	if scopes["react"] != cdx.ScopeRequired {
		t.Fatalf("expected runtime dependency to map to required scope, got %q", scopes["react"])
	}
	if scopes["vitest"] != cdx.ScopeExcluded {
		t.Fatalf("expected development dependency to map to excluded scope, got %q", scopes["vitest"])
	}
}

func TestUnmarshalJSON_RoundTripTargets(t *testing.T) {
	g := mustGraph(t)
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX14JSON, TargetCycloneDX15JSON, TargetCycloneDX16JSON} {
		out, err := MarshalDepGraphJSON(g, target, BuildOptions{
			DocumentName: "test-doc",
			ToolName:     "bomly-cli-test",
			Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
		}, EncodeOptions{})
		if err != nil {
			t.Fatalf("%s marshal: %v", target, err)
		}

		doc, err := UnmarshalJSON(out, target)
		if err != nil {
			t.Fatalf("%s unmarshal: %v", target, err)
		}
		if len(doc.Components) == 0 {
			t.Fatalf("%s expected components after unmarshal", target)
		}
	}
}

func TestUnmarshalJSON_SPDX23RestoresPackageIdentityFromPURL(t *testing.T) {
	g := sdk.New()
	if err := g.AddNode(sdk.NewDependency(sdk.Dependency{
		Ecosystem:      "npm",
		PackageManager: "npm",
		Name:           "accept",
		Version:        "1.1.0",
		PURL:           "pkg:npm/accept@1.1.0",
	})); err != nil {
		t.Fatalf("add package: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{
		DocumentName: "test-doc",
		DocumentNS:   "https://example.com/spdx/test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	doc, err := UnmarshalJSON(out, TargetSPDX23JSON)
	if err != nil {
		t.Fatalf("UnmarshalJSON(): %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(doc.Components))
	}
	component := doc.Components[0]
	if component.PURL != "pkg:npm/accept@1.1.0" {
		t.Fatalf("expected component purl to round-trip, got %q", component.PURL)
	}
	if component.Ecosystem != "npm" {
		t.Fatalf("expected component ecosystem npm, got %q", component.Ecosystem)
	}
	if component.PackageManager != "npm" {
		t.Fatalf("expected component package manager npm, got %q", component.PackageManager)
	}

	roundTrippedGraph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph(): %v", err)
	}
	pkg, ok := roundTrippedGraph.Node("pkg:npm/accept@1.1.0")
	if !ok || pkg == nil {
		t.Fatalf("expected round-tripped graph package, got %s", roundTrippedGraph.PrettyString())
	}
	if pkg.PURL != "pkg:npm/accept@1.1.0" {
		t.Fatalf("expected graph package purl, got %q", pkg.PURL)
	}
	if pkg.Ecosystem != "npm" || pkg.PackageManager != "npm" {
		t.Fatalf("expected graph package identity restored, got ecosystem=%q packageManager=%q", pkg.Ecosystem, pkg.PackageManager)
	}
}

func TestUnmarshalJSON_CycloneDXPreservesPURL(t *testing.T) {
	g := sdk.New()
	if err := g.AddNode(sdk.NewDependency(sdk.Dependency{
		Ecosystem:      "npm",
		PackageManager: "npm",
		Name:           "accept",
		Version:        "1.1.0",
		PURL:           "pkg:npm/accept@1.1.0",
	})); err != nil {
		t.Fatalf("add package: %v", err)
	}

	out, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{
		DocumentName: "test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	doc, err := UnmarshalJSON(out, TargetCycloneDX16JSON)
	if err != nil {
		t.Fatalf("UnmarshalJSON(): %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(doc.Components))
	}
	if doc.Components[0].PURL != "pkg:npm/accept@1.1.0" {
		t.Fatalf("expected purl to round-trip through cyclonedx, got %q", doc.Components[0].PURL)
	}
}

func TestDetectJSONTarget_DetectsSupportedFormats(t *testing.T) {
	g := mustGraph(t)

	spdxData, err := MarshalDepGraphJSON(g, TargetSPDX23JSON, BuildOptions{Created: time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}
	if target, err := DetectJSONTarget(spdxData); err != nil || target != TargetSPDX23JSON {
		t.Fatalf("DetectJSONTarget(spdx) = (%q, %v)", target, err)
	}

	cdxData, err := MarshalDepGraphJSON(g, TargetCycloneDX16JSON, BuildOptions{Created: time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC)}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}
	if target, err := DetectJSONTarget(cdxData); err != nil || target != TargetCycloneDX16JSON {
		t.Fatalf("DetectJSONTarget(cyclonedx) = (%q, %v)", target, err)
	}

	syftData := mustSyftJSONFixture(t)
	if target, err := DetectJSONTarget(syftData); err != nil || target != TargetSyftJSON {
		t.Fatalf("DetectJSONTarget(syft) = (%q, %v)", target, err)
	}
}

func TestUnmarshalAutoJSON_RejectsUnsupportedOrMalformedJSON(t *testing.T) {
	if _, _, err := UnmarshalAutoJSON([]byte(`{"hello":"world"}`)); err == nil || !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("expected unsupported-format error, got %v", err)
	}
	if _, _, err := UnmarshalAutoJSON([]byte(`{"hello":`)); err == nil || !errors.Is(err, ErrMalformedJSON) {
		t.Fatalf("expected malformed-json error, got %v", err)
	}
}

func TestToGraph_AllowsCycles(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: "a", Name: "a"},
			{ID: "b", Name: "b"},
		},
		Dependencies: []Dependency{
			{Ref: "a", DependsOn: []string{"b"}},
			{Ref: "b", DependsOn: []string{"a"}},
		},
	}

	depsGraph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph(): %v", err)
	}

	aDeps, err := depsGraph.DirectDependencies("a")
	if err != nil {
		t.Fatalf("Dependencies(a): %v", err)
	}
	bDeps, err := depsGraph.DirectDependencies("b")
	if err != nil {
		t.Fatalf("Dependencies(b): %v", err)
	}
	if got := idsOfPackages(aDeps); len(got) != 1 || got[0] != "b" {
		t.Fatalf("expected a -> b, got %#v", got)
	}
	if got := idsOfPackages(bDeps); len(got) != 1 || got[0] != "a" {
		t.Fatalf("expected b -> a, got %#v", got)
	}
}

func TestToGraph_MergesDuplicatePURLComponents(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{
				ID:      "SPDXRef-Package-python-certifi-from-lock",
				Name:    "certifi",
				Version: "2026.4.22",
				PURL:    "pkg:pypi/certifi@2026.4.22",
			},
			{
				ID:      "SPDXRef-Package-python-certifi-from-metadata",
				Name:    "certifi",
				Version: "2026.4.22",
				PURL:    "pkg:pypi/certifi@2026.4.22",
			},
			{
				ID:      "SPDXRef-Package-python-requests",
				Name:    "requests",
				Version: "2.21.0",
				PURL:    "pkg:pypi/requests@2.21.0",
			},
		},
		Dependencies: []Dependency{
			{Ref: "SPDXRef-Package-python-requests", DependsOn: []string{"SPDXRef-Package-python-certifi-from-lock"}},
			{Ref: "SPDXRef-Package-python-certifi-from-lock", DependsOn: []string{"SPDXRef-Package-python-certifi-from-metadata"}},
		},
	}

	depsGraph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph(): %v", err)
	}
	if depsGraph.Size() != 2 {
		t.Fatalf("expected duplicate PURL components to merge to 2 packages, got %d", depsGraph.Size())
	}
	deps, err := depsGraph.DirectDependencies("pkg:pypi/requests@2.21.0")
	if err != nil {
		t.Fatalf("Dependencies(): %v", err)
	}
	if got := idsOfPackages(deps); len(got) != 1 || got[0] != "pkg:pypi/certifi@2026.4.22" {
		t.Fatalf("expected requests -> certifi, got %#v", got)
	}
}

func TestToGraph_SkipsDocumentRootPseudoPackage(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: "SPDXRef-DocumentRoot-Directory-demo", Name: "/tmp/demo", Type: "file"},
			{ID: "SPDXRef-Package-react", Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"},
		},
		Dependencies: []Dependency{
			{Ref: "SPDXRef-DocumentRoot-Directory-demo", DependsOn: []string{"SPDXRef-Package-react"}},
		},
	}

	depsGraph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph(): %v", err)
	}
	if depsGraph.Size() != 1 {
		t.Fatalf("expected only real package, got %d: %s", depsGraph.Size(), depsGraph.PrettyString())
	}
	if _, ok := depsGraph.Node("pkg:npm/react@18.2.0"); !ok {
		t.Fatalf("expected react package, got %s", depsGraph.PrettyString())
	}
}

func TestUnmarshalJSON_SPDX23ParsesDependencyOfAndPrimaryPackagePurpose(t *testing.T) {
	raw := []byte(`{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "syft",
  "documentNamespace": "https://example.com/syft",
  "creationInfo": {"created": "2025-01-01T00:00:00Z", "creators": ["Tool: syft"]},
  "packages": [
    {"SPDXID": "SPDXRef-root", "name": "/tmp/demo", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "primaryPackagePurpose": "FILE"},
    {"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/app@1.0.0"}]},
    {"SPDXID": "SPDXRef-dep", "name": "dep", "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/dep@1.0.0"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "DESCRIBES"},
    {"spdxElementId": "SPDXRef-dep", "relatedSpdxElement": "SPDXRef-app", "relationshipType": "DEPENDENCY_OF"}
  ]
}`)

	doc, err := UnmarshalJSON(raw, TargetSPDX23JSON)
	if err != nil {
		t.Fatalf("UnmarshalJSON(): %v", err)
	}
	var rootType string
	for _, component := range doc.Components {
		if component.ID == "SPDXRef-root" {
			rootType = component.Type
		}
	}
	if rootType != "file" {
		t.Fatalf("expected root component type file, got %q", rootType)
	}
	depsGraph, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("ToGraph(): %v", err)
	}
	deps, err := depsGraph.DirectDependencies("pkg:npm/app@1.0.0")
	if err != nil {
		t.Fatalf("Dependencies(): %v", err)
	}
	if got := idsOfPackages(deps); len(got) != 1 || got[0] != "pkg:npm/dep@1.0.0" {
		t.Fatalf("expected app -> dep, got %#v", got)
	}
}

func mustGraph(t *testing.T) *sdk.Graph {
	t.Helper()

	g := sdk.New()
	app := sdk.NewDependencyRef("app", "1.0.0")
	react := sdk.NewDependencyRef("react", "18.2.0")
	zod := sdk.NewDependencyRef("zod", "3.23.0")

	for _, n := range []*sdk.Dependency{app, react, zod} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(app.ID, react.ID); err != nil {
		t.Fatalf("add edge app->react: %v", err)
	}
	if err := g.AddEdge(app.ID, zod.ID); err != nil {
		t.Fatalf("add edge app->zod: %v", err)
	}
	return g
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func idsOfPackages(packages []*sdk.Dependency) []string {
	ids := make([]string, 0, len(packages))
	for _, pkg := range packages {
		ids = append(ids, pkg.ID)
	}
	return ids
}

func mustSyftJSONFixture(t *testing.T) []byte {
	t.Helper()

	app := syftpkg.Package{
		Name:      "demo-app",
		Version:   "1.0.0",
		Type:      syftpkg.NpmPkg,
		PURL:      "pkg:npm/demo-app@1.0.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("package-lock.json")),
	}
	app.SetID()

	dependency := syftpkg.Package{
		Name:      "react",
		Version:   "18.2.0",
		Type:      syftpkg.NpmPkg,
		PURL:      "pkg:npm/react@18.2.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("package-lock.json")),
		Licenses:  syftpkg.NewLicenseSet(syftpkg.NewLicense("MIT")),
	}
	dependency.SetID()

	doc := syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(app, dependency),
		},
		Relationships: []artifact.Relationship{
			{From: dependency, To: app, Type: artifact.DependencyOfRelationship},
		},
	}

	encoder, err := syftjson.NewFormatEncoderWithConfig(syftjson.EncoderConfig{Pretty: true})
	if err != nil {
		t.Fatalf("new syft encoder: %v", err)
	}
	var out bytes.Buffer
	if err := encoder.Encode(&out, doc); err != nil {
		t.Fatalf("encode syft json: %v", err)
	}
	return []byte(strings.TrimSpace(out.String()))
}
