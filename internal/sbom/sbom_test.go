package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
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
	app := testnodes.Ref("app", "1.0.0")
	react := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "react", Version: "18.2.0"}, Scopes: sdk.ScopesOf("runtime")})
	vitest := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "vitest", Version: "2.0.0"}, Scopes: sdk.ScopesOf("development")})
	for _, n := range []*sdk.DependencyNode{app, react, vitest} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add edge app->react: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), vitest.NodeID()); err != nil {
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
	app := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		Name:    "demo",
		Version: "1.0.0",
		Type:    "application",
		PURL:    "pkg:npm/demo@1.0.0"},
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
		t.Fatalf("expected demo package, got %v", graph.DependencyNodes())
	}
	if mustDep(t, pkg).Type != "application" {
		t.Fatalf("expected application type, got %q", mustDep(t, pkg).Type)
	}
}

func TestMarshalDepGraphJSON_SPDX23PreservesPURLAndCopyright(t *testing.T) {
	g := sdk.New()
	pkg := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "accept",
		Version:        "1.1.0",
		PURL:           "pkg:npm/accept@1.1.0"}, Copyright: "Copyright (c) 2014, Walmart and other contributors.",
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
		{target: TargetCycloneDX17JSON, version: cdx.SpecVersion1_7},
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
	app := testnodes.Ref("app", "1.0.0")
	runtimeDep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "react", Version: "18.2.0"}, Scopes: sdk.ScopesOf("runtime")})
	devDep := testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Name: "vitest", Version: "2.0.0"}, Scopes: sdk.ScopesOf("development")})
	for _, n := range []*sdk.DependencyNode{app, runtimeDep, devDep} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), runtimeDep.NodeID()); err != nil {
		t.Fatalf("add runtime edge: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), devDep.NodeID()); err != nil {
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

func TestMarshalDepGraphJSON_IsDeterministicWithFixedMetadata(t *testing.T) {
	g := mustGraph(t)
	options := BuildOptions{
		DocumentName: "test-doc",
		DocumentNS:   "https://example.com/spdx/test-doc",
		ToolName:     "bomly-cli-test",
		Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
		SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000001",
	}
	for _, target := range []Target{TargetSPDX23JSON, TargetCycloneDX16JSON} {
		first, err := MarshalDepGraphJSON(g, target, options, EncodeOptions{Pretty: true})
		if err != nil {
			t.Fatalf("%s first marshal: %v", target, err)
		}
		second, err := MarshalDepGraphJSON(g, target, options, EncodeOptions{Pretty: true})
		if err != nil {
			t.Fatalf("%s second marshal: %v", target, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("%s output changed across identical encodes", target)
		}

		doc, err := UnmarshalJSON(first, target)
		if err != nil {
			t.Fatalf("%s unmarshal: %v", target, err)
		}
		roundTripped, err := ToGraph(doc)
		if err != nil {
			t.Fatalf("%s graph conversion: %v", target, err)
		}
		if roundTripped.Size() != g.Size() {
			t.Fatalf("%s graph size = %d, want %d", target, roundTripped.Size(), g.Size())
		}
		if got, want := edgeCount(roundTripped), edgeCount(g); got != want {
			t.Fatalf("%s edge count = %d, want %d", target, got, want)
		}
	}
}

func TestUnmarshalJSON_SPDX23RestoresPackageIdentityFromPURL(t *testing.T) {
	g := sdk.New()
	if err := g.AddNode(testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "accept",
		Version:        "1.1.0",
		PURL:           "pkg:npm/accept@1.1.0"},
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
	if !testnodes.Is(pkg, "pkg:npm/accept@1.1.0") {
		t.Fatalf("expected graph package purl, got %q", pkg.NodeID())
	}
	if mustDep(t, pkg).Ecosystem != "npm" || mustDep(t, pkg).PackageManager != "npm" {
		t.Fatalf("expected graph package identity restored, got ecosystem=%q packageManager=%q", mustDep(t, pkg).Ecosystem, mustDep(t, pkg).PackageManager)
	}
}

func TestUnmarshalJSON_CycloneDXPreservesPURL(t *testing.T) {
	g := sdk.New()
	if err := g.AddNode(testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{Ecosystem: "npm",
		PackageManager: "npm",
		Name:           "accept",
		Version:        "1.1.0",
		PURL:           "pkg:npm/accept@1.1.0"},
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
	if _, err := DetectJSONTarget(syftData); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("DetectJSONTarget(syft) must report an unsupported format, got %v", err)
	}
}

func TestUnmarshalAutoJSON_RejectsUnsupportedOrMalformedJSON(t *testing.T) {
	if _, _, err := UnmarshalAutoJSON([]byte(`{"hello":"world"}`)); err == nil || !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("expected unsupported-format error, got %v", err)
	}
	if _, _, err := UnmarshalAutoJSON([]byte(`{"hello":`)); err == nil || !errors.Is(err, ErrMalformedJSON) {
		t.Fatalf("expected malformed-json error, got %v", err)
	}
	if _, _, err := UnmarshalAutoJSON(mustSyftJSONFixture(t)); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("expected unsupported-format error for syft JSON, got %v", err)
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

	aDeps, err := depsGraph.DirectDependencies(testnodes.ID(depsGraph, "a"))
	if err != nil {
		t.Fatalf("Dependencies(a): %v", err)
	}
	bDeps, err := depsGraph.DirectDependencies(testnodes.ID(depsGraph, "b"))
	if err != nil {
		t.Fatalf("Dependencies(b): %v", err)
	}
	if got := idsOfPackages(aDeps); len(got) != 1 || got[0] != testnodes.ID(depsGraph, "b") {
		t.Fatalf("expected a -> b, got %#v", got)
	}
	if got := idsOfPackages(bDeps); len(got) != 1 || got[0] != testnodes.ID(depsGraph, "a") {
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
	app := testnodes.Ref("app", "1.0.0")
	react := testnodes.Ref("react", "18.2.0")
	zod := testnodes.Ref("zod", "3.23.0")

	for _, n := range []*sdk.DependencyNode{app, react, zod} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.NodeID(), err)
		}
	}
	if err := g.AddEdge(app.NodeID(), react.NodeID()); err != nil {
		t.Fatalf("add edge app->react: %v", err)
	}
	if err := g.AddEdge(app.NodeID(), zod.NodeID()); err != nil {
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

func edgeCount(graph *sdk.Graph) int {
	count := 0
	graph.WalkEdges(func(_, _ sdk.GraphNode) bool {
		count++
		return true
	})
	return count
}

func idsOfPackages(packages []sdk.GraphNode) []string {
	ids := make([]string, 0, len(packages))
	for _, pkg := range packages {
		ids = append(ids, pkg.NodeID())
	}
	return ids
}

func mustSyftJSONFixture(t *testing.T) []byte {
	t.Helper()
	// A representative syft-format JSON document. Bomly treats the format as
	// unsupported, so a static fixture is all these tests need.
	return []byte(`{
  "artifacts": [
    {"id": "a1", "name": "demo-app", "version": "1.0.0", "type": "npm", "purl": "pkg:npm/demo-app@1.0.0"},
    {"id": "a2", "name": "react", "version": "18.2.0", "type": "npm", "purl": "pkg:npm/react@18.2.0"}
  ],
  "artifactRelationships": [{"parent": "a2", "child": "a1", "type": "dependency-of"}],
  "source": {"type": "directory", "target": "."},
  "descriptor": {"name": "syft", "version": "1.0.0"},
  "schema": {"version": "16.0.34", "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.34.json"}
}`)
}

// A PURL Bomly emitted must name an ecosystem Bomly recognises when it is read
// back in. ParseEcosystem only knows Bomly's own identifiers, so every purl
// type whose spec name differs from the ecosystem name (pkg:deb for dpkg,
// pkg:cran for r, ...) needs an entry in purlTypeEcosystems. See issue #317.
func TestEcosystemFromPURLTypeRoundTripsEmittedPURLs(t *testing.T) {
	// pkg:hex is emitted for both Elixir (mix) and Erlang (rebar) and nothing
	// in the PURL says which, so it is deliberately left unresolved rather
	// than guessed. Everything else must round-trip.
	ambiguous := map[string]bool{"hex": true}

	for _, manager := range sdk.AllPackageManagers() {
		ecosystem := manager.Ecosystem()
		if ecosystem == sdk.EcosystemUnknown {
			continue
		}
		purlType := sdk.PackageURLTypeForValues(ecosystem, manager)
		if ambiguous[purlType] {
			continue
		}
		got := ecosystemFromPURLType(purlType)
		if got == sdk.EcosystemUnknown {
			t.Errorf("ecosystemFromPURLType(%q) = unknown; %q packages would lose their ecosystem on SBOM ingest", purlType, ecosystem)
		}
	}
}

// The standard codecs do not carry Component.Ecosystem — CycloneDX drops it and
// SPDX rebuilds it from the PURL — so a change to the emitted purl type can
// silently relabel a package on the way back in. OTP applications must survive
// as Erlang, and a Hex dependency must not come back as the wrong ecosystem.
func TestEncodeDecodeRoundTripPreservesErlangIdentity(t *testing.T) {
	targets := []Target{TargetSPDX23JSON, TargetCycloneDX16JSON}

	cases := []struct {
		name          string
		manager       sdk.PackageManager
		depName       string
		version       string
		wantPURL      string
		wantEcosystem sdk.Ecosystem
	}{{
		name:          "otp application",
		manager:       sdk.PackageManagerOTP,
		depName:       "kernel",
		version:       "9.2",
		wantPURL:      "pkg:otp/kernel@9.2",
		wantEcosystem: sdk.EcosystemErlang,
	}, {
		// pkg:hex cannot say whether it came from rebar or mix, so the only
		// correct answer on the way back in is "unknown" — never a confident
		// mislabel as Elixir.
		name:          "rebar dependency",
		manager:       sdk.PackageManagerRebar,
		depName:       "cowboy",
		version:       "2.10.0",
		wantPURL:      "pkg:hex/cowboy@2.10.0",
		wantEcosystem: sdk.EcosystemUnknown,
	}}

	for _, tc := range cases {
		for _, target := range targets {
			t.Run(tc.name+"/"+string(target), func(t *testing.T) {
				// The identity is minted from the coordinates at
				// construction, so the ecosystem and manager have to be
				// stated up front rather than patched on afterwards.
				dep := testnodes.Dep(sdk.Coordinates{
					Name:           tc.depName,
					Version:        tc.version,
					Ecosystem:      sdk.EcosystemErlang,
					PackageManager: tc.manager,
				})
				if !testnodes.Is(dep, tc.wantPURL) {
					t.Fatalf("emitted PURL = %q, want %q", dep.NodeID(), tc.wantPURL)
				}

				g := sdk.New()
				if err := g.AddNode(dep); err != nil {
					t.Fatalf("add node: %v", err)
				}

				out, err := MarshalDepGraphJSON(g, target, BuildOptions{
					DocumentName: "erlang-round-trip",
					DocumentNS:   "https://example.com/sbom/erlang-round-trip",
					ToolName:     "bomly-cli-test",
					Created:      time.Date(2026, 2, 28, 12, 0, 0, 0, time.UTC),
				}, EncodeOptions{})
				if err != nil {
					t.Fatalf("marshal %s: %v", target, err)
				}

				doc, err := UnmarshalJSON(out, target)
				if err != nil {
					t.Fatalf("unmarshal %s: %v", target, err)
				}
				decoded, err := ToGraph(doc)
				if err != nil {
					t.Fatalf("to graph: %v", err)
				}

				node, ok := testnodes.FindDep(decoded, tc.wantPURL)
				if !ok {
					t.Fatalf("decoded graph has no node %q", tc.wantPURL)
				}
				if node.Ecosystem != tc.wantEcosystem {
					t.Errorf("ecosystem = %q, want %q", node.Ecosystem, tc.wantEcosystem)
				}
				if tc.wantEcosystem == sdk.EcosystemUnknown && node.PackageManager == sdk.PackageManagerMix {
					t.Errorf("ambiguous pkg:hex must not be labelled %q", sdk.PackageManagerMix)
				}
			})
		}
	}
}

// SBOM component names are the ecosystem-native ones. This matters beyond
// document correctness: external grype mode feeds this SPDX document to the
// grype CLI, which searches its DB by the name it reads. See issue #319.
func TestFromDepGraph_ComponentNamesAreEcosystemNative(t *testing.T) {
	g := sdk.New()
	nodes := []*sdk.DependencyNode{
		testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
			Ecosystem: sdk.EcosystemNPM, Org: "tailwindcss", Name: "postcss", Version: "4.3.3",
		}}),
		testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
			Ecosystem: sdk.EcosystemNPM, Name: "postcss", Version: "8.5.16",
		}}),
		testnodes.DepFrom(sdk.DependencyNode{Coordinates: sdk.Coordinates{
			Ecosystem: sdk.EcosystemMaven, Org: "com.example", Name: "demo", Version: "1.2.3",
		}}),
	}
	for _, n := range nodes {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add node %s: %v", n.NodeID(), err)
		}
	}

	doc, err := FromDepGraph(g, BuildOptions{})
	if err != nil {
		t.Fatalf("FromDepGraph: %v", err)
	}

	got := make(map[string]bool, len(doc.Components))
	for _, c := range doc.Components {
		got[c.Name] = true
	}
	for _, want := range []string{"@tailwindcss/postcss", "postcss", "com.example:demo"} {
		if !got[want] {
			t.Errorf("missing component name %q; got %v", want, got)
		}
	}
	if got["tailwindcss:postcss"] {
		t.Error("scoped npm component emitted with a colon-joined name")
	}
}

// mustDep narrows a graph node to the dependency node a case is asserting
// about, failing rather than panicking when the graph holds something else.
func mustDep(t testing.TB, node sdk.GraphNode) *sdk.DependencyNode {
	t.Helper()
	dep, ok := node.(*sdk.DependencyNode)
	if !ok {
		t.Fatalf("expected a dependency node, got %T", node)
	}
	return dep
}
