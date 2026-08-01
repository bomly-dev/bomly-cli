package sbom

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/bomly-dev/bomly-sdk"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// mustMultiRootGraph builds a graph with two disconnected roots, mirroring a
// scan that discovered manifests from more than one ecosystem.
func mustMultiRootGraph(t *testing.T) *sdk.Graph {
	t.Helper()

	g := sdk.New()
	workflow := sdk.NewDependencyRef("ci.yml", "local")
	action := sdk.NewDependencyRef("actions/checkout", "4.0.0")
	app := sdk.NewDependencyRef("app", "1.0.0")
	react := sdk.NewDependencyRef("react", "18.2.0")

	for _, n := range []*sdk.Dependency{workflow, action, app, react} {
		if err := g.AddNode(n); err != nil {
			t.Fatalf("add package %s: %v", n.ID, err)
		}
	}
	if err := g.AddEdge(workflow.ID, action.ID); err != nil {
		t.Fatalf("add edge workflow->action: %v", err)
	}
	if err := g.AddEdge(app.ID, react.ID); err != nil {
		t.Fatalf("add edge app->react: %v", err)
	}
	return g
}

func TestFromDepGraph_SynthesizesProjectRootForMultiRootGraphs(t *testing.T) {
	doc, err := FromDepGraph(mustMultiRootGraph(t), BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project", Version: "v1.2.3"},
	})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}

	if len(doc.Roots) != 1 {
		t.Fatalf("expected a single synthesized root, got %v", doc.Roots)
	}
	rootID := doc.Roots[0]
	if !strings.HasPrefix(rootID, projectRootIDPrefix) {
		t.Fatalf("expected pseudo root prefix on %q", rootID)
	}

	var root *Component
	for i := range doc.Components {
		if doc.Components[i].ID == rootID {
			root = &doc.Components[i]
		}
	}
	if root == nil {
		t.Fatalf("synthesized root %q missing from components", rootID)
	}
	if root.Name != "demo-project" || root.Version != "v1.2.3" || root.Type != "application" {
		t.Fatalf("unexpected root identity: %+v", root)
	}
	if root.PURL != "pkg:generic/demo-project@v1.2.3" {
		t.Fatalf("unexpected root purl: %q", root.PURL)
	}
	if !IsProjectRootComponent(*root) {
		t.Fatalf("expected IsProjectRootComponent to detect %q", rootID)
	}

	var rootDeps []string
	for _, dep := range doc.Dependencies {
		if dep.Ref == rootID {
			rootDeps = dep.DependsOn
		}
	}
	if len(rootDeps) != 2 {
		t.Fatalf("expected the pseudo root to depend on both graph roots, got %v", rootDeps)
	}
}

func TestFromDepGraph_KeepsSingleRootWithoutSynthesis(t *testing.T) {
	doc, err := FromDepGraph(mustGraph(t), BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project"},
	})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if len(doc.Roots) != 1 || strings.HasPrefix(doc.Roots[0], projectRootIDPrefix) {
		t.Fatalf("expected the natural single root, got %v", doc.Roots)
	}
	for _, c := range doc.Components {
		if IsProjectRootComponent(c) {
			t.Fatalf("unexpected synthesized root %q", c.ID)
		}
	}
}

var uuidURNPattern = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestFromDepGraph_GeneratesSerialNumberAndAlignedNamespace(t *testing.T) {
	doc, err := FromDepGraph(mustGraph(t), BuildOptions{})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if !uuidURNPattern.MatchString(doc.SerialNumber) {
		t.Fatalf("expected an urn:uuid serial number, got %q", doc.SerialNumber)
	}
	nonce := strings.TrimPrefix(doc.SerialNumber, "urn:uuid:")
	if doc.Namespace != "https://bomly.dev/spdx/"+nonce {
		t.Fatalf("expected namespace to reuse the serial nonce, got %q vs serial %q", doc.Namespace, doc.SerialNumber)
	}

	explicit, err := FromDepGraph(mustGraph(t), BuildOptions{SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000"})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if explicit.SerialNumber != "urn:uuid:00000000-0000-4000-8000-000000000000" {
		t.Fatalf("explicit serial number was not preserved: %q", explicit.SerialNumber)
	}
}

func TestFromDepGraph_ProjectsDetectionTimeDigests(t *testing.T) {
	g := sdk.New()
	dep := sdk.NewDependency(sdk.Dependency{
		Coordinates: sdk.Coordinates{Name: "left-pad", Version: "1.3.0", Ecosystem: sdk.EcosystemNPM},
		// npm SRI integrity values are base64; expect hex in the SBOM model.
		Digests: []sdk.Digest{
			{Algorithm: "sha512", Value: "pkJf8Ni4YWlKDgODlNGxi/z1Wd0/hkJH8N4Rq+Cd1lTv7ZZKPXm8mTzcp2xEVSlHoQlUwjzUKh2nGSHTMEUUpg=="},
			{Algorithm: "nuget-content-hash", Value: "abc123"},
		},
	})
	if err := g.AddNode(dep); err != nil {
		t.Fatalf("add node: %v", err)
	}

	doc, err := FromDepGraph(g, BuildOptions{})
	if err != nil {
		t.Fatalf("from depgraph: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("expected one component, got %d", len(doc.Components))
	}
	digests := doc.Components[0].Digests
	if len(digests) != 2 {
		t.Fatalf("expected both digests projected, got %+v", digests)
	}
	if digests[0].Algorithm != "sha512" || len(digests[0].Value) != 128 {
		t.Fatalf("expected the sha512 digest re-encoded as 128 hex chars, got %+v", digests[0])
	}
	if strings.ToLower(digests[0].Value) != digests[0].Value {
		t.Fatalf("expected lowercase hex, got %q", digests[0].Value)
	}
	if digests[1].Algorithm != "nuget-content-hash" || digests[1].Value != "abc123" {
		t.Fatalf("expected unknown-algorithm digest kept verbatim, got %+v", digests[1])
	}
}

func TestMarshalDepGraphJSON_CycloneDXDocumentIdentityAndProvenance(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustMultiRootGraph(t), TargetCycloneDX17JSON, BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project", Version: "v1.2.3"},
		ToolVersion:  "9.9.9",
		ToolNames:    []string{"bomly-detector:demo"},
		Provenance: Provenance{
			Manufacturer:               "Example Org",
			SecurityContact:            "security@example.com",
			VulnerabilityDisclosureURL: "https://example.com/security",
			SupportEnd:                 "2030-12-31",
		},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	var bom cdx.BOM
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}

	if !uuidURNPattern.MatchString(bom.SerialNumber) {
		t.Fatalf("expected generated serial number, got %q", bom.SerialNumber)
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		t.Fatalf("expected metadata.component")
	}
	root := bom.Metadata.Component
	if root.Name != "demo-project" || root.Version != "v1.2.3" || root.PackageURL != "pkg:generic/demo-project@v1.2.3" {
		t.Fatalf("unexpected primary component: %+v", root)
	}
	if root.ExternalReferences == nil || len(*root.ExternalReferences) != 2 {
		t.Fatalf("expected security external references, got %+v", root.ExternalReferences)
	}
	refs := *root.ExternalReferences
	if refs[0].Type != cdx.ERTypeSecurityContact || refs[0].URL != "mailto:security@example.com" {
		t.Fatalf("unexpected security contact reference: %+v", refs[0])
	}
	if refs[1].Type != cdx.ERTypeAdvisories || refs[1].URL != "https://example.com/security" {
		t.Fatalf("unexpected disclosure reference: %+v", refs[1])
	}
	if bom.Metadata.Manufacturer == nil || bom.Metadata.Manufacturer.Name != "Example Org" {
		t.Fatalf("expected metadata.manufacturer, got %+v", bom.Metadata.Manufacturer)
	}
	if bom.Metadata.Properties == nil || len(*bom.Metadata.Properties) != 1 || (*bom.Metadata.Properties)[0].Name != "bomly:support_end_date" || (*bom.Metadata.Properties)[0].Value != "2030-12-31" {
		t.Fatalf("expected support end property, got %+v", bom.Metadata.Properties)
	}

	if bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatalf("expected tools components")
	}
	toolVersions := map[string]string{}
	for _, tool := range *bom.Metadata.Tools.Components {
		toolVersions[tool.Name] = tool.Version
	}
	if toolVersions["bomly-cli"] != "9.9.9" {
		t.Fatalf("expected primary tool version, got %+v", toolVersions)
	}
	if toolVersions["bomly-detector:demo"] != "" {
		t.Fatalf("expected detector tools to stay unversioned, got %+v", toolVersions)
	}

	// The pseudo root must not be double-counted in the component inventory,
	// but its dependency entry must link the document root to the graph roots.
	if bom.Components == nil {
		t.Fatalf("expected components")
	}
	for _, comp := range *bom.Components {
		if comp.BOMRef == root.BOMRef {
			t.Fatalf("pseudo root %q duplicated in components", root.BOMRef)
		}
	}
	if bom.Dependencies == nil {
		t.Fatalf("expected dependencies")
	}
	foundRootEntry := false
	for _, dep := range *bom.Dependencies {
		if dep.Ref == root.BOMRef {
			foundRootEntry = true
			if dep.Dependencies == nil || len(*dep.Dependencies) != 2 {
				t.Fatalf("expected pseudo root dependency entry to list both graph roots, got %+v", dep.Dependencies)
			}
		}
	}
	if !foundRootEntry {
		t.Fatalf("missing dependency entry for pseudo root %q", root.BOMRef)
	}
}

func TestUnmarshalJSON_CycloneDXPseudoRootRoundTrip(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustMultiRootGraph(t), TargetCycloneDX17JSON, BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project"},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal cyclonedx: %v", err)
	}

	doc, err := UnmarshalJSON(out, TargetCycloneDX17JSON)
	if err != nil {
		t.Fatalf("unmarshal cyclonedx: %v", err)
	}
	if len(doc.Components) != 4 {
		t.Fatalf("expected the four real components, got %d", len(doc.Components))
	}
	if len(doc.Roots) != 2 {
		t.Fatalf("expected both real graph roots after decode, got %v", doc.Roots)
	}

	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	if g.Size() != 4 {
		t.Fatalf("expected 4 graph nodes, got %d", g.Size())
	}
}

func TestToGraph_SkipsSynthesizedProjectRootWithPURL(t *testing.T) {
	doc := &Document{
		Components: []Component{
			{ID: projectRootIDPrefix + "demo", Name: "demo", Type: "application", PURL: "pkg:generic/demo"},
			{ID: "pkg:npm/react@18.2.0", Name: "react", Version: "18.2.0", PURL: "pkg:npm/react@18.2.0"},
		},
		Dependencies: []Dependency{
			{Ref: projectRootIDPrefix + "demo", DependsOn: []string{"pkg:npm/react@18.2.0"}},
			{Ref: "pkg:npm/react@18.2.0"},
		},
	}
	g, err := ToGraph(doc)
	if err != nil {
		t.Fatalf("to graph: %v", err)
	}
	if g.Size() != 1 {
		t.Fatalf("expected pseudo root to be skipped, got %d nodes", g.Size())
	}
}

func TestMarshalDepGraphJSON_SPDX23ProvenanceAndToolVersion(t *testing.T) {
	out, err := MarshalDepGraphJSON(mustMultiRootGraph(t), TargetSPDX23JSON, BuildOptions{
		DocumentName: "demo-project",
		ProjectRoot:  &ProjectRoot{Name: "demo-project", Version: "v1.2.3"},
		ToolVersion:  "9.9.9",
		Provenance: Provenance{
			Manufacturer:               "Example Org",
			SecurityContact:            "security@example.com",
			VulnerabilityDisclosureURL: "https://example.com/security",
			SupportEnd:                 "2030-12-31",
		},
	}, EncodeOptions{})
	if err != nil {
		t.Fatalf("marshal spdx: %v", err)
	}

	var d v23.Document
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatalf("unmarshal spdx: %v", err)
	}
	if d.DocumentName != "demo-project" {
		t.Fatalf("unexpected document name %q", d.DocumentName)
	}

	toolCreator, orgCreator := "", ""
	for _, c := range d.CreationInfo.Creators {
		switch c.CreatorType {
		case "Tool":
			if toolCreator == "" {
				toolCreator = c.Creator
			}
		case "Organization":
			orgCreator = c.Creator
		}
	}
	if toolCreator != "bomly-cli-9.9.9" {
		t.Fatalf("expected SPDX tool creator with version, got %q", toolCreator)
	}
	if orgCreator != "Example Org" {
		t.Fatalf("expected organization creator, got %q", orgCreator)
	}
	if !strings.Contains(d.CreationInfo.CreatorComment, "SecurityContact: security@example.com") ||
		!strings.Contains(d.CreationInfo.CreatorComment, "VulnerabilityDisclosure: https://example.com/security") ||
		!strings.Contains(d.CreationInfo.CreatorComment, "SupportEnd: 2030-12-31") {
		t.Fatalf("unexpected creator comment %q", d.CreationInfo.CreatorComment)
	}

	var root *v23.Package
	for _, p := range d.Packages {
		if strings.HasPrefix(string(p.PackageSPDXIdentifier), projectRootIDPrefix) {
			root = p
		}
	}
	if root == nil {
		t.Fatalf("expected synthesized root package in SPDX document")
	}
	if root.PrimaryPackagePurpose != "APPLICATION" {
		t.Fatalf("expected APPLICATION purpose on root, got %q", root.PrimaryPackagePurpose)
	}
	if root.PackageSupplier == nil || root.PackageSupplier.Supplier != "Example Org" {
		t.Fatalf("expected supplier on root, got %+v", root.PackageSupplier)
	}

	describesRoot := false
	for _, rel := range d.Relationships {
		if rel != nil && rel.Relationship == "DESCRIBES" && rel.RefB.ElementRefID == root.PackageSPDXIdentifier {
			describesRoot = true
		}
	}
	if !describesRoot {
		t.Fatalf("expected the document to describe the synthesized root")
	}
}
