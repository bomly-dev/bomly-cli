package sdk

import (
	"encoding/json"
	"testing"
)

func TestGraphJSONRoundTrip(t *testing.T) {
	graph := New()
	app := NewDependencyRefWithID("app@1.0.0", "app", "1.0.0")
	dep := NewDependencyRefWithID("dep@2.0.0", "dep", "2.0.0")
	if err := graph.AddNode(app); err != nil {
		t.Fatalf("AddNode(app): %v", err)
	}
	if err := graph.AddNode(dep); err != nil {
		t.Fatalf("AddNode(dep): %v", err)
	}
	if err := graph.AddEdge(app.ID, dep.ID); err != nil {
		t.Fatalf("AddEdge(): %v", err)
	}

	data, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}

	var decoded Graph
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	if decoded.Size() != 2 {
		t.Fatalf("decoded graph size = %d, want 2", decoded.Size())
	}
	deps, err := decoded.DirectDependencies(app.ID)
	if err != nil {
		t.Fatalf("DirectDependencies(): %v", err)
	}
	if len(deps) != 1 || deps[0].ID != dep.ID {
		t.Fatalf("decoded dependencies = %#v, want %q", deps, dep.ID)
	}
}

func TestPackageRegistryJSONRoundTrip(t *testing.T) {
	registry := NewPackageRegistry()
	pkg := registry.Ensure("pkg:npm/react@18.2.0")
	pkg.Name = "react"
	pkg.Version = "18.2.0"
	pkg.Licenses = []PackageLicense{{SPDXExpression: "MIT"}}
	pkg.Vulnerabilities = []Vulnerability{{ID: "GHSA-1", Source: "osv", ParsedSeverity: SeverityHigh}}

	data, err := json.Marshal(registry)
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}

	var decoded PackageRegistry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal(): %v", err)
	}
	decodedPkg, ok := decoded.Get("pkg:npm/react@18.2.0")
	if !ok {
		t.Fatalf("decoded registry missing package: %s", data)
	}
	if decodedPkg.Name != "react" || decodedPkg.Version != "18.2.0" {
		t.Fatalf("decoded package identity = %#v", decodedPkg)
	}
	if len(decodedPkg.Licenses) != 1 || decodedPkg.Licenses[0].SPDXExpression != "MIT" {
		t.Fatalf("decoded licenses = %#v", decodedPkg.Licenses)
	}
	if len(decodedPkg.Vulnerabilities) != 1 || decodedPkg.Vulnerabilities[0].ID != "GHSA-1" {
		t.Fatalf("decoded vulnerabilities = %#v", decodedPkg.Vulnerabilities)
	}
}

func TestPluginRequestResponseRegistryJSON(t *testing.T) {
	registry := NewPackageRegistry()
	registry.Ensure("pkg:npm/lodash@4.17.15").Vulnerabilities = []Vulnerability{{ID: "GHSA-lodash", Source: "osv"}}

	matchData, err := json.Marshal(MatchRequest{Registry: registry})
	if err != nil {
		t.Fatalf("marshal match request: %v", err)
	}
	var matchReq MatchRequest
	if err := json.Unmarshal(matchData, &matchReq); err != nil {
		t.Fatalf("unmarshal match request: %v", err)
	}
	if matchReq.Registry == nil {
		t.Fatal("match request registry was not decoded")
	}
	if pkg, ok := matchReq.Registry.Get("pkg:npm/lodash@4.17.15"); !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("match request registry package = %#v, ok=%v", pkg, ok)
	}

	resultData, err := json.Marshal(MatchResult{Registry: registry, MatcherStats: MatcherStats{Name: "test-matcher"}})
	if err != nil {
		t.Fatalf("marshal match result: %v", err)
	}
	var matchResult MatchResult
	if err := json.Unmarshal(resultData, &matchResult); err != nil {
		t.Fatalf("unmarshal match result: %v", err)
	}
	if matchResult.Registry == nil {
		t.Fatal("match result registry was not decoded")
	}
	if pkg, ok := matchResult.Registry.Get("pkg:npm/lodash@4.17.15"); !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("match result registry package = %#v, ok=%v", pkg, ok)
	}

	auditData, err := json.Marshal(AuditRequest{Registry: registry})
	if err != nil {
		t.Fatalf("marshal audit request: %v", err)
	}
	var auditReq AuditRequest
	if err := json.Unmarshal(auditData, &auditReq); err != nil {
		t.Fatalf("unmarshal audit request: %v", err)
	}
	if auditReq.Registry == nil {
		t.Fatal("audit request registry was not decoded")
	}
	if pkg, ok := auditReq.Registry.Get("pkg:npm/lodash@4.17.15"); !ok || len(pkg.Vulnerabilities) != 1 {
		t.Fatalf("audit request registry package = %#v, ok=%v", pkg, ok)
	}
}
