package baseline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"
	sdk "github.com/bomly-dev/bomly-sdk"
)

// A baseline written before ADR-0041 must keep suppressing the same findings
// after it.
//
// This is the compatibility question the identity change raises: node IDs
// changed from detector-minted strings to canonical package URLs, and a
// baseline that had keyed on them would have silently stopped matching --
// every suppressed finding reappearing at once, on an upgrade, with no error
// to explain it.
//
// It does not, because an entry keys on the finding's PackageRef, which was
// already a package URL and is unaffected. This pins that: a document written
// from the old graph shape resolves findings produced by the new one.
func TestBaselineWrittenBeforeTheIdentityChangeStillSuppresses(t *testing.T) {
	const purl = "pkg:npm/left-pad@1.3.0"

	// Verbatim from a pre-ADR-0041 baseline: the entry names the package, not
	// the node the finding was attached to.
	raw := []byte(`{
      "schema_version": "bomly.finding-baseline/v1",
      "entries": [{
        "package_ref": "pkg:npm/left-pad@1.3.0",
        "kind": "vulnerability",
        "auditor": "vulnerability",
        "rule_id": "advisory",
        "advisory_ids": ["GHSA-example"],
        "policy_status": "suppressed"
      }]
    }`)
	var document Document
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode baseline: %v", err)
	}
	resolver, err := NewResolver(document)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	// The finding a current scan produces: its DependencyRefs are canonical
	// package URLs now, and its PackageRef is what it always was.
	finding := sdk.Finding{
		Kind:            sdk.FindingKindVulnerability,
		Auditor:         "vulnerability",
		RuleID:          "advisory",
		PackageRef:      purl,
		VulnerabilityID: "GHSA-example",
		DependencyRefs:  []string{purl},
		Severity:        sdk.SeverityHigh,
		PolicyStatus:    sdk.FindingPolicyStatusFail,
	}

	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Name, pkg.Version = "left-pad", "1.3.0"
	pkg.Vulnerabilities = []sdk.Vulnerability{{ID: "GHSA-example"}}

	decision, ok := resolver.ResolveFindingPolicy(context.Background(), finding, registry)
	if !ok {
		t.Fatal("the baseline stopped matching a finding it was written to suppress")
	}
	if decision.Status != sdk.FindingPolicyStatusSuppressed {
		t.Fatalf("policy status = %q, want the baseline's suppression", decision.Status)
	}
}

// The same baseline matches whatever the graph looks like around the package.
//
// A package reached from a module node and the same package reached from a
// bare root produce findings with different DependencyRefs but one PackageRef,
// so one entry covers both -- which is why the baseline survived a change that
// rewrote every node ID.
func TestBaselineMatchesRegardlessOfGraphShape(t *testing.T) {
	const purl = "pkg:npm/left-pad@1.3.0"

	document := Document{SchemaVersion: SchemaVersion, Entries: []Entry{{
		PackageRef:   purl,
		Kind:         sdk.FindingKindVulnerability,
		Auditor:      "vulnerability",
		RuleID:       "advisory",
		AdvisoryIDs:  []string{"GHSA-example"},
		PolicyStatus: sdk.FindingPolicyStatusSuppressed,
	}}}
	resolver, err := NewResolver(document)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(purl)
	pkg.Name, pkg.Version = "left-pad", "1.3.0"
	pkg.Vulnerabilities = []sdk.Vulnerability{{ID: "GHSA-example"}}

	underModule := sdk.New()
	module := testnodes.Module("package.json", "app", "1.0.0")
	consumed := testnodes.Dep(sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	for _, node := range []sdk.GraphNode{module, consumed} {
		if err := underModule.AddNode(node); err != nil {
			t.Fatal(err)
		}
	}
	if err := underModule.AddEdge(module.NodeID(), consumed.NodeID()); err != nil {
		t.Fatal(err)
	}

	standalone := sdk.New()
	orphan := testnodes.Dep(sdk.Coordinates{Ecosystem: sdk.EcosystemNPM, Name: "left-pad", Version: "1.3.0"})
	if err := standalone.AddNode(orphan); err != nil {
		t.Fatal(err)
	}

	for name, refs := range map[string][]string{
		"under a module": {consumed.NodeID()},
		"standalone":     {orphan.NodeID()},
	} {
		t.Run(name, func(t *testing.T) {
			finding := sdk.Finding{
				Kind:            sdk.FindingKindVulnerability,
				Auditor:         "vulnerability",
				RuleID:          "advisory",
				PackageRef:      purl,
				VulnerabilityID: "GHSA-example",
				DependencyRefs:  refs,
			}
			if _, ok := resolver.ResolveFindingPolicy(context.Background(), finding, registry); !ok {
				t.Fatalf("baseline did not match a finding with dependency refs %v", refs)
			}
		})
	}
}
