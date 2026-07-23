package baseline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestResolverIsPortableAndVersionSpecific(t *testing.T) {
	registry := sdk.NewPackageRegistry()
	purl := "pkg:npm/lodash@4.17.20"
	pkg := registry.Ensure(purl)
	pkg.Vulnerabilities = []sdk.Vulnerability{{ID: "GHSA-1", Aliases: []string{"CVE-2024-1"}, ParsedSeverity: sdk.SeverityHigh}}
	finding := sdk.Finding{ID: "GHSA-1", VulnerabilityID: "GHSA-1", Kind: sdk.FindingKindVulnerability, Auditor: "vulnerability", RuleID: "advisory", PackageRef: purl, Severity: sdk.SeverityHigh, Disposition: sdk.FindingDispositionFail}

	resolver, err := NewResolver(NewDocument([]sdk.Finding{finding}, registry))
	if err != nil {
		t.Fatal(err)
	}
	aliasFinding := finding
	aliasFinding.ID = "CVE-2024-1"
	aliasFinding.VulnerabilityID = "CVE-2024-1"
	decision, ok := resolver.ResolveFinding(context.Background(), aliasFinding, registry)
	if !ok || decision.Disposition != sdk.FindingDispositionSuppressed {
		t.Fatalf("portable alias finding was not suppressed: %#v, %v", decision, ok)
	}

	otherVersion := aliasFinding
	otherVersion.PackageRef = "pkg:npm/lodash@4.17.21"
	if _, ok := resolver.ResolveFinding(context.Background(), otherVersion, registry); ok {
		t.Fatal("baseline must not cross package versions")
	}
}

func TestResolverDoesNotSuppressChangedPolicyState(t *testing.T) {
	finding := sdk.Finding{ID: "denied", Kind: sdk.FindingKindPackage, Auditor: "package", RuleID: "denied-package", PackageRef: "pkg:npm/example@1.0.0", Severity: sdk.SeverityWarning, Disposition: sdk.FindingDispositionWarn}
	resolver, err := NewResolver(NewDocument([]sdk.Finding{finding}, nil))
	if err != nil {
		t.Fatal(err)
	}
	escalated := finding
	escalated.Severity = sdk.SeverityError
	escalated.Disposition = sdk.FindingDispositionFail
	if _, ok := resolver.ResolveFinding(context.Background(), escalated, nil); ok {
		t.Fatal("changed severity/disposition must require explicit baseline update")
	}
}

func TestWriteAtomicLoadAndRejectSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".bomly", "baseline.json")
	document := NewDocument([]sdk.Finding{{ID: "rule", Kind: sdk.FindingKindPackage, Auditor: "package", RuleID: "rule", PackageRef: "pkg:npm/example@1.0.0"}}, nil)
	if err := WriteAtomic(path, document, false); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || len(loaded.Entries) != 1 {
		t.Fatalf("loaded baseline = %#v, %v", loaded, err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(link, document, true); err == nil {
		t.Fatal("expected symbolic-link destination to be rejected")
	}
}

func TestUpdateAndPrune(t *testing.T) {
	old := sdk.Finding{ID: "old", Kind: sdk.FindingKindPackage, Auditor: "package", RuleID: "old", PackageRef: "pkg:npm/old@1.0.0"}
	current := sdk.Finding{ID: "current", Kind: sdk.FindingKindPackage, Auditor: "package", RuleID: "current", PackageRef: "pkg:npm/current@1.0.0"}
	existing := NewDocument([]sdk.Finding{old}, nil)
	updated := Update(existing, []sdk.Finding{current}, nil)
	if len(updated.Entries) != 2 {
		t.Fatalf("update entries = %d, want 2", len(updated.Entries))
	}
	pruned := Prune(updated, []sdk.Finding{current}, nil)
	if len(pruned.Entries) != 1 || pruned.Entries[0].RuleID != "current" {
		t.Fatalf("pruned baseline = %#v", pruned)
	}
}
