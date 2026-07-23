package baseline

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestResolverIsPortableAndVersionSpecific(t *testing.T) {
	registry := sdk.NewPackageRegistry()
	purl := "pkg:npm/lodash@4.17.20"
	pkg := registry.Ensure(purl)
	pkg.Vulnerabilities = []sdk.Vulnerability{{ID: "GHSA-1", Aliases: []string{"CVE-2024-1"}, ParsedSeverity: sdk.SeverityHigh}}
	finding := sdk.Finding{ID: "GHSA-1", VulnerabilityID: "GHSA-1", Kind: sdk.FindingKindVulnerability, Auditor: "vulnerability", RuleID: "advisory", PackageRef: purl, Severity: sdk.SeverityHigh, PolicyStatus: sdk.FindingPolicyStatusFail}

	resolver, err := NewResolver(NewDocument([]sdk.Finding{finding}, registry))
	if err != nil {
		t.Fatal(err)
	}
	aliasFinding := finding
	aliasFinding.ID = "CVE-2024-1"
	aliasFinding.VulnerabilityID = "CVE-2024-1"
	decision, ok := resolver.ResolveFindingPolicy(context.Background(), aliasFinding, registry)
	if !ok || decision.Status != sdk.FindingPolicyStatusSuppressed {
		t.Fatalf("portable alias finding was not suppressed: %#v, %v", decision, ok)
	}

	otherVersion := aliasFinding
	otherVersion.PackageRef = "pkg:npm/lodash@4.17.21"
	if _, ok := resolver.ResolveFindingPolicy(context.Background(), otherVersion, registry); ok {
		t.Fatal("baseline must not cross package versions")
	}
}

func TestNewDocumentConsolidatesAliasEquivalentVulnerabilityFindings(t *testing.T) {
	const purl = "pkg:golang/golang.org/x/text@v0.3.5"
	registry := sdk.NewPackageRegistry()
	registry.Ensure(purl).Vulnerabilities = []sdk.Vulnerability{
		{ID: "GHSA-ppp9-7jff-5vj2", Aliases: []string{"CVE-2021-38561"}, ParsedSeverity: sdk.SeverityHigh},
		{ID: "GO-2021-0113", Aliases: []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2"}, ParsedSeverity: sdk.SeverityHigh},
	}
	findings := []sdk.Finding{
		{
			ID: "GHSA-ppp9-7jff-5vj2", VulnerabilityID: "GHSA-ppp9-7jff-5vj2",
			Kind: sdk.FindingKindVulnerability, Auditor: "vulnerability", RuleID: "advisory",
			PackageRef: purl, Severity: sdk.SeverityHigh, PolicyStatus: sdk.FindingPolicyStatusFail,
		},
		{
			ID: "GO-2021-0113", VulnerabilityID: "GO-2021-0113",
			Kind: sdk.FindingKindVulnerability, Auditor: "vulnerability", RuleID: "advisory",
			PackageRef: purl, Severity: sdk.SeverityHigh, PolicyStatus: sdk.FindingPolicyStatusFail,
		},
	}

	document := NewDocument(findings, registry)
	if err := document.Validate(); err != nil {
		t.Fatalf("generated document must validate: %v", err)
	}
	if len(document.Entries) != 1 {
		t.Fatalf("baseline entries = %d, want 1: %#v", len(document.Entries), document.Entries)
	}
	wantIDs := []string{"CVE-2021-38561", "GHSA-ppp9-7jff-5vj2", "GO-2021-0113"}
	if strings.Join(document.Entries[0].AdvisoryIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("advisory IDs = %#v, want %#v", document.Entries[0].AdvisoryIDs, wantIDs)
	}
}

func TestResolverDoesNotSuppressChangedPolicyState(t *testing.T) {
	finding := sdk.Finding{ID: "denied", Kind: sdk.FindingKindPackage, Auditor: "package", RuleID: "denied-package", PackageRef: "pkg:npm/example@1.0.0", Severity: sdk.SeverityWarning, PolicyStatus: sdk.FindingPolicyStatusWarn}
	resolver, err := NewResolver(NewDocument([]sdk.Finding{finding}, nil))
	if err != nil {
		t.Fatal(err)
	}
	escalated := finding
	escalated.Severity = sdk.SeverityError
	escalated.PolicyStatus = sdk.FindingPolicyStatusFail
	if _, ok := resolver.ResolveFindingPolicy(context.Background(), escalated, nil); ok {
		t.Fatal("changed severity or policy status must require explicit baseline update")
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
	if err := WriteAtomic(path, document, false); err == nil {
		t.Fatal("expected overwrite without replace permission to be rejected")
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

func TestStateCompatibleAllowsSaferReachability(t *testing.T) {
	expected := Entry{Reachability: sdk.ReachabilityUnknown}
	if !stateCompatible(expected, Entry{Reachability: sdk.ReachabilityUnreachable}) {
		t.Fatal("unknown to unreachable should remain accepted")
	}
	if stateCompatible(expected, Entry{Reachability: sdk.ReachabilityReachable}) {
		t.Fatal("unknown to reachable must require explicit acceptance")
	}
	if stateCompatible(Entry{Reachability: sdk.ReachabilityUnreachable}, Entry{Reachability: sdk.ReachabilityUnknown}) {
		t.Fatal("unreachable to unknown must require explicit acceptance")
	}
}

func TestDocumentUsesFriendlyPolicyStatusField(t *testing.T) {
	document := NewDocument([]sdk.Finding{{
		ID: "rule", Kind: sdk.FindingKindPackage, Auditor: "package",
		RuleID: "rule", PackageRef: "pkg:npm/example@1.0.0",
	}}, nil)
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"policy_status":"fail"`) || strings.Contains(string(data), `"policyStatus"`) {
		t.Fatalf("baseline JSON = %s", data)
	}
}

func TestDocumentRejectsUnsupportedSeverity(t *testing.T) {
	document := NewDocument([]sdk.Finding{{
		ID: "rule", Kind: sdk.FindingKindPackage, Auditor: "package",
		RuleID: "rule", PackageRef: "pkg:npm/example@1.0.0",
	}}, nil)
	document.Entries[0].Severity = sdk.SeverityLevel("urgent")
	if err := document.Validate(); err == nil || !strings.Contains(err.Error(), `unsupported severity "urgent"`) {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDocumentAcceptsFindingSeverityVocabulary(t *testing.T) {
	for _, severity := range []sdk.SeverityLevel{
		"",
		sdk.SeverityUnknown,
		sdk.SeverityLevel("n/a"),
		sdk.SeverityLow,
		sdk.SeverityMedium,
		sdk.SeverityHigh,
		sdk.SeverityCritical,
		sdk.SeverityNote,
		sdk.SeverityWarning,
		sdk.SeverityError,
	} {
		document := NewDocument([]sdk.Finding{{
			ID: "rule", Kind: sdk.FindingKindPackage, Auditor: "package",
			RuleID: "rule", PackageRef: "pkg:npm/example@1.0.0",
		}}, nil)
		document.Entries[0].Severity = severity
		if err := document.Validate(); err != nil {
			t.Errorf("severity %q rejected: %v", severity, err)
		}
	}
}

func TestResolvePathSelections(t *testing.T) {
	root := t.TempDir()
	sbomPath := filepath.Join(root, "bom.json")
	if err := os.WriteFile(sbomPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	filesystem := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root}
	path, required, ok, err := ResolvePath("auto", filesystem)
	if err != nil || required || !ok || path != filepath.Join(root, ".bomly", "baseline.json") {
		t.Fatalf("auto path = %q, required=%v, ok=%v, err=%v", path, required, ok, err)
	}
	if _, _, ok, err := ResolvePath("none", filesystem); err != nil || ok {
		t.Fatalf("none selection: ok=%v, err=%v", ok, err)
	}
	path, required, ok, err = ResolvePath("policy/accepted.json", filesystem)
	if err != nil || !required || !ok || path != filepath.Join(root, "policy", "accepted.json") {
		t.Fatalf("relative path = %q, required=%v, ok=%v, err=%v", path, required, ok, err)
	}
	path, _, _, err = ResolvePath("auto", sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: sbomPath})
	if err != nil || path != filepath.Join(root, ".bomly", "baseline.json") {
		t.Fatalf("SBOM-adjacent path = %q, err=%v", path, err)
	}
	if _, _, ok, err := ResolvePath("auto", sdk.ExecutionTarget{Kind: sdk.ExecutionTargetContainerImage, Location: "alpine:3"}); err != nil || ok {
		t.Fatalf("container auto selection: ok=%v, err=%v", ok, err)
	}
	if _, _, _, err := ResolvePath("relative.json", sdk.ExecutionTarget{Kind: sdk.ExecutionTargetContainerImage, Location: "alpine:3"}); err == nil {
		t.Fatal("relative container baseline should be rejected")
	}
}

func TestResolversForTargetHandlesOptionalRequiredAndURLPolicies(t *testing.T) {
	root := t.TempDir()
	core, observed := observer.New(zap.DebugLevel)
	logger := zap.New(core)
	target := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root}
	result, err := ResolversForTarget("auto", target, logger)
	if err != nil || len(result.Resolvers) != 0 {
		t.Fatalf("optional missing baseline = %d resolvers, %v", len(result.Resolvers), err)
	}
	if observed.FilterMessage("baseline: no project policy found").Len() != 1 {
		t.Fatalf("missing baseline debug logs = %#v", observed.All())
	}
	if _, err := ResolversForTarget("required.json", target, logger); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit missing baseline error = %v", err)
	}

	path := filepath.Join(root, ".bomly", "baseline.json")
	document := NewDocument([]sdk.Finding{{
		ID: "rule", Kind: sdk.FindingKindPackage, Auditor: "package",
		RuleID: "rule", PackageRef: "pkg:npm/example@1.0.0",
	}}, nil)
	if err := WriteAtomic(path, document, false); err != nil {
		t.Fatal(err)
	}
	urlTarget := sdk.ExecutionTarget{
		Kind: sdk.ExecutionTargetGitRepository, Location: root,
		RepositoryURL: "https://example.test/untrusted.git",
	}
	result, err = ResolversForTarget("auto", urlTarget, logger)
	if err != nil || len(result.Resolvers) != 1 || !result.Automatic || result.Entries != 1 || result.Path != path {
		t.Fatalf("URL auto baseline = %#v, %v", result, err)
	}
	result, err = ResolversForTarget(path, urlTarget, logger)
	if err != nil || len(result.Resolvers) != 1 || result.Automatic {
		t.Fatalf("explicit URL baseline = %#v, %v", result, err)
	}
	logs := observed.FilterMessage("baseline: project policy detected and enabled")
	if logs.Len() != 2 {
		t.Fatalf("loaded baseline info logs = %#v", observed.All())
	}
	if got := logs.All()[0].ContextMap()["entries"]; got != int64(1) {
		t.Fatalf("baseline log entries = %#v", got)
	}
}
