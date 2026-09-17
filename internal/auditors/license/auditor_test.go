package license

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestLicenseAuditorAllowDeny(t *testing.T) {
	allow := Auditor{AllowLicenses: []string{"MIT"}}
	deny := Auditor{DenyLicenses: []string{"GPL-3.0-only"}}

	// mkScenario builds an app→lib graph plus a registry where lib's package
	// (keyed by its PURL) carries the given license.
	mkScenario := func(license string) (*model.Graph, *model.PackageRegistry) {
		g := model.New()
		root := testnodes.Ref("app", "1.0.0")
		_ = g.AddNode(root)
		dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "lib", Version: "1.0.0", Ecosystem: model.EcosystemNPM, PackageManager: model.PackageManagerNPM}})
		purl := dep.NodeID()
		dep.PackageRef = purl
		_ = g.AddNode(dep)
		_ = g.AddEdge(root.NodeID(), dep.NodeID())

		registry := model.NewPackageRegistry()
		registry.Ensure(purl).Licenses = []model.PackageLicense{{SPDXExpression: license}}
		return g, registry
	}

	tests := []struct {
		name        string
		auditor     Auditor
		license     string
		wantFinding bool
	}{
		{"allow satisfied", allow, "MIT", false},
		{"allow violated", allow, "GPL-3.0-only", true},
		{"deny violated", deny, "GPL-3.0-only", true},
		{"deny satisfied", deny, "Apache-2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, registry := mkScenario(tt.license)
			result, err := tt.auditor.Audit(context.Background(), plugin.AuditRequest{Graph: g, Registry: registry})
			if err != nil {
				t.Fatalf("Audit() error = %v", err)
			}
			hasFinding := false
			for _, f := range result.Findings {
				if f.Kind == model.FindingKindLicense {
					hasFinding = true
				}
			}
			if hasFinding != tt.wantFinding {
				t.Errorf("want finding=%v got=%v", tt.wantFinding, hasFinding)
			}
		})
	}
}

func TestLicenseAuditorUnknownLicenseUsesCompactFindingID(t *testing.T) {
	g := model.New()
	root := testnodes.Ref("app", "1.0.0")
	_ = g.AddNode(root)
	dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "very-long-package-name-with-output-hostile-length",
		Version:        "1.2.3",
		Ecosystem:      model.EcosystemNPM,
		PackageManager: model.PackageManagerNPM},
	})
	purl := dep.NodeID()
	dep.PackageRef = purl
	_ = g.AddNode(dep)
	_ = g.AddEdge(root.NodeID(), dep.NodeID())

	result, err := Auditor{}.Audit(context.Background(), plugin.AuditRequest{
		Graph:    g,
		Registry: model.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", result.Findings)
	}
	finding := result.Findings[0]
	if !strings.HasPrefix(finding.ID, unknownLicenseFindingID+"-") {
		t.Fatalf("finding ID = %q, want %q prefix", finding.ID, unknownLicenseFindingID+"-")
	}
	if parts := strings.Split(finding.ID, "-"); len(parts) != 4 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 {
		t.Fatalf("finding ID = %q, want compact UNKNOWN-xxxx-xxxx-xxxx shape", finding.ID)
	}
	if strings.Contains(finding.ID, dep.Name) || strings.Contains(finding.ID, purl) {
		t.Fatalf("finding ID should not include package identity: %q", finding.ID)
	}
	if finding.PackageRef != purl {
		t.Fatalf("finding package ref = %q, want %q", finding.PackageRef, purl)
	}
	if finding.Severity != model.SeverityWarning {
		t.Fatalf("finding severity = %q, want %q", finding.Severity, model.SeverityWarning)
	}
}

func TestLicenseAuditorDeniedLicensesUseErrorSeverity(t *testing.T) {
	g := model.New()
	root := testnodes.Ref("app", "1.0.0")
	_ = g.AddNode(root)
	dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: "lib", Version: "1.0.0", Ecosystem: model.EcosystemNPM, PackageManager: model.PackageManagerNPM}})
	purl := dep.NodeID()
	dep.PackageRef = purl
	_ = g.AddNode(dep)
	_ = g.AddEdge(root.NodeID(), dep.NodeID())

	registry := model.NewPackageRegistry()
	registry.Ensure(purl).Licenses = []model.PackageLicense{{SPDXExpression: "GPL-3.0-only"}}

	result, err := Auditor{AllowLicenses: []string{"MIT"}}.Audit(context.Background(), plugin.AuditRequest{
		Graph:    g,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", result.Findings)
	}
	if got := result.Findings[0].Severity; got != model.SeverityError {
		t.Fatalf("finding severity = %q, want %q", got, model.SeverityError)
	}
	if got := result.Findings[0].ID; !strings.HasPrefix(got, deniedLicenseFindingID+"-") {
		t.Fatalf("finding ID = %q, want %q prefix", got, deniedLicenseFindingID+"-")
	}
}

func TestLicenseAuditorUnknownLicenseIDsDifferByPackage(t *testing.T) {
	g := model.New()
	root := testnodes.Ref("app", "1.0.0")
	_ = g.AddNode(root)
	for _, name := range []string{"left-pad", "is-odd"} {
		dep := testnodes.DepFrom(model.DependencyNode{Coordinates: model.Coordinates{Name: name, Version: "1.0.0", Ecosystem: model.EcosystemNPM, PackageManager: model.PackageManagerNPM}})
		dep.PackageRef = dep.NodeID()
		_ = g.AddNode(dep)
		_ = g.AddEdge(root.NodeID(), dep.NodeID())
	}

	result, err := Auditor{}.Audit(context.Background(), plugin.AuditRequest{
		Graph:    g,
		Registry: model.NewPackageRegistry(),
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", result.Findings)
	}
	if result.Findings[0].ID == result.Findings[1].ID {
		t.Fatalf("unknown license finding IDs should differ by package, got %q", result.Findings[0].ID)
	}
}
