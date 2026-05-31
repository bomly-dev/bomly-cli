package license

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// TestAuditor_SkipsRootPackage locks in the policy that the license
// auditor must NOT emit "unknown-license" findings for the root package
// of a project. The root is what the project IS, not a dependency, and
// most projects (especially private ones) don't carry a license attached
// to that node in lockfile data. Flagging it produces unactionable noise.
func TestAuditor_SkipsRootPackage(t *testing.T) {
	g := sdk.New()
	root := sdk.NewDependencyRef("github.com/example/private-app", "0.0.0")
	dep := sdk.NewDependencyRef("github.com/pkg/errors", "0.9.1")
	for _, p := range []*sdk.Package{root, dep} {
		if err := g.AddNode(p); err != nil {
			t.Fatalf("add %s: %v", p.ID, err)
		}
	}
	if err := g.AddEdge(root.ID, dep.ID); err != nil {
		t.Fatalf("add dep: %v", err)
	}

	result, err := Auditor{}.Audit(context.Background(), sdk.AuditRequest{Graph: g})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	for _, f := range result.Findings {
		if f.Package != nil && f.Package.ID == root.ID {
			t.Errorf("license auditor emitted finding for root package %q (id=%s): %#v",
				root.DisplayName(), root.ID, f)
		}
	}
	// The dependency should still be flagged — it has no license.
	flaggedDep := false
	for _, f := range result.Findings {
		if f.Package != nil && f.Package.ID == dep.ID {
			flaggedDep = true
			break
		}
	}
	if !flaggedDep {
		t.Errorf("expected the dependency to be flagged for unknown-license; findings: %#v", result.Findings)
	}
}

// TestAuditor_ComponentModeStillFlagsTarget verifies that the root-skip
// only applies to full-graph audits. When a caller invokes the auditor
// with `Mode=TargetModeComponent` against a specific target, that target
// is exactly what the user asked about — never skip it.
func TestAuditor_ComponentModeStillFlagsTarget(t *testing.T) {
	g := sdk.New()
	root := sdk.NewDependencyRef("github.com/example/app", "0.0.0")
	if err := g.AddNode(root); err != nil {
		t.Fatalf("add: %v", err)
	}

	result, err := Auditor{}.Audit(context.Background(), sdk.AuditRequest{
		Graph: g, Target: root, Mode: sdk.TargetModeComponent,
	})
	if err != nil {
		t.Fatalf("Audit() error = %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for explicit component target, got %d: %#v", len(result.Findings), result.Findings)
	}
	if !strings.Contains(result.Findings[0].ID, "unknown-license") {
		t.Errorf("expected unknown-license finding, got ID=%q", result.Findings[0].ID)
	}
}
