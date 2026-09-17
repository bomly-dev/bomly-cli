package packageauditor

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/testnodes"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// pkg is a convenience constructor for tests. The id argument is the PURL the
// node's identity is minted from, so it is both the coordinates' PURL and the
// resulting node ID -- there is no separate ID to set (ADR-0041).
func pkg(id, name, version, scope string) *model.DependencyNode {
	return testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: name, Version: version, PURL: id},
		Scopes:      model.ScopesOf(model.Scope(scope)),
		PackageRef:  id,
	})
}

// graphOf builds a Graph from the provided packages, panicking on error.
func graphOf(pkgs ...*model.DependencyNode) *model.Graph {
	g := model.New()
	for _, p := range pkgs {
		if err := g.AddNode(p); err != nil {
			panic(err)
		}
	}
	return g
}

func findingIDs(findings []model.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}

func findingKinds(findings []model.Finding) map[string]string {
	out := make(map[string]string, len(findings))
	for _, f := range findings {
		out[f.ID] = string(f.PolicyStatus)
	}
	return out
}

func TestAudit(t *testing.T) {
	const (
		idContainerdV2Old = "pkg:golang/github.com/containerd/containerd/v2@v2.2.2"
		idContainerdV2New = "pkg:golang/github.com/containerd/containerd/v2@v2.2.4"
		idContainerdAPI   = "pkg:golang/github.com/containerd/containerd/api@v1.0.0"
		idFake            = "pkg:golang/github.com/acme/fake@v1.0.0"
		idDenied          = "pkg:golang/github.com/evil/malware@v1.0.0"
		idDeniedGroup     = "pkg:golang/github.com/blocked/tool@v1.0.0"
	)

	pkgContainerdV2Old := pkg(idContainerdV2Old, "github.com/containerd/containerd/v2", "v2.2.2", "runtime")
	pkgContainerdV2New := pkg(idContainerdV2New, "github.com/containerd/containerd/v2", "v2.2.4", "runtime")
	pkgContainerdAPI := pkg(idContainerdAPI, "github.com/containerd/containerd/api", "v1.0.0", "runtime")
	pkgFake := pkg(idFake, "github.com/acme/fake", "v1.0.0", "runtime")
	pkgDenied := pkg(idDenied, "github.com/evil/malware", "v1.0.0", "runtime")
	pkgDeniedGroup := pkg(idDeniedGroup, "github.com/blocked/tool", "v1.0.0", "runtime")

	tests := []struct {
		name             string
		auditor          Auditor
		graph            *model.Graph
		baseline         *model.Graph
		wantFindingCount int
		wantFindingIDs   []string
		wantPolicyStatus map[string]string // finding ID → policy status
	}{
		{
			// Core regression: a version bump of an existing package must never
			// produce a typosquat finding, even when its name is highly similar to
			// another package already in the baseline.
			name: "version bump of existing package is not flagged as typosquat",
			auditor: Auditor{
				ProtectedPackages:  []string{},
				TyposquatThreshold: 0.90,
			},
			graph:            graphOf(pkgContainerdV2New),
			baseline:         graphOf(pkgContainerdV2Old, pkgContainerdAPI),
			wantFindingCount: 0,
		},
		{
			// A genuinely new package (not present in base at all) that is highly
			// similar to a protected name must be flagged.
			name: "new package similar to protected name is flagged",
			auditor: Auditor{
				ProtectedPackages:  []string{"github.com/containerd/containerd/api"},
				TyposquatThreshold: 0.90,
			},
			// head introduces containerd/v2 for the first time; base is empty.
			graph:            graphOf(pkgContainerdV2New),
			baseline:         model.New(),
			wantFindingCount: 1,
			wantFindingIDs: []string{
				"package:suspicious-package:" + idContainerdV2New,
			},
		},
		{
			// A new package similar to a baseline package is flagged.
			name: "new package similar to baseline package name is flagged",
			auditor: Auditor{
				TyposquatThreshold: 0.90,
			},
			// base has containerd/api; head introduces a new, similar name.
			graph:            graphOf(pkgContainerdV2New),
			baseline:         graphOf(pkgContainerdAPI),
			wantFindingCount: 1,
			wantFindingIDs: []string{
				"package:suspicious-package:" + idContainerdV2New,
			},
		},
		{
			// When the exact package ID (name + version) is unchanged the check
			// is skipped entirely.
			name: "unchanged package (same ID) produces no finding",
			auditor: Auditor{
				ProtectedPackages:  []string{"github.com/containerd/containerd/api"},
				TyposquatThreshold: 0.90,
			},
			graph:            graphOf(pkgContainerdV2Old),
			baseline:         graphOf(pkgContainerdV2Old),
			wantFindingCount: 0,
		},
		{
			// An ordinary scan has no baseline, but configured protected names
			// still provide the reference set needed for a safe evaluation.
			name: "no baseline checks configured protected package names",
			auditor: Auditor{
				ProtectedPackages:  []string{"github.com/containerd/containerd/api"},
				TyposquatThreshold: 0.90,
			},
			graph:            graphOf(pkgContainerdV2New),
			baseline:         nil,
			wantFindingCount: 1,
			wantFindingIDs: []string{
				"package:suspicious-package:" + idContainerdV2New,
			},
		},
		{
			// Without a baseline or configured protected names there is no
			// reference set, so an ordinary scan produces no typosquat finding.
			name: "no baseline and no protected names produces no finding",
			auditor: Auditor{
				TyposquatThreshold: 0.90,
			},
			graph:            graphOf(pkgContainerdV2New),
			baseline:         nil,
			wantFindingCount: 0,
		},
		{
			// An explicitly denied package triggers a fail finding regardless of
			// baseline presence.
			name: "denied package is flagged with fail policy status",
			auditor: Auditor{
				DenyPackages: []string{"pkg:golang/github.com/evil/malware"},
			},
			graph:    graphOf(pkgDenied),
			baseline: model.New(),
			wantFindingIDs: []string{
				"package:denied-package:" + idDenied,
			},
			wantFindingCount: 1,
			wantPolicyStatus: map[string]string{
				"package:denied-package:" + idDenied: string(model.FindingPolicyStatusFail),
			},
		},
		{
			// An explicitly denied group triggers a fail finding.
			name: "denied group is flagged with fail policy status",
			auditor: Auditor{
				DenyGroups: []string{"pkg:golang/github.com/blocked"},
			},
			graph:    graphOf(pkgDeniedGroup),
			baseline: model.New(),
			wantFindingIDs: []string{
				"package:denied-group:" + idDeniedGroup,
			},
			wantFindingCount: 1,
			wantPolicyStatus: map[string]string{
				"package:denied-group:" + idDeniedGroup: string(model.FindingPolicyStatusFail),
			},
		},
		{
			// TyposquatMode "fail" escalates policy status to fail.
			name: "typosquat mode fail escalates policy status",
			auditor: Auditor{
				ProtectedPackages:  []string{"github.com/containerd/containerd/api"},
				TyposquatThreshold: 0.90,
				TyposquatMode:      "fail",
			},
			graph:            graphOf(pkgContainerdV2New),
			baseline:         model.New(),
			wantFindingCount: 1,
			wantPolicyStatus: map[string]string{
				"package:suspicious-package:" + idContainerdV2New: string(model.FindingPolicyStatusFail),
			},
		},
		{
			// Unrelated new package that does not resemble any protected name
			// produces no finding.
			name: "unrelated new package produces no finding",
			auditor: Auditor{
				ProtectedPackages:  []string{"github.com/containerd/containerd/api"},
				TyposquatThreshold: 0.90,
			},
			graph:            graphOf(pkgFake),
			baseline:         model.New(),
			wantFindingCount: 0,
		},
		{
			// Nil graph returns an empty result without panicking.
			name:             "nil graph returns empty result",
			auditor:          Auditor{},
			graph:            nil,
			baseline:         nil,
			wantFindingCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := plugin.AuditRequest{
				Graph:         tc.graph,
				BaselineGraph: tc.baseline,
			}
			result, err := tc.auditor.Audit(context.Background(), req)
			if err != nil {
				t.Fatalf("Audit() error = %v", err)
			}
			if got := len(result.Findings); got != tc.wantFindingCount {
				t.Errorf("finding count = %d, want %d; findings: %v", got, tc.wantFindingCount, findingIDs(result.Findings))
			}
			for _, finding := range result.Findings {
				wantSeverity := model.SeverityError
				if finding.PolicyStatus == model.FindingPolicyStatusWarn {
					wantSeverity = model.SeverityWarning
				}
				if finding.Severity != wantSeverity {
					t.Errorf("finding %q severity = %q, want %q (policy status %q)", finding.ID, finding.Severity, wantSeverity, finding.PolicyStatus)
				}
			}
			for _, wantID := range tc.wantFindingIDs {
				found := false
				for _, f := range result.Findings {
					if f.ID == wantID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding %q not present; got: %v", wantID, findingIDs(result.Findings))
				}
			}
			if tc.wantPolicyStatus != nil {
				dispositions := findingKinds(result.Findings)
				for wantID, wantDisp := range tc.wantPolicyStatus {
					if got, ok := dispositions[wantID]; !ok {
						t.Errorf("finding %q not present", wantID)
					} else if got != wantDisp {
						t.Errorf("finding %q policy status = %q, want %q", wantID, got, wantDisp)
					}
				}
			}
		})
	}
}

func TestAuditDependencySourceChanges(t *testing.T) {
	// One node per name: identity is minted from the coordinates now, so two
	// transitions that share a name are one dependency, and this case is
	// about two distinct ones both moving to Git.
	transition := func(name string, source model.DependencySource) model.DependencyDetailTransition {
		purl := "pkg:npm/" + name + "@1.0.0"
		before := testnodes.DepFrom(model.DependencyNode{
			Coordinates: model.Coordinates{PURL: purl, Ecosystem: model.EcosystemNPM, Name: name, Version: "1.0.0"},
			Source:      model.DependencySourceRegistry,
			PackageRef:  purl,
		})
		after := before.Clone()
		after.Source = source
		return model.DependencyDetailTransition{
			Before:                 before,
			After:                  after,
			ChangedFields:          []model.DependencyDetailField{model.DependencyDetailSource, model.DependencyDetailRegistryEligibility},
			BeforeRegistryEligible: true,
		}
	}

	result, err := (Auditor{}).Audit(context.Background(), plugin.AuditRequest{
		DependencyDetailChanges: []model.DependencyDetailTransition{
			transition("one", model.DependencySourceGit),
			transition("two", model.DependencySourceGit),
			transition("url-package", model.DependencySourceURL),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// One finding per package: findings group by package reference, and two
	// packages that both moved to Git are two references. There is no longer
	// a case where one package contributes two transitions -- occurrences
	// were what produced that, and identity is unique by construction now.
	if len(result.Findings) != 3 {
		t.Fatalf("findings = %#v, want one per changed package", result.Findings)
	}
	for _, git := range result.Findings[:2] {
		if git.RuleID != "dependency-source-change-to-git" ||
			git.PolicyStatus != model.FindingPolicyStatusWarn ||
			git.Severity != model.SeverityWarning ||
			len(git.DependencyRefs) != 1 {
			t.Fatalf("Git source finding = %#v", git)
		}
	}
	if result.Findings[2].RuleID != "dependency-source-change-to-url" {
		t.Fatalf("URL source finding = %#v", result.Findings[2])
	}

	enforced, err := (Auditor{
		FailOn: []model.FailOnConstraint{{
			Kind: model.SourceChangeConstraint, Value: model.SourceChangeValue,
		}},
	}).Audit(context.Background(), plugin.AuditRequest{
		DependencyDetailChanges: []model.DependencyDetailTransition{
			transition("npm:one", model.DependencySourceGit),
			transition("npm:url", model.DependencySourceURL),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if enforced.Findings[0].PolicyStatus != model.FindingPolicyStatusFail ||
		enforced.Findings[0].Severity != model.SeverityError {
		t.Fatalf("denied Git source finding = %#v", enforced.Findings[0])
	}
	if enforced.Findings[1].PolicyStatus != model.FindingPolicyStatusFail ||
		enforced.Findings[1].Severity != model.SeverityError {
		t.Fatalf("enforced URL source finding = %#v", enforced.Findings[1])
	}
}

func TestAuditDependencySourceChangesIgnoresInformationalTransitions(t *testing.T) {
	dependency := testnodes.DepFrom(model.DependencyNode{
		Coordinates: model.Coordinates{Name: "example", Version: "1.0.0"},
		Source:      model.DependencySourceRegistry,
	})
	after := dependency.Clone()
	after.Relationship = model.DependencyRelationshipTransitive
	result, err := (Auditor{}).Audit(context.Background(), plugin.AuditRequest{
		DependencyDetailChanges: []model.DependencyDetailTransition{{
			Before:        dependency,
			After:         after,
			ChangedFields: []model.DependencyDetailField{model.DependencyDetailRelationship},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("informational transition produced findings: %#v", result.Findings)
	}
}
