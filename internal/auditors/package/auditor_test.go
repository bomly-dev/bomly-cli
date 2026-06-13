package packageauditor

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// pkg is a convenience constructor for tests.
func pkg(id, name, version, scope string) *sdk.Dependency {
	return &sdk.Dependency{Coordinates: sdk.Coordinates{Name: name,
		Version: version,

		PURL: id}, ID: id,

		Scopes: sdk.ScopesOf(sdk.Scope(scope)),

		PackageRef: id,
	}
}

// graphOf builds a Graph from the provided packages, panicking on error.
func graphOf(pkgs ...*sdk.Dependency) *sdk.Graph {
	g := sdk.New()
	for _, p := range pkgs {
		if err := g.AddNode(p); err != nil {
			panic(err)
		}
	}
	return g
}

func findingIDs(findings []sdk.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}

func findingKinds(findings []sdk.Finding) map[string]string {
	out := make(map[string]string, len(findings))
	for _, f := range findings {
		out[f.ID] = string(f.Disposition)
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
		graph            *sdk.Graph
		baseline         *sdk.Graph
		wantFindingCount int
		wantFindingIDs   []string
		wantDisposition  map[string]string // finding ID → disposition
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
			baseline:         sdk.New(),
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
			// When there is no baseline the typosquat check is skipped for all
			// packages (we have no diff context).
			name: "no baseline skips typosquat check",
			auditor: Auditor{
				ProtectedPackages:  []string{"github.com/containerd/containerd/api"},
				TyposquatThreshold: 0.90,
			},
			graph:            graphOf(pkgContainerdV2New),
			baseline:         nil,
			wantFindingCount: 0,
		},
		{
			// An explicitly denied package triggers a fail finding regardless of
			// baseline presence.
			name: "denied package is flagged with fail disposition",
			auditor: Auditor{
				DenyPackages: []string{"pkg:golang/github.com/evil/malware"},
			},
			graph:    graphOf(pkgDenied),
			baseline: sdk.New(),
			wantFindingIDs: []string{
				"package:denied-package:" + idDenied,
			},
			wantFindingCount: 1,
			wantDisposition: map[string]string{
				"package:denied-package:" + idDenied: string(sdk.FindingDispositionFail),
			},
		},
		{
			// An explicitly denied group triggers a fail finding.
			name: "denied group is flagged with fail disposition",
			auditor: Auditor{
				DenyGroups: []string{"pkg:golang/github.com/blocked"},
			},
			graph:    graphOf(pkgDeniedGroup),
			baseline: sdk.New(),
			wantFindingIDs: []string{
				"package:denied-group:" + idDeniedGroup,
			},
			wantFindingCount: 1,
			wantDisposition: map[string]string{
				"package:denied-group:" + idDeniedGroup: string(sdk.FindingDispositionFail),
			},
		},
		{
			// TyposquatMode "fail" escalates disposition to fail.
			name: "typosquat mode fail escalates disposition",
			auditor: Auditor{
				ProtectedPackages:  []string{"github.com/containerd/containerd/api"},
				TyposquatThreshold: 0.90,
				TyposquatMode:      "fail",
			},
			graph:            graphOf(pkgContainerdV2New),
			baseline:         sdk.New(),
			wantFindingCount: 1,
			wantDisposition: map[string]string{
				"package:suspicious-package:" + idContainerdV2New: string(sdk.FindingDispositionFail),
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
			baseline:         sdk.New(),
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
			req := sdk.AuditRequest{
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
				if finding.Severity != packageSeverityNA {
					t.Errorf("finding %q severity = %q, want %q", finding.ID, finding.Severity, packageSeverityNA)
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
			if tc.wantDisposition != nil {
				dispositions := findingKinds(result.Findings)
				for wantID, wantDisp := range tc.wantDisposition {
					if got, ok := dispositions[wantID]; !ok {
						t.Errorf("finding %q not present", wantID)
					} else if got != wantDisp {
						t.Errorf("finding %q disposition = %q, want %q", wantID, got, wantDisp)
					}
				}
			}
		})
	}
}
