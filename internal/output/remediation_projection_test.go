package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestScanAndDiffJSONKeepRemediationOnTopLevelPackages(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	registry := sdk.NewPackageRegistry()
	registry.Add(&sdk.Package{
		Coordinates: sdk.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:      "GHSA-example",
			FixedIn: "1.2.0",
		}},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})

	scan := BuildScanResponse(ProjectDescriptor{Name: "demo"}, sdk.ConsolidatedGraph{}, registry, nil, time.Now())
	assertOnlyPackageRemediation(t, scan, 1)

	diff := BuildDiffResponse(
		"/tmp/demo",
		"main",
		"feature",
		sdk.ConsolidatedGraph{},
		sdk.ConsolidatedGraph{},
		nil,
		time.Now(),
		ReportOptions{HeadRegistry: registry},
	)
	assertOnlyPackageRemediation(t, diff, 1)
}

func assertOnlyPackageRemediation(t *testing.T, value any, wantCount int) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if got := strings.Count(string(data), `"remediation"`); got != wantCount {
		t.Fatalf("remediation occurrence count = %d, want %d: %s", got, wantCount, data)
	}
	for _, unwanted := range []string{`"fix_result"`, `"remediation_plan"`} {
		if strings.Contains(string(data), unwanted) {
			t.Fatalf("unexpected top-level remediation contract %s: %s", unwanted, data)
		}
	}
}
