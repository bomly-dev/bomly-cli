package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

func TestScanAndDiffJSONKeepRemediationOnTopLevelPackages(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	registry := model.NewPackageRegistry()
	registry.Add(&model.Package{
		Coordinates: model.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
		Vulnerabilities: []model.Vulnerability{{
			ID:      "GHSA-example",
			FixedIn: "1.2.0",
		}},
		Remediation: &model.PackageRemediation{
			Status:             model.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
		},
	})

	scan := BuildScanResponse(ProjectDescriptor{Name: "demo"}, plugin.ConsolidatedGraph{}, registry, nil, time.Now())
	assertOnlyPackageRemediation(t, scan, 1)

	diff := BuildDiffResponse(
		"/tmp/demo",
		"main",
		"feature",
		plugin.ConsolidatedGraph{},
		plugin.ConsolidatedGraph{},
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
