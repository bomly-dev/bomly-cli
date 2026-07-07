package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestScanRendersReachabilityColumnWhenEnabled(t *testing.T) {
	g := model.New()
	const libPURL = "pkg:go/lib@1.0.0"
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "lib", Version: "1.0.0", Ecosystem: model.EcosystemGo, PURL: libPURL}})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	registry := model.NewPackageRegistry()
	regPkg := registry.Ensure(libPURL)
	regPkg.Name = "lib"
	regPkg.Version = "1.0.0"
	regPkg.Vulnerabilities = []model.Vulnerability{{
		ID:     "CVE-2024-0001",
		Title:  "tls bypass",
		Source: "osv",
		Reachability: &model.Reachability{
			Status:   model.ReachabilityReachable,
			Tier:     model.TierSymbol,
			Analyzer: "govulncheck",
		},
	}}
	findings := []model.Finding{
		{
			ID:              "CVE-2024-0001",
			VulnerabilityID: "CVE-2024-0001",
			Kind:            model.FindingKindVulnerability,
			PackageRef:      libPURL,
			Severity:        "high",
			Title:           "tls bypass",
			Source:          "osv",
		},
	}
	out := Scan(g, registry, findings, nil /*matcherStats*/, true /*enrich*/, true /*audit*/, true /*reachability*/, nil /*failOn*/, "" /*subprojectSummary*/, nil /*fallbackNotices*/)
	// The compact text format shows the finding CVE ID and package name; detailed
	// reachability info is available in the JSON and Markdown output formats.
	if !strings.Contains(StripANSI(out), "CVE-2024-0001") {
		t.Fatalf("expected finding ID in compact scan output; got:\n%s", out)
	}
	if !strings.Contains(StripANSI(out), "Findings") {
		t.Fatalf("expected Findings section in compact scan output; got:\n%s", out)
	}
}

func TestScanMarkdownRendersReachabilityOnlyWhenEnabled(t *testing.T) {
	payload := output.ScanResponse{
		Metadata: output.Metadata{ReachabilityEnabled: true},
		Packages: []output.ScanPackageEntry{{
			Purl: "pkg:golang/lib@1.0.0",
			Name: "lib",
			Vulnerabilities: []output.VulnerabilityRef{{
				ID:           "CVE-2024-0001",
				Source:       "osv",
				Reachability: &model.Reachability{Status: model.ReachabilityReachable, Tier: model.TierPackage},
			}},
		}},
		Findings: []output.AuditFinding{{
			ID:           "CVE-2024-0001",
			Severity:     "high",
			Package:      output.PackageRef{Name: "lib"},
			Reachability: &model.Reachability{Status: model.ReachabilityReachable, Tier: model.TierPackage},
		}},
	}
	var out bytes.Buffer
	if err := ScanMarkdown(&out, payload); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	if !strings.Contains(out.String(), "Reachability") || !strings.Contains(out.String(), "reachable (package)") {
		t.Fatalf("expected reachability in enabled Markdown output; got:\n%s", out.String())
	}

	payload.Metadata.ReachabilityEnabled = false
	out.Reset()
	if err := ScanMarkdown(&out, payload); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	if strings.Contains(out.String(), "Reachability") || strings.Contains(out.String(), "reachable (package)") {
		t.Fatalf("reachability should be absent when disabled; got:\n%s", out.String())
	}
}

func TestDiffTextAndMarkdownRenderReachabilityOnlyWhenEnabled(t *testing.T) {
	payload := output.DiffResponse{
		Metadata: output.Metadata{ReachabilityEnabled: true},
		Results: output.DiffResults{
			Vulnerabilities: output.DiffVulnerabilityResults{
				Added: []output.DiffVulnerabilityChange{{
					Package: output.PackageRef{Name: "lib", Version: "1.0.0"},
					Vulnerability: output.VulnerabilityRef{
						ID:           "CVE-2024-0001",
						Severity:     "high",
						Reachability: &model.Reachability{Status: model.ReachabilityReachable, Tier: model.TierPackage},
					},
				}},
			},
		},
		Audit: &output.DiffAudit{
			Introduced: []output.AuditFinding{{
				ID:           "CVE-2024-0001",
				Severity:     "high",
				Package:      output.PackageRef{Name: "lib", Version: "1.0.0"},
				Reachability: &model.Reachability{Status: model.ReachabilityReachable, Tier: model.TierPackage},
			}},
		},
	}
	// Compact text diff shows only a findings summary; reachability detail is
	// available in JSON and Markdown formats.
	var text bytes.Buffer
	if err := Diff(&text, payload); err != nil {
		t.Fatalf("Diff() error = %v", err)
	}
	plainText := StripANSI(text.String())
	if strings.Contains(plainText, "reachability reachable") {
		t.Fatalf("reachability detail should not appear in compact diff text; got:\n%s", text.String())
	}
	if !strings.Contains(plainText, "finding") {
		t.Fatalf("expected findings summary in diff text; got:\n%s", text.String())
	}

	var markdown bytes.Buffer
	if err := DiffMarkdown(&markdown, payload); err != nil {
		t.Fatalf("DiffMarkdown() error = %v", err)
	}
	if !strings.Contains(markdown.String(), "Reachability") || !strings.Contains(markdown.String(), "reachable (package)") {
		t.Fatalf("expected reachability in enabled diff Markdown; got:\n%s", markdown.String())
	}

	payload.Metadata.ReachabilityEnabled = false
	markdown.Reset()
	if err := DiffMarkdown(&markdown, payload); err != nil {
		t.Fatalf("DiffMarkdown() error = %v", err)
	}
	if strings.Contains(markdown.String(), "Reachability") || strings.Contains(markdown.String(), "reachable (package)") {
		t.Fatalf("reachability should be absent from disabled diff Markdown; got:\n%s", markdown.String())
	}
}

func TestExplainTextAndMarkdownRenderReachabilityOnlyWhenEnabled(t *testing.T) {
	target := output.ExplainTargetResponse{
		Project: output.ProjectDescriptor{Name: "demo"},
		Dependency: output.PackageRef{
			Name: "lib",
			Vulnerabilities: []output.VulnerabilityRef{{
				ID:           "CVE-2024-0001",
				Source:       "osv",
				Severity:     "high",
				Reachability: &model.Reachability{Status: model.ReachabilityReachable, Tier: model.TierPackage},
			}},
		},
		Findings: []output.AuditFinding{{
			ID:           "CVE-2024-0001",
			Severity:     "high",
			Package:      output.PackageRef{Name: "lib"},
			Reachability: &model.Reachability{Status: model.ReachabilityReachable, Tier: model.TierPackage},
		}},
	}
	// Compact text explain shows the CVE ID and severity but not the reachability
	// detail; that is available in JSON and Markdown formats.
	var text bytes.Buffer
	if err := Explain(&text, target, true); err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	plainText := StripANSI(text.String())
	if !strings.Contains(plainText, "CVE-2024-0001") {
		t.Fatalf("expected CVE ID in compact explain text; got:\n%s", text.String())
	}
	if strings.Contains(plainText, "Reach:") || strings.Contains(plainText, "reachable (package)") {
		t.Fatalf("reachability detail should not appear in compact explain text; got:\n%s", text.String())
	}

	payload := output.ExplainResponse{
		Metadata: output.Metadata{ReachabilityEnabled: true},
		Query:    output.ExplainQuery{Name: "lib"},
		Targets:  []output.ExplainTargetResponse{target},
	}
	var markdown bytes.Buffer
	if err := ExplainMarkdown(&markdown, payload); err != nil {
		t.Fatalf("ExplainMarkdown() error = %v", err)
	}
	if !strings.Contains(markdown.String(), "Reachability") || !strings.Contains(markdown.String(), "reachable (package)") {
		t.Fatalf("expected reachability in enabled explain Markdown; got:\n%s", markdown.String())
	}
	payload.Metadata.ReachabilityEnabled = false
	markdown.Reset()
	if err := ExplainMarkdown(&markdown, payload); err != nil {
		t.Fatalf("ExplainMarkdown() error = %v", err)
	}
	if strings.Contains(markdown.String(), "Reachability") || strings.Contains(markdown.String(), "reachable (package)") {
		t.Fatalf("reachability should be absent from disabled explain Markdown; got:\n%s", markdown.String())
	}
}

func TestScanOmitsReachabilityColumnWhenDisabled(t *testing.T) {
	g := model.New()
	pkg := model.NewDependency(model.Dependency{Coordinates: model.Coordinates{Name: "lib", Version: "1.0.0", Ecosystem: model.EcosystemGo}})
	if err := g.AddNode(pkg); err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{
		{ID: "CVE-2024-0001", Kind: model.FindingKindVulnerability, PackageRef: pkg.PURL, Severity: "high", Title: "x", Source: "osv"},
	}
	out := Scan(g, nil, findings, nil, true, true, false, nil, "", nil)
	// Compact text format never shows a REACHABILITY column; detailed info is in JSON/Markdown.
	if strings.Contains(StripANSI(out), "REACHABILITY") {
		t.Fatalf("REACHABILITY column should not appear in compact text output; got:\n%s", out)
	}
	if strings.Contains(StripANSI(out), "Reachability:") {
		t.Fatalf("Reachability summary should not appear in compact text output; got:\n%s", out)
	}
}

func TestFormatReachabilityCell(t *testing.T) {
	cases := []struct {
		name string
		in   *model.Reachability
		want string
	}{
		{"nil", nil, "-"},
		{"reachable+symbol", &model.Reachability{Status: model.ReachabilityReachable, Tier: model.TierSymbol}, "reachable (symbol)"},
		{"unknown+none", &model.Reachability{Status: model.ReachabilityUnknown, Tier: model.TierNone}, "unknown"},
		{"unreachable, no tier", &model.Reachability{Status: model.ReachabilityUnreachable}, "unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatReachabilityCell(tc.in); got != tc.want {
				t.Errorf("formatReachabilityCell = %q, want %q", got, tc.want)
			}
		})
	}
}
