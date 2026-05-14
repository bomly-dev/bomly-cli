package render

import (
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestScanRendersReachabilityColumnWhenEnabled(t *testing.T) {
	g := model.New()
	pkg := model.NewPackage(model.Package{Name: "lib", Version: "1.0.0", Ecosystem: "go"})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{
		{
			ID:       "CVE-2024-0001",
			Kind:     model.FindingKindVulnerability,
			Package:  pkg,
			Severity: "high",
			Title:    "tls bypass",
			Source:   "osv",
			Reachability: &model.Reachability{
				Status:   model.ReachabilityReachable,
				Tier:     model.TierSymbol,
				Analyzer: "govulncheck",
			},
		},
	}
	out := Scan([]output.ScanManifest{}, g, findings, true /*enrich*/, true /*audit*/, true /*reachability*/)
	if !strings.Contains(out, "REACHABILITY") {
		t.Fatalf("expected REACHABILITY column when reachabilityEnabled=true; got:\n%s", out)
	}
	if !strings.Contains(out, "reachable (symbol)") {
		t.Fatalf("expected reachable (symbol) cell in findings table; got:\n%s", out)
	}
	if !strings.Contains(out, "Reachability:") {
		t.Fatalf("expected Reachability summary line; got:\n%s", out)
	}
}

func TestScanOmitsReachabilityColumnWhenDisabled(t *testing.T) {
	g := model.New()
	pkg := model.NewPackage(model.Package{Name: "lib", Version: "1.0.0", Ecosystem: "go"})
	if err := g.AddPackage(pkg); err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{
		{ID: "CVE-2024-0001", Kind: model.FindingKindVulnerability, Package: pkg, Severity: "high", Title: "x", Source: "osv"},
	}
	out := Scan([]output.ScanManifest{}, g, findings, true, true, false)
	if strings.Contains(out, "REACHABILITY") {
		t.Fatalf("REACHABILITY column should not appear when reachabilityEnabled=false; got:\n%s", out)
	}
	if strings.Contains(out, "Reachability:") {
		t.Fatalf("Reachability summary should not appear when disabled; got:\n%s", out)
	}
}

func TestFormatReachabilityCell(t *testing.T) {
	cases := []struct {
		name string
		in   *model.Reachability
		want string
	}{
		{"nil", nil, "—"},
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
