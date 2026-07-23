package license

import (
	"context"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestLicenseAuditorComplexSPDXAllowMatrix(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		allowed    []string
		wantRule   string
	}{
		{
			name:       "OR accepts one permitted alternative",
			expression: "MIT OR GPL-3.0-only",
			allowed:    []string{"MIT"},
		},
		{
			name:       "OR rejects when no alternative is permitted",
			expression: "MIT OR Apache-2.0",
			allowed:    []string{"BSD-3-Clause"},
			wantRule:   "denied-license",
		},
		{
			name:       "AND accepts when every term is permitted",
			expression: "MIT AND Apache-2.0",
			allowed:    []string{"Apache-2.0", "MIT"},
		},
		{
			name:       "AND rejects when one term is not permitted",
			expression: "MIT AND Apache-2.0",
			allowed:    []string{"MIT"},
			wantRule:   "denied-license",
		},
		{
			name:       "nested expression accepts a complete branch",
			expression: "(MIT OR Apache-2.0) AND BSD-3-Clause",
			allowed:    []string{"MIT", "BSD-3-Clause"},
		},
		{
			name:       "nested expression rejects incomplete branches",
			expression: "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)",
			allowed:    []string{"MIT"},
			wantRule:   "denied-license",
		},
		{
			name:       "operator precedence permits standalone OR branch",
			expression: "MIT OR Apache-2.0 AND BSD-3-Clause",
			allowed:    []string{"MIT"},
		},
		{
			name:       "parentheses require the trailing AND term",
			expression: "(MIT OR Apache-2.0) AND BSD-3-Clause",
			allowed:    []string{"MIT"},
			wantRule:   "denied-license",
		},
		{
			name:       "three-way AND requires every term",
			expression: "MIT AND Apache-2.0 AND BSD-3-Clause",
			allowed:    []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
		{
			name:       "three-way OR permits one term",
			expression: "GPL-3.0-only OR Apache-2.0 OR BSD-3-Clause",
			allowed:    []string{"BSD-3-Clause"},
		},
		{
			name:       "surrounding and repeated whitespace is accepted",
			expression: "  MIT   AND   Apache-2.0  ",
			allowed:    []string{"MIT", "Apache-2.0"},
		},
		{
			name:       "exception accepts exact permitted expression",
			expression: "GPL-2.0-only WITH Classpath-exception-2.0",
			allowed:    []string{"GPL-2.0-only WITH Classpath-exception-2.0"},
		},
		{
			name:       "exception is not erased when only base is permitted",
			expression: "GPL-2.0-only WITH Classpath-exception-2.0",
			allowed:    []string{"GPL-2.0-only"},
			wantRule:   "denied-license",
		},
		{
			name:       "license reference participates in AND",
			expression: "MIT AND LicenseRef-Proprietary-Notice",
			allowed:    []string{"MIT", "LicenseRef-Proprietary-Notice"},
		},
		{
			name:       "document license reference participates in AND",
			expression: "MIT AND DocumentRef-supplier:LicenseRef-Custom",
			allowed:    []string{"MIT", "DocumentRef-supplier:LicenseRef-Custom"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := auditLicenseExpressions(t, Auditor{AllowLicenses: test.allowed}, test.expression)
			assertLicenseRule(t, findings, test.wantRule)
		})
	}
}

func TestLicenseAuditorComplexSPDXDenyMatrix(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		denied     []string
		wantRule   string
	}{
		{
			name:       "OR is conservatively denied when any alternative is denied",
			expression: "MIT OR GPL-3.0-only",
			denied:     []string{"GPL-3.0-only"},
			wantRule:   "denied-license",
		},
		{
			name:       "AND is denied when one required term is denied",
			expression: "MIT AND Apache-2.0",
			denied:     []string{"Apache-2.0"},
			wantRule:   "denied-license",
		},
		{
			name:       "nested expression is denied at any depth",
			expression: "(MIT OR Apache-2.0) AND (BSD-3-Clause OR ISC)",
			denied:     []string{"ISC"},
			wantRule:   "denied-license",
		},
		{
			name:       "unrelated deny entry does not reject expression",
			expression: "(MIT OR Apache-2.0) AND BSD-3-Clause",
			denied:     []string{"GPL-3.0-only"},
		},
		{
			name:       "base deny does not erase an SPDX exception",
			expression: "GPL-2.0-only WITH Classpath-exception-2.0",
			denied:     []string{"GPL-2.0-only"},
		},
		{
			name:       "exact exception expression can be denied",
			expression: "GPL-2.0-only WITH Classpath-exception-2.0",
			denied:     []string{"GPL-2.0-only WITH Classpath-exception-2.0"},
			wantRule:   "denied-license",
		},
		{
			name:       "license reference can be denied",
			expression: "MIT OR LicenseRef-Restricted",
			denied:     []string{"LicenseRef-Restricted"},
			wantRule:   "denied-license",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := auditLicenseExpressions(t, Auditor{DenyLicenses: test.denied}, test.expression)
			assertLicenseRule(t, findings, test.wantRule)
		})
	}
}

func TestLicenseAuditorInvalidSPDXExpressionMatrix(t *testing.T) {
	tests := []struct {
		name        string
		expressions []string
	}{
		{name: "unknown identifier", expressions: []string{"Definitely-Not-SPDX"}},
		{name: "misspelled identifier in AND", expressions: []string{"MIT AND Apche-2.0"}},
		{name: "missing right AND operand", expressions: []string{"MIT AND"}},
		{name: "missing left OR operand", expressions: []string{"OR MIT"}},
		{name: "unbalanced opening parenthesis", expressions: []string{"(MIT OR Apache-2.0"}},
		{name: "unbalanced closing parenthesis", expressions: []string{"MIT OR Apache-2.0)"}},
		{name: "empty nested branch", expressions: []string{"MIT AND (Apache-2.0 OR)"}},
		{name: "duplicated operator", expressions: []string{"MIT OR OR Apache-2.0"}},
		{name: "lowercase operator is invalid SPDX syntax", expressions: []string{"MIT and Apache-2.0"}},
		{name: "unsupported symbolic operator", expressions: []string{"MIT && Apache-2.0"}},
		{name: "unsupported separator", expressions: []string{"MIT / Apache-2.0"}},
		{name: "unknown exception", expressions: []string{"GPL-2.0-only WITH Not-An-Exception"}},
		{name: "duplicated WITH clause", expressions: []string{"GPL-2.0-only WITH Classpath-exception-2.0 WITH LLVM-exception"}},
		{name: "incomplete license reference", expressions: []string{"LicenseRef-"}},
		{name: "invalid document reference target", expressions: []string{"DocumentRef-supplier:MIT"}},
		{name: "URL is not an SPDX expression", expressions: []string{"https://example.test/license"}},
		{name: "NOASSERTION is not a license expression", expressions: []string{"NOASSERTION"}},
		{name: "NONE is not a license expression", expressions: []string{"NONE"}},
		{name: "valid and invalid records together", expressions: []string{"MIT", "Apache-2.0 OR Nope-1.0"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policies := []struct {
				name    string
				auditor Auditor
			}{
				{name: "without allow or deny policy"},
				{name: "with allow policy", auditor: Auditor{
					AllowLicenses: []string{"MIT", "Apache-2.0", "GPL-2.0-only"},
				}},
				{name: "with unrelated deny policy", auditor: Auditor{
					DenyLicenses: []string{"AGPL-3.0-only"},
				}},
			}
			for _, policy := range policies {
				t.Run(policy.name, func(t *testing.T) {
					findings := auditLicenseExpressions(t, policy.auditor, test.expressions...)
					if len(findings) != 1 {
						t.Fatalf("findings = %#v, want one invalid-license finding", findings)
					}
					finding := findings[0]
					if finding.RuleID != "invalid-license" ||
						finding.PolicyStatus != sdk.FindingPolicyStatusFail ||
						finding.Severity != sdk.SeverityWarning ||
						!strings.Contains(finding.Title, "invalid SPDX license") {
						t.Fatalf("invalid expression finding = %#v", finding)
					}
				})
			}
		})
	}
}

func TestLicenseAuditorExemptionIsPackageSpecificAndVersionAgnostic(t *testing.T) {
	graph := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "app", Version: "1.0.0", Type: sdk.PackageTypeApplication,
	}})
	root.FirstParty = true
	exempt := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "exempt", Version: "2.0.0",
	}})
	blocked := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "blocked", Version: "1.0.0",
	}})
	registry := sdk.NewPackageRegistry()
	for _, dependency := range []*sdk.Dependency{root, exempt, blocked} {
		dependency.PackageRef = sdk.CanonicalPackageURLFromDependency(dependency)
		if err := graph.AddNode(dependency); err != nil {
			t.Fatal(err)
		}
		if dependency != root {
			if err := graph.AddEdge(root.ID, dependency.ID); err != nil {
				t.Fatal(err)
			}
			registry.Ensure(dependency.PackageRef).Licenses = []sdk.PackageLicense{{SPDXExpression: "GPL-3.0-only"}}
		}
	}

	result, err := (Auditor{
		DenyLicenses:   []string{"GPL-3.0-only"},
		ExemptPackages: []string{"pkg:npm/exempt@1.0.0"},
	}).Audit(context.Background(), sdk.AuditRequest{Graph: graph, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].PackageRef != blocked.PackageRef {
		t.Fatalf("package exemption findings = %#v", result.Findings)
	}
}

func auditLicenseExpressions(t *testing.T, auditor Auditor, expressions ...string) []sdk.Finding {
	t.Helper()
	graph := sdk.New()
	root := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "app", Version: "1.0.0", Type: sdk.PackageTypeApplication,
	}})
	root.FirstParty = true
	dependency := sdk.NewDependency(sdk.Dependency{Coordinates: sdk.Coordinates{
		Ecosystem: sdk.EcosystemNPM, Name: "library", Version: "1.0.0",
	}})
	dependency.PackageRef = sdk.CanonicalPackageURLFromDependency(dependency)
	if err := graph.AddNode(root); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddNode(dependency); err != nil {
		t.Fatal(err)
	}
	if err := graph.AddEdge(root.ID, dependency.ID); err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewPackageRegistry()
	pkg := registry.Ensure(dependency.PackageRef)
	for _, expression := range expressions {
		pkg.Licenses = append(pkg.Licenses, sdk.PackageLicense{SPDXExpression: expression})
	}
	result, err := auditor.Audit(context.Background(), sdk.AuditRequest{Graph: graph, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	return result.Findings
}

func assertLicenseRule(t *testing.T, findings []sdk.Finding, wantRule string) {
	t.Helper()
	if wantRule == "" {
		if len(findings) != 0 {
			t.Fatalf("findings = %#v, want none", findings)
		}
		return
	}
	if len(findings) != 1 || findings[0].RuleID != wantRule {
		t.Fatalf("findings = %#v, want one %q finding", findings, wantRule)
	}
}
