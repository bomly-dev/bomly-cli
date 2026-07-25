package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestExplainTextAndMarkdownShowRemediationAfterVulnerabilities(t *testing.T) {
	target := output.ExplainTargetResponse{
		Dependency: output.ExplainDependency{
			PackageRef: output.PackageRef{
				Name:     "example",
				Version:  "1.0.0",
				Purl:     "pkg:npm/example@1.0.0",
				Licenses: []output.LicenseRef{},
				Vulnerabilities: []output.VulnerabilityRef{{
					ID:       "GHSA-example",
					Severity: sdk.SeverityHigh,
				}},
			},
			Remediation: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "9.9.9",
				Suggestions: []sdk.PackageRemediationSuggestion{{
					AffectedDependencyRefs:       []string{"example@1.0.0"},
					SuggestedActionDependencyRef: "example@1.0.0",
					ManifestPath:                 "package-lock.json",
					Action:                       sdk.RemediationActionDirectBump,
				}},
			},
		},
	}

	var text bytes.Buffer
	if err := Explain(&text, target); err != nil {
		t.Fatalf("Explain() error = %v", err)
	}
	var markdown bytes.Buffer
	if err := ExplainMarkdown(&markdown, output.ExplainResponse{
		Query:   output.ExplainQuery{Name: "example"},
		Targets: []output.ExplainTargetResponse{target},
	}); err != nil {
		t.Fatalf("ExplainMarkdown() error = %v", err)
	}
	for name, value := range map[string]string{
		"text":     text.String(),
		"markdown": markdown.String(),
	} {
		for _, want := range []string{
			"Remediation",
			"1 remediation suggestion for 1 of 1 vulnerable package",
			"9.9.9",
			"Direct bump",
			"example@1.0.0",
			"package-lock.json",
		} {
			if !strings.Contains(value, want) {
				t.Fatalf("%s remediation output missing %q:\n%s", name, want, value)
			}
		}
		vulnerabilityIndex := strings.Index(strings.ToLower(value), "vulnerabilities")
		remediationIndex := strings.Index(strings.ToLower(value), "remediation")
		if vulnerabilityIndex < 0 || remediationIndex <= vulnerabilityIndex {
			t.Fatalf("%s remediation must follow vulnerabilities:\n%s", name, value)
		}
	}
}

func TestScanTextAndMarkdownShowRemediationAfterFindings(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	registry := sdk.NewPackageRegistry()
	registry.Add(remediationTestPackage(purl))
	graph := sdk.New()
	if err := graph.AddNode(&sdk.Dependency{
		ID:          "example@1.0.0",
		Coordinates: sdk.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
	}); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}

	text := Scan(graph, registry, nil, nil, true, false, false, nil, nil, nil)
	var markdown bytes.Buffer
	if err := ScanMarkdown(&markdown, output.ScanResponse{
		Packages: output.PackagesFromRegistry(registry),
	}); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	for name, value := range map[string]string{
		"text":     text,
		"markdown": markdown.String(),
	} {
		for _, want := range []string{
			"Remediation",
			"1 remediation suggestion for 1 of 1 vulnerable package",
			"example@1.0.0",
			"Direct bump",
		} {
			if !strings.Contains(value, want) {
				t.Fatalf("%s remediation output missing %q:\n%s", name, want, value)
			}
		}
	}
	if policyIndex, remediationIndex := strings.Index(markdown.String(), "## Policy Findings"), strings.Index(markdown.String(), "## Remediation"); policyIndex < 0 || remediationIndex <= policyIndex {
		t.Fatalf("Markdown remediation must follow findings:\n%s", markdown.String())
	}
}

func TestDiffTextAndMarkdownShowHeadRemediationAfterFindings(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	pkg := remediationTestPackage(purl)
	payload := output.DiffResponse{
		Packages: output.PackagesFromRegistry(func() *sdk.PackageRegistry {
			registry := sdk.NewPackageRegistry()
			registry.Add(pkg)
			return registry
		}()),
		Results: output.DiffResults{
			Vulnerabilities: output.DiffVulnerabilityResults{
				Added: []output.DiffVulnerabilityChange{{
					Package:       output.PackageRef{Purl: purl},
					Vulnerability: output.VulnerabilityRef{ID: "GHSA-example"},
				}},
			},
		},
	}
	var text bytes.Buffer
	if err := Diff(&text, payload); err != nil {
		t.Fatalf("Diff() error = %v", err)
	}
	var markdown bytes.Buffer
	if err := DiffMarkdown(&markdown, payload); err != nil {
		t.Fatalf("DiffMarkdown() error = %v", err)
	}
	for name, value := range map[string]string{
		"text":     text.String(),
		"markdown": markdown.String(),
	} {
		for _, want := range []string{
			"Remediation",
			"1 remediation suggestion for 1 of 1 vulnerable package",
			"example@1.0.0",
		} {
			if !strings.Contains(value, want) {
				t.Fatalf("%s remediation output missing %q:\n%s", name, want, value)
			}
		}
	}
	if policyIndex, remediationIndex := strings.Index(markdown.String(), "## Policy Findings"), strings.Index(markdown.String(), "## Remediation"); policyIndex < 0 || remediationIndex <= policyIndex {
		t.Fatalf("Markdown remediation must follow findings:\n%s", markdown.String())
	}
}

func TestRemediationOutputIsOmittedWithoutSuggestions(t *testing.T) {
	var markdown bytes.Buffer
	if err := ScanMarkdown(&markdown, output.ScanResponse{
		Packages: []output.ScanPackageEntry{{
			Purl:            "pkg:npm/example@1.0.0",
			Vulnerabilities: []output.VulnerabilityRef{{ID: "GHSA-example"}},
			Remediation:     &sdk.PackageRemediation{Status: sdk.PackageRemediationUnknown},
		}},
	}); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	if strings.Contains(markdown.String(), "## Remediation") {
		t.Fatalf("Markdown added an empty remediation section:\n%s", markdown.String())
	}
}

func TestRemediationTextCapsTableAndPointsToJSON(t *testing.T) {
	pkg := output.PackagesFromRegistry(func() *sdk.PackageRegistry {
		registry := sdk.NewPackageRegistry()
		value := remediationTestPackage("pkg:npm/example@1.0.0")
		value.Remediation.Suggestions = make([]sdk.PackageRemediationSuggestion, maxTextRemediationSuggestions+2)
		for idx := range value.Remediation.Suggestions {
			value.Remediation.Suggestions[idx] = sdk.PackageRemediationSuggestion{
				AffectedDependencyRefs:       []string{"example@1.0.0"},
				SuggestedActionDependencyRef: "example@1.0.0",
				ManifestPath:                 "package-lock.json",
				Action:                       sdk.RemediationActionDirectBump,
			}
		}
		registry.Add(value)
		return registry
	}())

	text := remediationText(pkg)
	for _, want := range []string{
		"22 remediation suggestions for 1 of 1 vulnerable package",
		"2 more suggestions are not shown",
		"Run again with --format json to see every suggestion",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("remediation text missing %q:\n%s", want, text)
		}
	}
}

func remediationTestPackage(purl string) *sdk.Package {
	return &sdk.Package{
		Coordinates: sdk.Coordinates{
			PURL:    purl,
			Name:    "example",
			Version: "1.0.0",
		},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:             "GHSA-example",
			ParsedSeverity: sdk.SeverityHigh,
		}},
		Remediation: &sdk.PackageRemediation{
			Status:             sdk.PackageRemediationComplete,
			RecommendedVersion: "1.2.0",
			Suggestions: []sdk.PackageRemediationSuggestion{{
				AffectedDependencyRefs:       []string{"example@1.0.0"},
				SuggestedActionDependencyRef: "example@1.0.0",
				ManifestPath:                 "package-lock.json",
				Action:                       sdk.RemediationActionDirectBump,
			}},
		},
	}
}
