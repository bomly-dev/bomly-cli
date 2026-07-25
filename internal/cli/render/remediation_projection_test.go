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
					OverrideAdvice:               `add "overrides": {"example": "9.9.9"} to package.json`,
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
	textValue := text.String()
	for _, want := range []string{
		"1 fix suggestion for 1 of 1 vulnerable package",
		"Run again with --format json to see remediation details",
	} {
		if !strings.Contains(textValue, want) {
			t.Fatalf("text remediation summary missing %q:\n%s", want, textValue)
		}
	}
	for _, unwanted := range []string{"Direct bump", "9.9.9", "package-lock.json"} {
		if strings.Contains(textValue, unwanted) {
			t.Fatalf("text remediation summary included detail %q:\n%s", unwanted, textValue)
		}
	}
	if vulnerabilityIndex, remediationIndex := strings.Index(strings.ToLower(textValue), "vulnerabilities"), strings.Index(strings.ToLower(textValue), "fix suggestion"); vulnerabilityIndex < 0 || remediationIndex <= vulnerabilityIndex {
		t.Fatalf("text remediation summary must follow vulnerabilities:\n%s", textValue)
	}

	markdownValue := markdown.String()
	for _, want := range []string{
		"## Remediation",
		"1 fix suggestion for 1 of 1 vulnerable package",
		"9.9.9",
		"Direct bump",
		"example@1.0.0",
		"package-lock.json",
		`add "overrides": {"example": "9.9.9"} to package.json`,
	} {
		if !strings.Contains(markdownValue, want) {
			t.Fatalf("Markdown remediation output missing %q:\n%s", want, markdownValue)
		}
	}
	if strings.Contains(markdownValue, "&#34;") {
		t.Fatalf("Markdown remediation advice encoded quotes:\n%s", markdownValue)
	}
}

func TestScanTextSummaryFollowsEnrichmentAndMarkdownShowsDetails(t *testing.T) {
	const purl = "pkg:npm/example@1.0.0"
	registry := sdk.NewPackageRegistry()
	registry.Add(remediationTestPackage(purl))
	graph := sdk.New()
	if err := graph.AddNode(sdk.NewDependencyRefWithID("project", "project", "")); err != nil {
		t.Fatalf("AddNode(project) error = %v", err)
	}
	dependency := sdk.NewDependency(sdk.Dependency{
		ID:           "example@1.0.0",
		Coordinates:  sdk.Coordinates{PURL: purl, Name: "example", Version: "1.0.0"},
		Relationship: sdk.DependencyRelationshipDirect,
	})
	if err := graph.AddNode(dependency); err != nil {
		t.Fatalf("AddNode() error = %v", err)
	}
	if err := graph.AddEdge("project", dependency.ID); err != nil {
		t.Fatalf("AddEdge() error = %v", err)
	}

	text := StripANSI(Scan(graph, registry, nil, []sdk.MatcherStats{{
		Name:        "example",
		DisplayName: "Example Matcher",
	}}, true, false, false, nil, nil, nil))
	var markdown bytes.Buffer
	if err := ScanMarkdown(&markdown, output.ScanResponse{
		Packages: output.PackagesFromRegistry(registry),
	}); err != nil {
		t.Fatalf("ScanMarkdown() error = %v", err)
	}
	wantTextBlock := "✓ Enriched via Example Matcher\n\n" +
		"✓ 1 fix suggestion for 1 of 1 vulnerable package.\n" +
		"  Run again with --format json to see remediation details.\n\n"
	if !strings.Contains(text, wantTextBlock) {
		t.Fatalf("text remediation summary is not separated from enrichment:\n%s", text)
	}
	for _, unwanted := range []string{"Direct bump", "package-lock.json", "Recommended version"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("text remediation summary included detail %q:\n%s", unwanted, text)
		}
	}
	for _, want := range []string{
		"## Remediation",
		"1 fix suggestion for 1 of 1 vulnerable package",
		"example@1.0.0",
		"Direct bump",
	} {
		if !strings.Contains(markdown.String(), want) {
			t.Fatalf("Markdown remediation output missing %q:\n%s", want, markdown.String())
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
	for _, want := range []string{
		"1 fix suggestion for 1 of 1 vulnerable package",
		"Run again with --format json to see remediation details",
	} {
		if !strings.Contains(text.String(), want) {
			t.Fatalf("text remediation output missing %q:\n%s", want, text.String())
		}
	}
	if strings.Contains(text.String(), "example@1.0.0") {
		t.Fatalf("text remediation output included suggestion rows:\n%s", text.String())
	}
	for _, want := range []string{
		"## Remediation",
		"1 fix suggestion for 1 of 1 vulnerable package",
		"example@1.0.0",
	} {
		if !strings.Contains(markdown.String(), want) {
			t.Fatalf("Markdown remediation output missing %q:\n%s", want, markdown.String())
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

func TestRemediationTextSummarizesAllSuggestionsAndPointsToJSON(t *testing.T) {
	pkg := output.PackagesFromRegistry(func() *sdk.PackageRegistry {
		registry := sdk.NewPackageRegistry()
		value := remediationTestPackage("pkg:npm/example@1.0.0")
		value.Remediation.Suggestions = make([]sdk.PackageRemediationSuggestion, 22)
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
		"22 fix suggestions for 1 of 1 vulnerable package",
		"Run again with --format json to see remediation details",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("remediation text missing %q:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"Direct bump", "package-lock.json", "example@1.0.0"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("remediation text included suggestion detail %q:\n%s", unwanted, text)
		}
	}
}

func TestRemediationSummaryCountsOnlyConcreteFixSuggestions(t *testing.T) {
	packages := []output.ScanPackageEntry{
		remediationReportEntry(
			"complete",
			sdk.PackageRemediationComplete,
			sdk.RemediationActionDirectBump,
		),
		remediationReportEntry(
			"partial",
			sdk.PackageRemediationPartial,
			sdk.RemediationActionManualReview,
		),
		remediationReportEntry(
			"unavailable",
			sdk.PackageRemediationUnavailable,
			sdk.RemediationActionNoFixUpstream,
		),
		remediationReportEntry(
			"unknown",
			sdk.PackageRemediationUnknown,
			sdk.RemediationActionManualReview,
		),
	}

	text := StripANSI(remediationText(packages))
	if !strings.Contains(text, "1 fix suggestion for 1 of 4 vulnerable packages") {
		t.Fatalf("text summary counted non-fix guidance:\n%s", text)
	}

	markdown := strings.Join(remediationMarkdown(packages), "\n")
	for _, want := range []string{
		"1 fix suggestion for 1 of 4 vulnerable packages",
		"Complete fix available",
		"Partial fix available",
		"No fix available",
		"Fix availability unknown",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("Markdown remediation missing %q:\n%s", want, markdown)
		}
	}

	nonFixText := StripANSI(remediationText(packages[1:]))
	if !strings.Contains(nonFixText, "No fix suggestions available for 3 vulnerable packages") {
		t.Fatalf("non-fix summary is misleading:\n%s", nonFixText)
	}
	if strings.Contains(nonFixText, "✓") {
		t.Fatalf("non-fix summary used a success mark:\n%s", nonFixText)
	}
}

func remediationReportEntry(
	name string,
	status sdk.PackageRemediationStatus,
	action sdk.RemediationAction,
) output.ScanPackageEntry {
	return output.ScanPackageEntry{
		Purl:            "pkg:npm/" + name + "@1.0.0",
		Name:            name,
		Version:         "1.0.0",
		Vulnerabilities: []output.VulnerabilityRef{{ID: "GHSA-" + name}},
		Remediation: &sdk.PackageRemediation{
			Status: status,
			Suggestions: []sdk.PackageRemediationSuggestion{{
				AffectedDependencyRefs: []string{name + "@1.0.0"},
				Action:                 action,
			}},
		},
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
