package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestExplainTextAndMarkdownDoNotAddRemediationSections(t *testing.T) {
	target := output.ExplainTargetResponse{
		Dependency: output.ExplainDependency{
			PackageRef: output.PackageRef{
				Name:            "example",
				Version:         "1.0.0",
				Purl:            "pkg:npm/example@1.0.0",
				Licenses:        []output.LicenseRef{},
				Vulnerabilities: []output.VulnerabilityRef{},
			},
			Remediation: &sdk.PackageRemediation{
				Status:             sdk.PackageRemediationComplete,
				RecommendedVersion: "9.9.9",
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
		lower := strings.ToLower(value)
		if strings.Contains(lower, "remediation") || strings.Contains(value, "9.9.9") {
			t.Fatalf("%s added remediation output:\n%s", name, value)
		}
	}
}
