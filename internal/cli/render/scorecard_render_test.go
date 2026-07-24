package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func newTestScorecard(repo string, score float64, checks ...sdk.PackageScorecardCheck) *sdk.PackageScorecard {
	return &sdk.PackageScorecard{
		Source:           "api.scorecard.dev",
		Repository:       repo,
		CommitSHA:        "abc123",
		ScorecardVersion: "v5.0.0",
		RunDate:          time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC),
		AggregateScore:   score,
		Checks:           checks,
	}
}

func TestExplain_OmitsScorecardFromCompactText(t *testing.T) {
	t.Parallel()
	// The compact text format does not include scorecard blocks; that detail
	// is available in JSON and Markdown output formats.
	target := output.ExplainTargetResponse{
		Dependency: output.ExplainDependency{PackageRef: output.PackageRef{
			Name:    "logrus",
			Version: "v1.9.0",
			Scorecard: newTestScorecard("github.com/sirupsen/logrus", 8.2,
				sdk.PackageScorecardCheck{Name: "Branch-Protection", Score: 9, Reason: "branch protection enabled"},
				sdk.PackageScorecardCheck{Name: "Code-Review", Score: 2, Reason: "missing reviews"},
			),
		}},
	}
	var buf bytes.Buffer
	if err := Explain(&buf, target); err != nil {
		t.Fatalf("Explain: %v", err)
	}
	out := StripANSI(buf.String())
	if strings.Contains(out, "Project posture:") {
		t.Errorf("compact explain text should not include scorecard block; got:\n%s", out)
	}
	// Package metadata (name/version) still appears.
	if !strings.Contains(out, "logrus@v1.9.0") {
		t.Errorf("expected package name in explain output; got:\n%s", out)
	}
}

func TestExplain_OmitsScorecardWhenNil(t *testing.T) {
	t.Parallel()
	target := output.ExplainTargetResponse{
		Dependency: output.ExplainDependency{PackageRef: output.PackageRef{Name: "logrus", Version: "v1.9.0"}},
	}
	var buf bytes.Buffer
	if err := Explain(&buf, target); err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if strings.Contains(StripANSI(buf.String()), "Project posture") {
		t.Errorf("expected no posture block when Scorecard is nil; got:\n%s", buf.String())
	}
}

func TestBuildPostureDelta_Classifies(t *testing.T) {
	t.Parallel()
	results := output.DiffDependencyResults{
		Added: []output.DiffPackageChange{
			{Package: output.PackageRef{Scorecard: newTestScorecard("github.com/new/repo", 7.5)}},
		},
		Removed: []output.DiffPackageChange{
			{Package: output.PackageRef{Scorecard: newTestScorecard("github.com/old/repo", 4.0)}},
		},
		Changed: []output.DiffChangedPackage{
			{
				Before: output.PackageRef{Scorecard: newTestScorecard("github.com/shared/repo", 6.0)},
				After:  output.PackageRef{Scorecard: newTestScorecard("github.com/shared/repo", 8.5)},
			},
			{
				// Same score on both sides → must NOT appear in Changed.
				Before: output.PackageRef{Scorecard: newTestScorecard("github.com/stable/repo", 9.1)},
				After:  output.PackageRef{Scorecard: newTestScorecard("github.com/stable/repo", 9.1)},
			},
		},
	}
	delta := buildPostureDelta(results)
	if len(delta.Added) != 1 || delta.Added[0].Repository != "github.com/new/repo" {
		t.Errorf("Added classification wrong: %+v", delta.Added)
	}
	if len(delta.Removed) != 1 || delta.Removed[0].Repository != "github.com/old/repo" {
		t.Errorf("Removed classification wrong: %+v", delta.Removed)
	}
	if len(delta.Changed) != 1 || delta.Changed[0].Repository != "github.com/shared/repo" {
		t.Errorf("Changed classification wrong: %+v", delta.Changed)
	}
}

func TestBuildPostureDelta_DedupesByRepo(t *testing.T) {
	t.Parallel()
	card := newTestScorecard("github.com/mono/repo", 7.0)
	results := output.DiffDependencyResults{
		Added: []output.DiffPackageChange{
			{Package: output.PackageRef{Name: "a", Scorecard: card}},
			{Package: output.PackageRef{Name: "b", Scorecard: card}},
			{Package: output.PackageRef{Name: "c", Scorecard: card}},
		},
	}
	delta := buildPostureDelta(results)
	if len(delta.Added) != 1 {
		t.Fatalf("expected one row for 3 packages sharing a repo; got %d: %+v", len(delta.Added), delta.Added)
	}
}

func TestDiff_OmitsPostureSectionFromCompactText(t *testing.T) {
	t.Parallel()
	// The compact text format does not include a Project Posture section; that
	// detail is available in the Markdown output format.
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "HEAD"},
		Results: output.DiffResults{
			Dependencies: output.DiffDependencyResults{
				Added: []output.DiffPackageChange{{
					Package: output.PackageRef{Scorecard: newTestScorecard("github.com/new/repo", 7.5)},
				}},
				Changed: []output.DiffChangedPackage{{
					Before: output.PackageRef{Scorecard: newTestScorecard("github.com/shared/repo", 5.0)},
					After:  output.PackageRef{Scorecard: newTestScorecard("github.com/shared/repo", 8.0)},
				}},
			},
		},
	}
	var buf bytes.Buffer
	if err := Diff(&buf, payload); err != nil {
		t.Fatalf("Diff: %v", err)
	}
	out := StripANSI(buf.String())
	if strings.Contains(out, "Project Posture") {
		t.Errorf("compact diff text should not include Project Posture section; got:\n%s", out)
	}
	// Dep changes still appear.
	if !strings.Contains(out, "Added") && !strings.Contains(out, "Changed") {
		t.Errorf("expected dep change sections in compact diff; got:\n%s", out)
	}
}

func TestDiff_OmitsPostureWhenNoScorecardData(t *testing.T) {
	t.Parallel()
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "HEAD"},
		Results: output.DiffResults{
			Dependencies: output.DiffDependencyResults{
				Added: []output.DiffPackageChange{{Package: output.PackageRef{Name: "foo", Version: "1.0"}}},
			},
		},
	}
	var buf bytes.Buffer
	if err := Diff(&buf, payload); err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if strings.Contains(StripANSI(buf.String()), "Project Posture") {
		t.Errorf("expected no Project Posture section when no scorecards; got:\n%s", buf.String())
	}
}

func TestDiffMarkdown_AlwaysIncludesPostureHeader(t *testing.T) {
	t.Parallel()
	payload := output.DiffResponse{
		Comparison: output.DiffComparison{Base: "main", Head: "HEAD"},
		Results: output.DiffResults{
			Dependencies: output.DiffDependencyResults{
				Added: []output.DiffPackageChange{{
					Package: output.PackageRef{Scorecard: newTestScorecard("github.com/new/repo", 7.5)},
				}},
			},
		},
	}
	var buf bytes.Buffer
	if err := DiffMarkdown(&buf, payload); err != nil {
		t.Fatalf("DiffMarkdown: %v", err)
	}
	out := buf.String()
	for _, sub := range []string{
		"## Project Posture",
		"Introduced Repositories",
		"github.com/new/repo",
		"7.5/10",
	} {
		if !strings.Contains(out, sub) {
			t.Errorf("markdown diff missing %q\n---\n%s", sub, out)
		}
	}
}

func TestFormatPostureDelta(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		before, after  float64
		expectContains string
	}{
		{"improvement", 5.0, 8.0, "+3.0"},
		{"regression", 8.0, 5.0, "-3.0"},
		{"newly scored", -1, 7.5, "newly scored"},
		{"now inconclusive", 7.5, -1, "now inconclusive"},
		{"both inconclusive", -1, -1, "—"},
		{"unchanged", 7.5, 7.5, "0"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := formatPostureDelta(tc.before, tc.after)
			if !strings.Contains(got, tc.expectContains) {
				t.Errorf("formatPostureDelta(%v, %v) = %q, want substring %q", tc.before, tc.after, got, tc.expectContains)
			}
		})
	}
}
