package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

// ScorecardHeadline renders a one-line summary suitable for a
// "Project posture: …" prefix. Example:
//
//	"8.2/10  github.com/ossf/scorecard  (updated 2026-04-12, scorecard v5.0.0)"
//
// Returns "" when card is nil so callers can branch cleanly.
func ScorecardHeadline(card *sdk.PackageScorecard) string {
	if card == nil {
		return ""
	}
	score := scorecardAggregateScore(card.AggregateScore)
	parts := []string{score}
	if card.Repository != "" {
		parts = append(parts, card.Repository)
	}
	meta := scorecardHeadlineMeta(card)
	if meta != "" {
		parts = append(parts, "("+meta+")")
	}
	return strings.Join(parts, "  ")
}

func explainScorecardHeadline(card *sdk.PackageScorecard) string {
	return ScorecardHeadline(card)
}

// scorecardAggregateScore renders the overall numeric score, treating
// negative values as inconclusive runs the way Scorecard itself does.
func scorecardAggregateScore(score float64) string {
	if score < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f/10", score)
}

func scorecardHeadlineMeta(card *sdk.PackageScorecard) string {
	parts := make([]string, 0, 2)
	if !card.RunDate.IsZero() {
		parts = append(parts, "updated "+card.RunDate.UTC().Format("2006-01-02"))
	}
	if card.ScorecardVersion != "" {
		parts = append(parts, "scorecard "+card.ScorecardVersion)
	}
	return strings.Join(parts, ", ")
}

// topScorecardChecks returns up to max checks, lowest score first so the
// most actionable failures bubble to the top. Inconclusive checks
// (score == -1) sort to the end.
func topScorecardChecks(checks []sdk.PackageScorecardCheck, max int) []sdk.PackageScorecardCheck {
	if len(checks) == 0 || max <= 0 {
		return nil
	}
	out := make([]sdk.PackageScorecardCheck, len(checks))
	copy(out, checks)
	sort.SliceStable(out, func(i, j int) bool {
		left := normalizedScorecardScore(out[i].Score)
		right := normalizedScorecardScore(out[j].Score)
		if left != right {
			return left < right
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// normalizedScorecardScore maps "inconclusive" (-1) to a sentinel that sorts
// after every 0–10 score, so failing/low-scoring checks appear first in any
// "top issues" list.
func normalizedScorecardScore(score int) int {
	if score < 0 {
		return 11
	}
	return score
}

// scorecardCheckBadge returns a short label that mirrors the severity-style
// brackets the rest of the renderer uses, so checks line up visually with
// vulnerability findings.
func scorecardCheckBadge(score int) string {
	switch {
	case score < 0:
		return "[ ? ]"
	case score <= 2:
		return "[!!!]"
	case score <= 5:
		return "[!! ]"
	case score <= 8:
		return "[!  ]"
	default:
		return "[ok ]"
	}
}

func explainScorecardCheckScore(score int) string {
	if score < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d", score)
}

// explainScorecardCheckLine renders the human-readable portion of a single
// check row: the check name, then its reason if present.
func explainScorecardCheckLine(check sdk.PackageScorecardCheck) string {
	name := strings.TrimSpace(check.Name)
	reason := strings.TrimSpace(check.Reason)
	switch {
	case name == "" && reason == "":
		return "(no detail)"
	case name == "":
		return reason
	case reason == "":
		return name
	default:
		return name + ": " + reason
	}
}
