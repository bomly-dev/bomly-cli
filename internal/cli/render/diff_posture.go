package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// postureTextSections renders the per-repository Scorecard delta between
// the diff's base and head sides. The data lives on PackageRef.Scorecard
// for added, removed, and changed packages — we aggregate by repository so
// a monorepo whose dozens of packages share one Scorecard run shows up as
// one row, not dozens.
//
// Returns nil when no package in the diff carries Scorecard data, so the
// caller can skip the section header entirely (no empty "Project Posture"
// block).
func postureTextSections(results output.DiffDependencyResults) []string {
	delta := buildPostureDelta(results)
	if delta.isEmpty() {
		return nil
	}
	lines := []string{
		"Project Posture",
		fmt.Sprintf(
			"  Repositories: %d introduced, %d dropped, %d score change(s)",
			len(delta.Added),
			len(delta.Removed),
			len(delta.Changed),
		),
	}
	if len(delta.Added) > 0 {
		lines = append(lines, fmt.Sprintf("Added (%d)", len(delta.Added)))
		for _, row := range delta.Added {
			lines = append(lines, Wrap(fmt.Sprintf("  + %s  %s",
				scorecardAggregateScore(row.AfterScore),
				row.Repository,
			), Green))
		}
	}
	if len(delta.Removed) > 0 {
		lines = append(lines, fmt.Sprintf("Removed (%d)", len(delta.Removed)))
		for _, row := range delta.Removed {
			lines = append(lines, Wrap(fmt.Sprintf("  - %s  %s",
				scorecardAggregateScore(row.BeforeScore),
				row.Repository,
			), Red))
		}
	}
	if len(delta.Changed) > 0 {
		lines = append(lines, fmt.Sprintf("Changed (%d)", len(delta.Changed)))
		for _, row := range delta.Changed {
			arrow := fmt.Sprintf("%s -> %s",
				scorecardAggregateScore(row.BeforeScore),
				scorecardAggregateScore(row.AfterScore),
			)
			color := Yellow
			if row.AfterScore > row.BeforeScore && row.BeforeScore >= 0 && row.AfterScore >= 0 {
				color = Green
			} else if row.AfterScore < row.BeforeScore && row.BeforeScore >= 0 && row.AfterScore >= 0 {
				color = Red
			}
			lines = append(lines, Wrap(fmt.Sprintf("  ~ %s  %s", arrow, row.Repository), color))
		}
	}
	return append(lines, "")
}

// postureDelta holds the de-duped per-repository score state computed from
// the diff payload's package-level Scorecard annotations.
type postureDelta struct {
	Added   []postureRow
	Removed []postureRow
	Changed []postureRow
}

func (d postureDelta) isEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

type postureRow struct {
	Repository  string
	BeforeScore float64
	AfterScore  float64
}

// buildPostureDelta groups the diff's package-level Scorecard annotations
// by repository and classifies each repo as Added / Removed / Changed.
//
// "Changed" is detected when the same repository appears on both sides of a
// version-changed package and the score moved. A repository present only in
// Added packages with no matching Removed-side counterpart is "Added"; the
// mirror case is "Removed".
func buildPostureDelta(results output.DiffDependencyResults) postureDelta {
	type sides struct {
		before *sdk.PackageScorecard
		after  *sdk.PackageScorecard
	}
	byRepo := make(map[string]*sides)

	record := func(repo string, before, after *sdk.PackageScorecard) {
		if repo == "" {
			return
		}
		entry, ok := byRepo[repo]
		if !ok {
			entry = &sides{}
			byRepo[repo] = entry
		}
		if before != nil && entry.before == nil {
			entry.before = before
		}
		if after != nil && entry.after == nil {
			entry.after = after
		}
	}

	for _, change := range results.Added {
		if card := change.Package.Scorecard; card != nil {
			record(card.Repository, nil, card)
		}
	}
	for _, change := range results.Removed {
		if card := change.Package.Scorecard; card != nil {
			record(card.Repository, card, nil)
		}
	}
	for _, change := range results.Changed {
		if card := change.Before.Scorecard; card != nil {
			record(card.Repository, card, nil)
		}
		if card := change.After.Scorecard; card != nil {
			record(card.Repository, nil, card)
		}
	}

	var delta postureDelta
	for repo, entry := range byRepo {
		switch {
		case entry.before == nil && entry.after != nil:
			delta.Added = append(delta.Added, postureRow{
				Repository: repo,
				AfterScore: entry.after.AggregateScore,
			})
		case entry.before != nil && entry.after == nil:
			delta.Removed = append(delta.Removed, postureRow{
				Repository:  repo,
				BeforeScore: entry.before.AggregateScore,
			})
		case entry.before != nil && entry.after != nil:
			if scoresDifferMeaningfully(entry.before.AggregateScore, entry.after.AggregateScore) {
				delta.Changed = append(delta.Changed, postureRow{
					Repository:  repo,
					BeforeScore: entry.before.AggregateScore,
					AfterScore:  entry.after.AggregateScore,
				})
			}
		}
	}

	sort.Slice(delta.Added, func(i, j int) bool {
		if delta.Added[i].AfterScore != delta.Added[j].AfterScore {
			return delta.Added[i].AfterScore < delta.Added[j].AfterScore
		}
		return delta.Added[i].Repository < delta.Added[j].Repository
	})
	sort.Slice(delta.Removed, func(i, j int) bool {
		if delta.Removed[i].BeforeScore != delta.Removed[j].BeforeScore {
			return delta.Removed[i].BeforeScore < delta.Removed[j].BeforeScore
		}
		return delta.Removed[i].Repository < delta.Removed[j].Repository
	})
	sort.Slice(delta.Changed, func(i, j int) bool {
		di := delta.Changed[i].AfterScore - delta.Changed[i].BeforeScore
		dj := delta.Changed[j].AfterScore - delta.Changed[j].BeforeScore
		if di != dj {
			return di < dj // biggest regressions first
		}
		return delta.Changed[i].Repository < delta.Changed[j].Repository
	})
	return delta
}

// scoresDifferMeaningfully returns true when before / after differ by at
// least 0.1 — enough to surface above noise but below the precision we
// already render at (.1/10).
func scoresDifferMeaningfully(before, after float64) bool {
	diff := after - before
	if diff < 0 {
		diff = -diff
	}
	return diff >= 0.1 || nonZeroSign(before) != nonZeroSign(after)
}

// nonZeroSign collapses {<0, 0, >0} so a transition between "scored" and
// "inconclusive" still counts as a meaningful change.
func nonZeroSign(score float64) int {
	switch {
	case score < 0:
		return -1
	case score > 0:
		return 1
	default:
		return 0
	}
}

// diffPostureMarkdown renders the same per-repository delta as
// postureTextSections but as the Markdown report's "Project Posture"
// section. Returns a single line when there is no scorecard data on either
// side, so the section header still appears (matching the convention used
// by diffVulnerabilityMarkdown / diffLicenseMarkdown).
func diffPostureMarkdown(payload output.DiffResponse) []string {
	delta := buildPostureDelta(payload.Results.Dependencies)
	if delta.isEmpty() {
		return []string{"✅ No project posture changes (or `--matchers +scorecard` was not selected)."}
	}
	lines := []string{
		fmt.Sprintf(
			"**Summary:** %d introduced, %d dropped, %d score change(s).",
			len(delta.Added),
			len(delta.Removed),
			len(delta.Changed),
		),
		"",
	}
	appendRows := func(title string, rows []postureRow, beforeCol, afterCol string) {
		if len(rows) == 0 {
			return
		}
		table := make([][]string, 0, len(rows))
		for _, row := range rows {
			table = append(table, []string{
				row.Repository,
				valueOrDash(formatPostureCell(row.BeforeScore, beforeCol == "")),
				valueOrDash(formatPostureCell(row.AfterScore, afterCol == "")),
				formatPostureDelta(row.BeforeScore, row.AfterScore),
			})
		}
		header := []string{"Repository", "Before", "After", "Δ"}
		lines = append(lines, "### "+title, "")
		lines = append(lines, markdownTable(header, table)...)
		lines = append(lines, "")
	}
	appendRows("Introduced Repositories", delta.Added, "", "after")
	appendRows("Dropped Repositories", delta.Removed, "before", "")
	appendRows("Score Changes", delta.Changed, "before", "after")
	return trimTrailingMarkdownBlanks(lines)
}

// formatPostureCell renders a score with the diff payload's "—" convention
// for absent sides. The skip flag tells the caller this column doesn't
// apply for this row category (e.g. "Before" on an Introduced row).
func formatPostureCell(score float64, skip bool) string {
	if skip {
		return ""
	}
	return scorecardAggregateScore(score)
}

// formatPostureDelta renders a signed Δ for the Changed table. Inconclusive
// sides collapse to "n/a → n.n" semantics instead of a number.
func formatPostureDelta(before, after float64) string {
	switch {
	case before < 0 && after >= 0:
		return "newly scored"
	case before >= 0 && after < 0:
		return "now inconclusive"
	case before < 0 && after < 0:
		return "—"
	}
	diff := after - before
	switch {
	case diff > 0:
		return strings.TrimSpace(fmt.Sprintf("+%.1f", diff))
	case diff < 0:
		return strings.TrimSpace(fmt.Sprintf("%.1f", diff))
	default:
		return "0"
	}
}
