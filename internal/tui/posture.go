package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// posturePackageRef is the per-package back-pointer attached to each
// posture row, so the details pane can list which packages a repo's
// Scorecard run covers.
type posturePackageRef struct {
	id          string
	displayName string
	version     string
}

// postureRow aggregates a single source repository's Scorecard run
// alongside the packages that resolved to it. The matcher dedupes by repo
// while attaching `pkg.Scorecard`, so multiple packages can carry the same
// underlying *sdk.PackageScorecard; we collect every distinct package here
// so the details pane can render the affected component list.
type postureRow struct {
	repository string
	card       *sdk.PackageScorecard
	packages   []posturePackageRef
}

// postureRowsFromGraph walks the dependency graph and groups packages by
// their attached Scorecard repository. A row is emitted per unique repo;
// packages with no Scorecard are skipped entirely (matching how the scan
// text report's Project Posture section behaves). Scorecard data lives on
// the PURL-keyed registry; the graph dependencies provide the display
// labels.
func postureRowsFromGraph(graphValue *sdk.Graph, registry *sdk.PackageRegistry) []postureRow {
	if graphValue == nil || registry == nil {
		return nil
	}
	byRepo := make(map[string]*postureRow)
	for _, dep := range graphValue.Nodes() {
		if dep == nil || dep.PURL == "" {
			continue
		}
		pkg, ok := registry.Get(dep.PURL)
		if !ok || pkg == nil || pkg.Scorecard == nil {
			continue
		}
		repo := pkg.Scorecard.Repository
		if repo == "" {
			repo = dep.PURL
		}
		row, ok := byRepo[repo]
		if !ok {
			row = &postureRow{
				repository: repo,
				card:       pkg.Scorecard,
				packages:   make([]posturePackageRef, 0, 1),
			}
			byRepo[repo] = row
		}
		row.packages = append(row.packages, posturePackageRef{
			id:          dep.ID,
			displayName: dep.DisplayName(),
			version:     dep.Version,
		})
	}
	out := make([]postureRow, 0, len(byRepo))
	for _, row := range byRepo {
		sort.Slice(row.packages, func(i, j int) bool {
			if row.packages[i].displayName != row.packages[j].displayName {
				return row.packages[i].displayName < row.packages[j].displayName
			}
			return row.packages[i].id < row.packages[j].id
		})
		out = append(out, *row)
	}
	// Worst score first so failing repos lead the list. Inconclusive scores
	// (< 0) sort to the bottom — they're informational, not actionable.
	sort.Slice(out, func(i, j int) bool {
		li := normalizedPostureScore(out[i].card.AggregateScore)
		lj := normalizedPostureScore(out[j].card.AggregateScore)
		if li != lj {
			return li < lj
		}
		return out[i].repository < out[j].repository
	})
	return out
}

func normalizedPostureScore(score float64) float64 {
	if score < 0 {
		return 11 // sentinel below 0..10 ordering
	}
	return score
}

// postureScoreBand buckets aggregate scores into broad categories so the
// summary panels can show counts and the list rows can pick a color.
func postureScoreBand(score float64) string {
	switch {
	case score < 0:
		return "inconclusive"
	case score < 3:
		return "critical"
	case score < 6:
		return "warning"
	case score < 8:
		return "ok"
	default:
		return "strong"
	}
}

func postureBandColor(band string) string {
	switch band {
	case "critical":
		return render.Red
	case "warning":
		return render.Yellow
	case "ok":
		return render.Cyan
	case "strong":
		return render.Green
	default:
		return render.Dim
	}
}

// postureBandBadgeKind maps a band to a color kind the list renderer
// understands. The list package only knows a fixed vocabulary; we reuse
// the severity-* kinds so colors line up with the rest of the TUI.
func postureBandBadgeKind(band string) string {
	switch band {
	case "critical":
		return "severity-critical"
	case "warning":
		return "severity-high"
	case "ok":
		return "severity-medium"
	case "strong":
		return "severity-low"
	default:
		return "severity-unknown"
	}
}

// postureBandDistribution returns the number of repos in each band, in
// fixed band order so the summary panel reads the same way every render.
func postureBandDistribution(rows []postureRow) []postureBandCount {
	counts := make(map[string]int)
	for _, row := range rows {
		counts[postureScoreBand(row.card.AggregateScore)]++
	}
	bands := []string{"critical", "warning", "ok", "strong", "inconclusive"}
	out := make([]postureBandCount, 0, len(bands))
	for _, band := range bands {
		if counts[band] == 0 {
			continue
		}
		out = append(out, postureBandCount{Band: band, Count: counts[band]})
	}
	return out
}

type postureBandCount struct {
	Band  string
	Count int
}

// postureTopFailingChecks aggregates check failures across every repo and
// returns the most common low-scoring checks, name-keyed. The result feeds
// the summary panel and answers "what is consistently broken across this
// dependency set?".
func postureTopFailingChecks(rows []postureRow, limit int) []postureCheckCount {
	if limit <= 0 {
		return nil
	}
	type counter struct {
		failing int
		total   int
	}
	byCheck := make(map[string]*counter)
	for _, row := range rows {
		for _, check := range row.card.Checks {
			name := strings.TrimSpace(check.Name)
			if name == "" {
				continue
			}
			entry, ok := byCheck[name]
			if !ok {
				entry = &counter{}
				byCheck[name] = entry
			}
			entry.total++
			// Treat anything <= 5 as a "failing" outcome — Scorecard's own
			// numeric mapping treats 5 as the warning boundary. Inconclusive
			// (-1) is informational, not failing.
			if check.Score >= 0 && check.Score <= 5 {
				entry.failing++
			}
		}
	}
	out := make([]postureCheckCount, 0, len(byCheck))
	for name, entry := range byCheck {
		if entry.failing == 0 {
			continue
		}
		out = append(out, postureCheckCount{Name: name, Failing: entry.failing, Total: entry.total})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Failing != out[j].Failing {
			return out[i].Failing > out[j].Failing
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

type postureCheckCount struct {
	Name    string
	Failing int
	Total   int
}

// postureSummaryLines is the left summary panel content for the Posture
// tab — overall posture stats in one block so users can size up the
// dependency set at a glance.
func postureSummaryLines(rows []postureRow) []string {
	if len(rows) == 0 {
		return []string{
			render.Style("No Scorecard data attached.", render.Dim),
			render.Style("Run with --matchers +scorecard.", render.Dim),
		}
	}
	bands := postureBandDistribution(rows)
	lines := make([]string, 0, len(bands)+2)
	lines = append(lines, render.Style(fmt.Sprintf("%d repositories scored", len(rows)), render.Cyan, render.Bold))
	avg := postureAverageScore(rows)
	if avg >= 0 {
		lines = append(lines, render.Style("Average: ", render.Dim)+fmt.Sprintf("%.1f/10", avg))
	}
	for _, b := range bands {
		lines = append(lines, render.Style(capitalizeASCII(b.Band)+": ", postureBandColor(b.Band))+fmt.Sprintf("%d", b.Count))
	}
	return lines
}

// postureAverageScore returns the mean aggregate across rows with a valid
// (non-negative) score. Returns -1 when no rows are scored — callers omit
// the line in that case.
func postureAverageScore(rows []postureRow) float64 {
	var sum float64
	count := 0
	for _, row := range rows {
		if row.card.AggregateScore < 0 {
			continue
		}
		sum += row.card.AggregateScore
		count++
	}
	if count == 0 {
		return -1
	}
	return sum / float64(count)
}

// postureTopFailingLines is the right summary panel — "what consistently
// fails?" across the dependency set.
func postureTopFailingLines(rows []postureRow, width int) []string {
	checks := postureTopFailingChecks(rows, 6)
	if len(checks) == 0 {
		return []string{render.Style("No failing checks across scored repos.", render.Dim)}
	}
	if width < 32 {
		width = 32
	}
	baseLabelWidth := width / 2
	if baseLabelWidth < 18 {
		baseLabelWidth = 18
	}
	if baseLabelWidth > 32 {
		baseLabelWidth = 32
	}
	out := make([]string, 0, len(checks))
	maxFail := 0
	for _, c := range checks {
		if c.Failing > maxFail {
			maxFail = c.Failing
		}
	}
	for idx, c := range checks {
		labelWidth := baseLabelWidth
		suffix := fmt.Sprintf(" %d/%d", c.Failing, c.Total)
		barWidth := width - labelWidth - 1 - len(suffix) - 2
		if barWidth < 8 {
			barWidth = 8
			labelWidth = width - barWidth - 1 - len(suffix) - 2
			if labelWidth < 8 {
				labelWidth = 8
				barWidth = width - labelWidth - 1 - len(suffix) - 2
				if barWidth < 1 {
					barWidth = 1
				}
			}
		}
		label := padRight(truncateToWidth(c.Name, labelWidth), labelWidth)
		bar := coloredBarLine(c.Failing, maxFail, barWidth, paletteColor(idx))
		out = append(out, label+render.Style(" ", render.Dim)+bar+suffix)
	}
	return out
}

// postureRowDetails is the right-hand details pane content for a single
// repository row: headline, every check sorted lowest-first, and the
// packages that resolved to this repo.
func postureRowDetails(row postureRow) []string {
	lines := []string{
		render.Style("Repository", render.Bold, render.Cyan),
		"",
		render.Style("  Repository: ", render.Dim) + row.repository,
		render.Style("  Aggregate: ", render.Dim) + posturePrettyScore(row.card.AggregateScore),
	}
	if !row.card.RunDate.IsZero() {
		lines = append(lines, render.Style("  Updated: ", render.Dim)+row.card.RunDate.UTC().Format("2006-01-02"))
	}
	if row.card.ScorecardVersion != "" {
		lines = append(lines, render.Style("  Scorecard version: ", render.Dim)+row.card.ScorecardVersion)
	}
	if row.card.CommitSHA != "" {
		lines = append(lines, render.Style("  Commit: ", render.Dim)+row.card.CommitSHA)
	}

	lines = append(lines, "", render.Style(fmt.Sprintf("Checks (%d)", len(row.card.Checks)), render.Bold, render.Magenta), "")
	checks := make([]sdk.PackageScorecardCheck, len(row.card.Checks))
	copy(checks, row.card.Checks)
	sort.SliceStable(checks, func(i, j int) bool {
		li := normalizedPostureCheckScore(checks[i].Score)
		lj := normalizedPostureCheckScore(checks[j].Score)
		if li != lj {
			return li < lj
		}
		return checks[i].Name < checks[j].Name
	})
	for _, check := range checks {
		band := postureScoreBand(float64(check.Score))
		lines = append(lines, render.Style("  ", render.Dim)+
			render.Style(postureCheckBadge(check.Score), postureBandColor(band))+" "+
			render.Style(posturePrettyCheckScore(check.Score)+"  ", render.Dim)+
			check.Name)
		if reason := strings.TrimSpace(check.Reason); reason != "" {
			lines = append(lines, render.Style("      reason: ", render.Dim)+reason)
		}
		if doc := strings.TrimSpace(check.Documentation); doc != "" {
			lines = append(lines, render.Style("      docs:   ", render.Dim)+doc)
		}
	}

	lines = append(lines, "", render.Style(fmt.Sprintf("Affected components (%d)", len(row.packages)), render.Bold, render.Magenta), "")
	if len(row.packages) == 0 {
		lines = append(lines, render.Style("  (none)", render.Dim))
	}
	for _, pkg := range row.packages {
		label := pkg.displayName
		if pkg.version != "" {
			label += "@" + pkg.version
		}
		lines = append(lines, render.Style("  - ", render.Dim)+label)
	}
	return lines
}

func normalizedPostureCheckScore(score int) int {
	if score < 0 {
		return 11
	}
	return score
}

func posturePrettyScore(score float64) string {
	if score < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f/10", score)
}

func posturePrettyCheckScore(score int) string {
	if score < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d/10", score)
}

func postureCheckBadge(score int) string {
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

// capitalizeASCII is a deliberately tiny replacement for strings.Title,
// scoped to the ASCII band labels this file emits.
func capitalizeASCII(value string) string {
	if value == "" {
		return value
	}
	first := value[0]
	if first >= 'a' && first <= 'z' {
		first -= 'a' - 'A'
	}
	return string(first) + value[1:]
}

// postureListTitle renders the row label shown in the main list pane.
// Format mirrors the licenses tab: aligned columns so the eye can scan
// scores at a fixed offset.
func postureListTitle(row postureRow, repoWidth int) string {
	score := posturePrettyScore(row.card.AggregateScore)
	repo := truncateToWidth(row.repository, repoWidth)
	return padRight(repo, repoWidth) + "  " + padRight(score, 8) + render.Style(fmt.Sprintf(" %d pkg", len(row.packages)), render.Dim)
}

// postureCheckGroup aggregates every repository's outcome for one
// Scorecard check name. Groups are emitted with the highest number of
// failing repos at the top so the most actionable checks sort first.
type postureCheckGroup struct {
	Name              string
	Documentation     string
	FailingRepos      []postureCheckGroupRow // score 0..5 (and inconclusive surfaced separately below)
	InconclusiveRepos []postureCheckGroupRow
	PassingRepos      []postureCheckGroupRow // score 6..10
}

type postureCheckGroupRow struct {
	Row    postureRow
	Score  int
	Reason string
}

// postureCheckGroups pivots the per-repo rows onto a check axis: one
// group per check name, with repos sorted by score asc inside each group
// so failing repos lead. Inconclusive (-1) outcomes get their own
// section so they neither pollute the failing count nor pretend to be
// passing.
func postureCheckGroups(rows []postureRow) []postureCheckGroup {
	groups := make(map[string]*postureCheckGroup)
	for _, row := range rows {
		for _, check := range row.card.Checks {
			name := strings.TrimSpace(check.Name)
			if name == "" {
				continue
			}
			entry, ok := groups[name]
			if !ok {
				entry = &postureCheckGroup{Name: name}
				groups[name] = entry
			}
			if check.Documentation != "" && entry.Documentation == "" {
				entry.Documentation = check.Documentation
			}
			gr := postureCheckGroupRow{Row: row, Score: check.Score, Reason: check.Reason}
			switch {
			case check.Score < 0:
				entry.InconclusiveRepos = append(entry.InconclusiveRepos, gr)
			case check.Score <= 5:
				entry.FailingRepos = append(entry.FailingRepos, gr)
			default:
				entry.PassingRepos = append(entry.PassingRepos, gr)
			}
		}
	}
	out := make([]postureCheckGroup, 0, len(groups))
	for _, entry := range groups {
		sortCheckGroupRows(entry.FailingRepos)
		sortCheckGroupRows(entry.InconclusiveRepos)
		sortCheckGroupRows(entry.PassingRepos)
		out = append(out, *entry)
	}
	// Top failing first; on ties, larger failing+inconclusive set first;
	// on further ties, name-sorted for stable rendering.
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i].FailingRepos) != len(out[j].FailingRepos) {
			return len(out[i].FailingRepos) > len(out[j].FailingRepos)
		}
		problemsI := len(out[i].FailingRepos) + len(out[i].InconclusiveRepos)
		problemsJ := len(out[j].FailingRepos) + len(out[j].InconclusiveRepos)
		if problemsI != problemsJ {
			return problemsI > problemsJ
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortCheckGroupRows(rows []postureCheckGroupRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score < rows[j].Score
		}
		return rows[i].Row.repository < rows[j].Row.repository
	})
}

// postureCheckGroupTitle renders the group header for the by-check view.
func postureCheckGroupTitle(group postureCheckGroup) string {
	worst := 11
	for _, r := range group.FailingRepos {
		if r.Score < worst {
			worst = r.Score
		}
	}
	if worst == 11 {
		// No failing repos — surface the best representative score.
		for _, r := range group.PassingRepos {
			if r.Score < worst {
				worst = r.Score
			}
		}
	}
	band := postureScoreBand(float64(worst))
	badge := postureCheckBadge(worst)
	return render.Style(badge, postureBandColor(band)) + " " + group.Name +
		render.Style(fmt.Sprintf("  %d failing / %d inconclusive / %d passing",
			len(group.FailingRepos), len(group.InconclusiveRepos), len(group.PassingRepos)), render.Dim)
}

// postureCheckGroupDetails is the right-pane details when a check-group
// header is selected: a worst-first list of every affected repository
// and a documentation link.
func postureCheckGroupDetails(group postureCheckGroup) []string {
	lines := []string{
		render.Style("Scorecard Check", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + group.Name,
		render.Style("  Failing repositories: ", render.Dim) + fmt.Sprintf("%d", len(group.FailingRepos)),
		render.Style("  Inconclusive repositories: ", render.Dim) + fmt.Sprintf("%d", len(group.InconclusiveRepos)),
		render.Style("  Passing repositories: ", render.Dim) + fmt.Sprintf("%d", len(group.PassingRepos)),
	}
	if group.Documentation != "" {
		lines = append(lines, render.Style("  Documentation: ", render.Dim)+group.Documentation)
	}
	appendBucket := func(title string, rows []postureCheckGroupRow) {
		if len(rows) == 0 {
			return
		}
		lines = append(lines, "", render.Style(fmt.Sprintf("%s (%d)", title, len(rows)), render.Bold, render.Magenta), "")
		for _, r := range rows {
			band := postureScoreBand(float64(r.Score))
			line := render.Style("  "+postureCheckBadge(r.Score), postureBandColor(band)) +
				" " + render.Style(posturePrettyCheckScore(r.Score)+"  ", render.Dim) + r.Row.repository
			lines = append(lines, line)
			if reason := strings.TrimSpace(r.Reason); reason != "" {
				lines = append(lines, render.Style("      reason: ", render.Dim)+reason)
			}
		}
	}
	appendBucket("Failing repositories", group.FailingRepos)
	appendBucket("Inconclusive repositories", group.InconclusiveRepos)
	appendBucket("Passing repositories", group.PassingRepos)
	return lines
}

// postureCheckGroupRowTitle renders a single repository row inside an
// expanded check group.
func postureCheckGroupRowTitle(r postureCheckGroupRow, repoWidth int) string {
	band := postureScoreBand(float64(r.Score))
	score := posturePrettyCheckScore(r.Score)
	repo := truncateToWidth(r.Row.repository, repoWidth)
	return render.Style(postureCheckBadge(r.Score), postureBandColor(band)) + " " +
		padRight(repo, repoWidth) + "  " + padRight(score, 8) +
		render.Style(fmt.Sprintf("  agg %s", posturePrettyScore(r.Row.card.AggregateScore)), render.Dim)
}

// postureCheckGroupRowDetails renders the same per-repo details pane
// the by-repository view uses, plus a top banner naming the check that
// brought the user here so context is never lost.
func postureCheckGroupRowDetails(group postureCheckGroup, r postureCheckGroupRow) []string {
	lines := []string{
		render.Style("Selected via check: "+group.Name, render.Dim),
		"",
	}
	lines = append(lines, postureRowDetails(r.Row)...)
	return lines
}
