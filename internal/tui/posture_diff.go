package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/render"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// postureDiffRow is the per-repository state for the diff Posture tab.
// Unlike postureRow (scan/explain) it tracks both base and head scorecards
// so the details pane can render a side-by-side delta.
type postureDiffRow struct {
	repository string
	before     *sdk.PackageScorecard
	after      *sdk.PackageScorecard
	packages   []posturePackageRef
}

// postureDiffStatus categorises one repo's delta. The values mirror the
// "Introduced / Dropped / Changed" buckets used by the diff text report.
type postureDiffStatus string

const (
	postureDiffStatusIntroduced postureDiffStatus = "introduced"
	postureDiffStatusDropped    postureDiffStatus = "dropped"
	postureDiffStatusChanged    postureDiffStatus = "changed"
	postureDiffStatusUnchanged  postureDiffStatus = "unchanged"
)

func (r postureDiffRow) status() postureDiffStatus {
	switch {
	case r.before == nil && r.after != nil:
		return postureDiffStatusIntroduced
	case r.before != nil && r.after == nil:
		return postureDiffStatusDropped
	case r.before != nil && r.after != nil:
		if postureScoresDifferMeaningfully(r.before.AggregateScore, r.after.AggregateScore) {
			return postureDiffStatusChanged
		}
		return postureDiffStatusUnchanged
	default:
		return postureDiffStatusUnchanged
	}
}

// postureScoresDifferMeaningfully mirrors the renderer's 0.1 threshold so
// the TUI and the text reports agree on what counts as a "change".
func postureScoresDifferMeaningfully(before, after float64) bool {
	diff := after - before
	if diff < 0 {
		diff = -diff
	}
	if diff >= 0.1 {
		return true
	}
	// Inconclusive ↔ scored transitions also count as meaningful, since the
	// score column reads differently in each case. Only a transition counts:
	// when exactly one side is inconclusive. Two inconclusive scores read the
	// same and are not a meaningful change.
	beforeInconclusive := postureScoreBand(before) == "inconclusive"
	afterInconclusive := postureScoreBand(after) == "inconclusive"
	return beforeInconclusive != afterInconclusive
}

// postureDiffRowsFromPayload aggregates the diff payload's per-package
// scorecard data into one row per source repository. Multiple packages
// that share a repo collapse to one row (monorepos, multi-module Go).
func postureDiffRowsFromPayload(results output.DiffDependencyResults) []postureDiffRow {
	rowsByRepo := make(map[string]*postureDiffRow)
	pkgsByRepo := make(map[string]map[string]posturePackageRef)

	record := func(ref output.PackageRef, before, after *sdk.PackageScorecard) {
		var repo string
		switch {
		case after != nil && after.Repository != "":
			repo = after.Repository
		case before != nil && before.Repository != "":
			repo = before.Repository
		default:
			return
		}
		row, ok := rowsByRepo[repo]
		if !ok {
			row = &postureDiffRow{repository: repo}
			rowsByRepo[repo] = row
			pkgsByRepo[repo] = make(map[string]posturePackageRef)
		}
		if before != nil && row.before == nil {
			row.before = before
		}
		if after != nil && row.after == nil {
			row.after = after
		}
		key := ref.ID
		if key == "" {
			key = ref.Name + "@" + ref.Version
		}
		if _, exists := pkgsByRepo[repo][key]; !exists {
			pkgsByRepo[repo][key] = posturePackageRef{
				id:          ref.ID,
				displayName: firstNonEmptyString(ref.Name, ref.ID),
				version:     ref.Version,
			}
		}
	}

	for _, change := range results.Added {
		if change.Package.Scorecard != nil {
			record(change.Package, nil, change.Package.Scorecard)
		}
	}
	for _, change := range results.Removed {
		if change.Package.Scorecard != nil {
			record(change.Package, change.Package.Scorecard, nil)
		}
	}
	for _, change := range results.Changed {
		if change.Before.Scorecard != nil {
			record(change.Before, change.Before.Scorecard, nil)
		}
		if change.After.Scorecard != nil {
			record(change.After, nil, change.After.Scorecard)
		}
	}

	out := make([]postureDiffRow, 0, len(rowsByRepo))
	for repo, row := range rowsByRepo {
		refs := make([]posturePackageRef, 0, len(pkgsByRepo[repo]))
		for _, ref := range pkgsByRepo[repo] {
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].displayName != refs[j].displayName {
				return refs[i].displayName < refs[j].displayName
			}
			return refs[i].id < refs[j].id
		})
		row.packages = refs
		out = append(out, *row)
	}
	// Status order: Changed → Introduced → Dropped → Unchanged. Inside each
	// bucket, biggest regressions / lowest scores first.
	sort.Slice(out, func(i, j int) bool {
		si := postureDiffStatusRank(out[i].status())
		sj := postureDiffStatusRank(out[j].status())
		if si != sj {
			return si < sj
		}
		return postureDiffRowSortKey(out[i]) < postureDiffRowSortKey(out[j])
	})
	return out
}

func postureDiffStatusRank(status postureDiffStatus) int {
	switch status {
	case postureDiffStatusChanged:
		return 0
	case postureDiffStatusIntroduced:
		return 1
	case postureDiffStatusDropped:
		return 2
	default:
		return 3
	}
}

// postureDiffRowSortKey returns a comparable key that sorts the worst /
// most-actionable row first within a status group.
func postureDiffRowSortKey(row postureDiffRow) string {
	switch row.status() {
	case postureDiffStatusChanged:
		// biggest regression first → most negative delta gets the smallest key
		delta := row.after.AggregateScore - row.before.AggregateScore
		return fmt.Sprintf("%010.4f|%s", delta+1000, row.repository)
	case postureDiffStatusIntroduced:
		return fmt.Sprintf("%05.1f|%s", row.after.AggregateScore, row.repository)
	case postureDiffStatusDropped:
		return fmt.Sprintf("%05.1f|%s", row.before.AggregateScore, row.repository)
	default:
		return row.repository
	}
}

// postureDiffSummaryLines is the left summary panel: bucket counts.
func postureDiffSummaryLines(rows []postureDiffRow) []string {
	if len(rows) == 0 {
		return []string{
			render.Style("No Scorecard data attached.", render.Dim),
			render.Style("Re-run with --matchers +scorecard on both sides.", render.Dim),
		}
	}
	var introduced, dropped, changed, unchanged int
	for _, row := range rows {
		switch row.status() {
		case postureDiffStatusIntroduced:
			introduced++
		case postureDiffStatusDropped:
			dropped++
		case postureDiffStatusChanged:
			changed++
		default:
			unchanged++
		}
	}
	return []string{
		render.Style(fmt.Sprintf("%d repositories", len(rows)), render.Cyan, render.Bold),
		render.Style("Introduced: ", render.Green) + fmt.Sprintf("%d", introduced),
		render.Style("Dropped:    ", render.Red) + fmt.Sprintf("%d", dropped),
		render.Style("Changed:    ", render.Yellow) + fmt.Sprintf("%d", changed),
		render.Style("Unchanged:  ", render.Dim) + fmt.Sprintf("%d", unchanged),
	}
}

// postureDiffMoversLines is the right summary panel — the biggest score
// regressions, with bars sized to the worst regression so the eye gets
// the magnitude.
func postureDiffMoversLines(rows []postureDiffRow, width int) []string {
	type mover struct {
		repo  string
		delta float64
	}
	movers := make([]mover, 0, len(rows))
	for _, row := range rows {
		if row.status() != postureDiffStatusChanged {
			continue
		}
		// Skip rows where one side is inconclusive — they're not really a
		// numeric "delta" the bar can represent.
		if row.before.AggregateScore < 0 || row.after.AggregateScore < 0 {
			continue
		}
		movers = append(movers, mover{repo: row.repository, delta: row.after.AggregateScore - row.before.AggregateScore})
	}
	if len(movers) == 0 {
		return []string{render.Style("No score deltas in this range.", render.Dim)}
	}
	sort.Slice(movers, func(i, j int) bool {
		ai, aj := movers[i].delta, movers[j].delta
		if ai < 0 {
			ai = -ai
		}
		if aj < 0 {
			aj = -aj
		}
		if ai != aj {
			return ai > aj
		}
		return movers[i].repo < movers[j].repo
	})
	if len(movers) > 6 {
		movers = movers[:6]
	}
	labelWidth := width / 2
	if labelWidth < 18 {
		labelWidth = 18
	}
	if labelWidth > 38 {
		labelWidth = 38
	}
	barWidth := width - labelWidth - 12
	if barWidth < 8 {
		barWidth = 8
	}
	maxMag := 0.0
	for _, m := range movers {
		mag := m.delta
		if mag < 0 {
			mag = -mag
		}
		if mag > maxMag {
			maxMag = mag
		}
	}
	out := make([]string, 0, len(movers))
	for _, m := range movers {
		mag := m.delta
		if mag < 0 {
			mag = -mag
		}
		color := render.Green
		sign := "+"
		if m.delta < 0 {
			color = render.Red
			sign = "-"
		}
		bar := coloredBarLine(int(mag*10), int(maxMag*10), barWidth, color)
		label := padRight(truncateToWidth(m.repo, labelWidth), labelWidth)
		out = append(out, label+render.Style(" ", render.Dim)+bar+fmt.Sprintf(" %s%.1f", sign, mag))
	}
	return out
}

// postureDiffRowDetails renders the right-hand details pane for one
// repository row: status banner, before/after numbers, full check
// diff (when both sides exist), and affected packages.
func postureDiffRowDetails(row postureDiffRow) []string {
	lines := []string{
		render.Style("Repository", render.Bold, render.Cyan),
		"",
		render.Style("  Repository: ", render.Dim) + row.repository,
		render.Style("  Status:     ", render.Dim) + postureDiffStatusBadge(row.status()),
	}
	if row.before != nil {
		lines = append(lines, render.Style("  Before:     ", render.Dim)+posturePrettyScore(row.before.AggregateScore)+postureDiffMetaLine(row.before))
	}
	if row.after != nil {
		lines = append(lines, render.Style("  After:      ", render.Dim)+posturePrettyScore(row.after.AggregateScore)+postureDiffMetaLine(row.after))
	}
	if row.before != nil && row.after != nil {
		delta := row.after.AggregateScore - row.before.AggregateScore
		lines = append(lines, render.Style("  Δ:          ", render.Dim)+postureDiffDeltaCell(delta, row.before.AggregateScore, row.after.AggregateScore))
	}

	checks := postureDiffMergedChecks(row)
	if len(checks) > 0 {
		lines = append(lines, "", render.Style(fmt.Sprintf("Checks (%d)", len(checks)), render.Bold, render.Magenta), "")
		for _, check := range checks {
			lines = append(lines, postureDiffCheckLines(check)...)
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

func postureDiffMetaLine(card *sdk.PackageScorecard) string {
	parts := make([]string, 0, 2)
	if !card.RunDate.IsZero() {
		parts = append(parts, "updated "+card.RunDate.UTC().Format("2006-01-02"))
	}
	if card.ScorecardVersion != "" {
		parts = append(parts, "scorecard "+card.ScorecardVersion)
	}
	if len(parts) == 0 {
		return ""
	}
	return render.Style("  ("+strings.Join(parts, ", ")+")", render.Dim)
}

func postureDiffDeltaCell(delta, before, after float64) string {
	if before < 0 && after >= 0 {
		return render.Style("newly scored", render.Green)
	}
	if before >= 0 && after < 0 {
		return render.Style("now inconclusive", render.Yellow)
	}
	if before < 0 && after < 0 {
		return render.Style("—", render.Dim)
	}
	switch {
	case delta > 0:
		return render.Style(fmt.Sprintf("+%.1f", delta), render.Green)
	case delta < 0:
		return render.Style(fmt.Sprintf("%.1f", delta), render.Red)
	default:
		return render.Style("0", render.Dim)
	}
}

func postureDiffStatusBadge(status postureDiffStatus) string {
	switch status {
	case postureDiffStatusIntroduced:
		return render.Style("introduced", render.Green, render.Bold)
	case postureDiffStatusDropped:
		return render.Style("dropped", render.Red, render.Bold)
	case postureDiffStatusChanged:
		return render.Style("changed", render.Yellow, render.Bold)
	default:
		return render.Style("unchanged", render.Dim)
	}
}

// postureDiffMergedChecks merges before/after check lists by name so the
// details pane can render a side-by-side per-check delta.
type postureDiffMergedCheck struct {
	name          string
	before        *sdk.PackageScorecardCheck
	after         *sdk.PackageScorecardCheck
	documentation string
}

func postureDiffMergedChecks(row postureDiffRow) []postureDiffMergedCheck {
	merged := make(map[string]*postureDiffMergedCheck)
	add := func(checks []sdk.PackageScorecardCheck, side string) {
		for i := range checks {
			c := checks[i]
			name := strings.TrimSpace(c.Name)
			if name == "" {
				continue
			}
			entry, ok := merged[name]
			if !ok {
				entry = &postureDiffMergedCheck{name: name}
				merged[name] = entry
			}
			if c.Documentation != "" && entry.documentation == "" {
				entry.documentation = c.Documentation
			}
			cc := c
			if side == "before" {
				entry.before = &cc
			} else {
				entry.after = &cc
			}
		}
	}
	if row.before != nil {
		add(row.before.Checks, "before")
	}
	if row.after != nil {
		add(row.after.Checks, "after")
	}
	out := make([]postureDiffMergedCheck, 0, len(merged))
	for _, entry := range merged {
		out = append(out, *entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Regressions first, then unchanged failing checks, then alphabetical
		// within score brackets.
		li := postureDiffCheckRegressionRank(out[i])
		lj := postureDiffCheckRegressionRank(out[j])
		if li != lj {
			return li < lj
		}
		return out[i].name < out[j].name
	})
	return out
}

// postureDiffCheckRegressionRank returns 0 for biggest regressions, higher
// numbers for stable/strong checks. Used to bubble actionable rows up.
func postureDiffCheckRegressionRank(c postureDiffMergedCheck) int {
	if c.before != nil && c.after != nil {
		delta := c.after.Score - c.before.Score
		switch {
		case delta < -2:
			return 0
		case delta < 0:
			return 1
		case delta > 2:
			return 5
		case delta > 0:
			return 4
		default:
			// Unchanged. Failing checks (low score) bubble above strong ones.
			if c.after.Score < 0 {
				return 3
			}
			if c.after.Score <= 5 {
				return 2
			}
			return 6
		}
	}
	if c.after != nil {
		// Introduced side only — sort low scores first.
		if c.after.Score < 0 {
			return 8
		}
		if c.after.Score <= 5 {
			return 7
		}
		return 9
	}
	// Dropped side only.
	return 10
}

func postureDiffCheckLines(check postureDiffMergedCheck) []string {
	var head string
	switch {
	case check.before != nil && check.after != nil:
		head = render.Style("  ", render.Dim) + render.Style(postureCheckBadge(check.after.Score), postureBandColor(postureScoreBand(float64(check.after.Score)))) +
			" " + check.name + render.Style(fmt.Sprintf("  %s → %s", posturePrettyCheckScore(check.before.Score), posturePrettyCheckScore(check.after.Score)), render.Dim)
	case check.after != nil:
		head = render.Style("  ", render.Dim) + render.Style(postureCheckBadge(check.after.Score), postureBandColor(postureScoreBand(float64(check.after.Score)))) +
			" " + check.name + render.Style("  introduced @ "+posturePrettyCheckScore(check.after.Score), render.Green)
	case check.before != nil:
		head = render.Style("  ", render.Dim) + render.Style(postureCheckBadge(check.before.Score), postureBandColor(postureScoreBand(float64(check.before.Score)))) +
			" " + check.name + render.Style("  dropped @ "+posturePrettyCheckScore(check.before.Score), render.Red)
	}
	lines := []string{head}
	reason := ""
	if check.after != nil && check.after.Reason != "" {
		reason = check.after.Reason
	} else if check.before != nil && check.before.Reason != "" {
		reason = check.before.Reason
	}
	if reason != "" {
		lines = append(lines, render.Style("      reason: ", render.Dim)+reason)
	}
	if check.documentation != "" {
		lines = append(lines, render.Style("      docs:   ", render.Dim)+check.documentation)
	}
	return lines
}

// postureDiffListItem renders one repository row in the main list pane.
func postureDiffListItem(row postureDiffRow, repoWidth int) listItem {
	repo := truncateToWidth(row.repository, repoWidth)
	score := postureDiffScoreCell(row)
	title := padRight(repo, repoWidth) + "  " + score
	status := row.status()
	return listItem{
		title: title,
		badges: []badge{
			{label: strings.ToUpper(string(status)), kind: postureDiffStatusBadgeKind(status)},
		},
		details: postureDiffRowDetails(row),
	}
}

func postureDiffStatusBadgeKind(status postureDiffStatus) string {
	switch status {
	case postureDiffStatusIntroduced:
		return "severity-low" // green-toned in existing badge palette
	case postureDiffStatusDropped:
		return "severity-critical"
	case postureDiffStatusChanged:
		return "severity-high"
	default:
		return "severity-unknown"
	}
}

func postureDiffScoreCell(row postureDiffRow) string {
	switch row.status() {
	case postureDiffStatusIntroduced:
		return render.Style(fmt.Sprintf("    → %s", posturePrettyScore(row.after.AggregateScore)), render.Green)
	case postureDiffStatusDropped:
		return render.Style(fmt.Sprintf("%s →    ", posturePrettyScore(row.before.AggregateScore)), render.Red)
	case postureDiffStatusChanged:
		arrow := fmt.Sprintf("%s → %s", posturePrettyScore(row.before.AggregateScore), posturePrettyScore(row.after.AggregateScore))
		if row.after.AggregateScore >= row.before.AggregateScore {
			return render.Style(arrow, render.Green)
		}
		return render.Style(arrow, render.Red)
	default:
		score := row.after
		if score == nil {
			score = row.before
		}
		return render.Style(posturePrettyScore(score.AggregateScore), render.Dim)
	}
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// postureDiffCheckGroup pivots the diff payload onto a check axis: one
// group per check name, with the affected repositories sorted by
// regression magnitude (worst regressions first).
type postureDiffCheckGroup struct {
	Name          string
	Documentation string
	Rows          []postureDiffCheckRow
	// Counters used for the header sort: a check group with many
	// repositories regressing should sort above a group with only
	// improvements or stable scores.
	Regressions  int
	Improvements int
	Stable       int
	Introduced   int
	Dropped      int
}

// postureDiffCheckRow is one repository's outcome for one check, holding
// the score on each side so the renderer can show before → after.
type postureDiffCheckRow struct {
	Repo   postureDiffRow
	Before *int
	After  *int
}

// postureDiffCheckGroups builds the by-check groups from a slice of
// postureDiffRow values. A check appears with at most one row per repo;
// the before/after pointers reflect what (if anything) was scored on
// each side.
//
// Implementation note: rows are built in a (checkName, repo) ->
// *postureDiffCheckRow map first, then flattened into each group's slice
// after collection. This keeps before/after updates simple (pointer
// mutation) and avoids re-finding-and-replacing slice entries on every
// scan.
func postureDiffCheckGroups(rows []postureDiffRow) []postureDiffCheckGroup {
	type rowKey struct {
		check string
		repo  string
	}
	cells := make(map[rowKey]*postureDiffCheckRow)
	docs := make(map[string]string)

	for _, row := range rows {
		record := func(checks []sdk.PackageScorecardCheck, side string) {
			for i := range checks {
				c := checks[i]
				name := strings.TrimSpace(c.Name)
				if name == "" {
					continue
				}
				if c.Documentation != "" {
					if _, ok := docs[name]; !ok {
						docs[name] = c.Documentation
					}
				}
				key := rowKey{check: name, repo: row.repository}
				entry, ok := cells[key]
				if !ok {
					entry = &postureDiffCheckRow{Repo: row}
					cells[key] = entry
				}
				score := c.Score
				if side == "before" {
					entry.Before = &score
				} else {
					entry.After = &score
				}
			}
		}
		if row.before != nil {
			record(row.before.Checks, "before")
		}
		if row.after != nil {
			record(row.after.Checks, "after")
		}
	}

	groups := make(map[string]*postureDiffCheckGroup)
	for key, cell := range cells {
		group, ok := groups[key.check]
		if !ok {
			group = &postureDiffCheckGroup{Name: key.check, Documentation: docs[key.check]}
			groups[key.check] = group
		}
		group.Rows = append(group.Rows, *cell)
	}
	out := make([]postureDiffCheckGroup, 0, len(groups))
	for _, group := range groups {
		for _, r := range group.Rows {
			switch {
			case r.Before == nil && r.After != nil:
				group.Introduced++
			case r.Before != nil && r.After == nil:
				group.Dropped++
			case r.Before != nil && r.After != nil:
				switch {
				case *r.After < *r.Before:
					group.Regressions++
				case *r.After > *r.Before:
					group.Improvements++
				default:
					group.Stable++
				}
			}
		}
		sort.SliceStable(group.Rows, func(i, j int) bool {
			return postureDiffCheckRowRank(group.Rows[i]) < postureDiffCheckRowRank(group.Rows[j])
		})
		out = append(out, *group)
	}
	// Worst regressions first; then most-introduced; then alphabetical.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Regressions != out[j].Regressions {
			return out[i].Regressions > out[j].Regressions
		}
		if out[i].Dropped != out[j].Dropped {
			return out[i].Dropped > out[j].Dropped
		}
		if out[i].Introduced != out[j].Introduced {
			return out[i].Introduced > out[j].Introduced
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func postureDiffCheckRowRank(r postureDiffCheckRow) int {
	switch {
	case r.Before != nil && r.After != nil && *r.After < *r.Before:
		return 0 // regression
	case r.Before != nil && r.After == nil:
		return 1 // dropped
	case r.Before == nil && r.After != nil && *r.After <= 5:
		return 2 // introduced failing
	case r.Before == nil && r.After != nil:
		return 3 // introduced passing
	case r.Before != nil && r.After != nil && *r.After > *r.Before:
		return 4 // improvement
	default:
		return 5 // stable
	}
}

func postureDiffCheckGroupTitle(group postureDiffCheckGroup) string {
	movement := fmt.Sprintf("%d ↓ regressions, %d ↑ improvements", group.Regressions, group.Improvements)
	if group.Dropped > 0 || group.Introduced > 0 {
		movement += fmt.Sprintf(", %d introduced, %d dropped", group.Introduced, group.Dropped)
	}
	color := render.Yellow
	if group.Regressions > 0 || group.Dropped > 0 {
		color = render.Red
	} else if group.Improvements > 0 || group.Introduced > 0 {
		color = render.Green
	}
	return render.Style("●", color) + " " + group.Name + render.Style("  "+movement, render.Dim)
}

func postureDiffCheckGroupDetails(group postureDiffCheckGroup) []string {
	lines := []string{
		render.Style("Scorecard Check (delta)", render.Bold, render.Cyan),
		"",
		render.Style("  Name: ", render.Dim) + group.Name,
		render.Style("  Regressions: ", render.Dim) + fmt.Sprintf("%d", group.Regressions),
		render.Style("  Improvements: ", render.Dim) + fmt.Sprintf("%d", group.Improvements),
		render.Style("  Stable: ", render.Dim) + fmt.Sprintf("%d", group.Stable),
		render.Style("  Introduced: ", render.Dim) + fmt.Sprintf("%d", group.Introduced),
		render.Style("  Dropped: ", render.Dim) + fmt.Sprintf("%d", group.Dropped),
	}
	if group.Documentation != "" {
		lines = append(lines, render.Style("  Documentation: ", render.Dim)+group.Documentation)
	}
	lines = append(lines, "", render.Style(fmt.Sprintf("Affected repositories (%d)", len(group.Rows)), render.Bold, render.Magenta), "")
	for _, r := range group.Rows {
		lines = append(lines, "  "+postureDiffCheckGroupRowTitle(r, 40))
	}
	return lines
}

func postureDiffCheckGroupRowTitle(r postureDiffCheckRow, repoWidth int) string {
	repo := truncateToWidth(r.Repo.repository, repoWidth)
	switch {
	case r.Before == nil && r.After != nil:
		return padRight(repo, repoWidth) + render.Style(fmt.Sprintf("  ─ → %s  (introduced)", posturePrettyCheckScore(*r.After)), render.Green)
	case r.Before != nil && r.After == nil:
		return padRight(repo, repoWidth) + render.Style(fmt.Sprintf("  %s → ─  (dropped)", posturePrettyCheckScore(*r.Before)), render.Red)
	case r.Before != nil && r.After != nil && *r.After < *r.Before:
		return padRight(repo, repoWidth) + render.Style(fmt.Sprintf("  %s → %s", posturePrettyCheckScore(*r.Before), posturePrettyCheckScore(*r.After)), render.Red)
	case r.Before != nil && r.After != nil && *r.After > *r.Before:
		return padRight(repo, repoWidth) + render.Style(fmt.Sprintf("  %s → %s", posturePrettyCheckScore(*r.Before), posturePrettyCheckScore(*r.After)), render.Green)
	case r.Before != nil && r.After != nil:
		return padRight(repo, repoWidth) + render.Style(fmt.Sprintf("  %s → %s  (stable)", posturePrettyCheckScore(*r.Before), posturePrettyCheckScore(*r.After)), render.Dim)
	default:
		return padRight(repo, repoWidth) + render.Style("  ─ → ─", render.Dim)
	}
}

func postureDiffCheckGroupRowDetails(group postureDiffCheckGroup, r postureDiffCheckRow) []string {
	lines := []string{
		render.Style("Selected via check: "+group.Name, render.Dim),
		"",
	}
	lines = append(lines, postureDiffRowDetails(r.Repo)...)
	return lines
}

// buildPostureTab is the DiffModel's TabSpec.Build for the Posture tab.
// Layout mirrors the other diff tabs: top summary panels, single main
// list, secondary details pane. The `g` key cycles the grouping axis
// between "check" (default) and "repository".
func (m *DiffModel) buildPostureTab() *listModel {
	rows := postureDiffRowsFromPayload(m.payload.Results.Dependencies)
	repoWidth := 24
	for _, row := range rows {
		if len(row.repository) > repoWidth {
			repoWidth = len(row.repository)
		}
	}
	if repoWidth > 56 {
		repoWidth = 56
	}

	group := valueOrDefault(m.postureGroup, "check")
	var items []listItem
	var listTitle, listHeader string
	switch group {
	case "check":
		items, listTitle, listHeader = m.postureDiffItemsByCheck(rows, repoWidth)
	default:
		items = make([]listItem, 0, len(rows))
		for _, row := range rows {
			items = append(items, postureDiffListItem(row, repoWidth))
		}
		listTitle = fmt.Sprintf("Repositories (%d)", len(rows))
		listHeader = padRight("Repository", repoWidth) + "  Score"
	}

	emptyState := "No Scorecard data in either side of this diff. Re-run with --enrich --matchers +scorecard on both base and head."
	if m.enrichEnabled && len(rows) == 0 {
		emptyState = "Enrichment ran without Scorecard. Re-run with --matchers +scorecard on both sides."
	}

	return &listModel{
		listTitle:   listTitle,
		listHeader:  listHeader,
		detailTitle: "Repository Posture",
		topPanels: []listPanel{
			{title: "Posture Delta", lines: postureDiffSummaryLines(rows), color: render.Yellow, weight: 1},
			{title: "Biggest Score Movers", lines: postureDiffMoversLines(rows, 140), color: render.Red, weight: 2},
		},
		navigationHelp: interactiveCommonNavigationHelp,
		filterHelp:     "Use / to search; g cycles group (repository/check); Enter focuses details; 1-7 switch tabs",
		emptyState:     emptyState,
		items:          items,
	}
}

// postureDiffItemsByCheck renders the by-check view for the diff:
// expandable group headers per check name, with affected repositories
// underneath. Each row shows the per-check before/after rather than the
// aggregate, so deltas are pegged to the specific failing check.
func (m *DiffModel) postureDiffItemsByCheck(rows []postureDiffRow, repoWidth int) ([]listItem, string, string) {
	groups := postureDiffCheckGroups(rows)
	items := make([]listItem, 0, len(rows)+len(groups))
	for _, group := range groups {
		key := "check:" + group.Name
		expanded := expandedValue(m.postureExpanded, key, true)
		items = append(items, listItem{
			title:    postureDiffCheckGroupTitle(group),
			subtitle: "group",
			details:  postureDiffCheckGroupDetails(group),
			key:      key,
			canOpen:  true,
			expanded: expanded,
		})
		if !expanded {
			continue
		}
		for idx, child := range group.Rows {
			items = append(items, listItem{
				title:   postureDiffCheckGroupRowTitle(child, repoWidth),
				details: postureDiffCheckGroupRowDetails(group, child),
				tree:    treePrefix(nil, idx == len(group.Rows)-1, 1),
				depth:   1,
			})
		}
	}
	listTitle := fmt.Sprintf("Checks (%d)", len(groups))
	listHeader := padRight("Check / Repository", repoWidth+6) + "  Before → After"
	return items, listTitle, listHeader
}
