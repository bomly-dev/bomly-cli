package assurance

import "sort"

// Direction names whether a rising metric is an improvement.
const (
	betterLower   = "lower"
	betterHigher  = "higher"
	betterNeutral = "neutral"
)

// buildTrends compares the current report against the previous release's
// report: every check whose status changed, and every measurement the catalog
// declares that both reports recorded. A measurement that did not move is
// still listed, so the comparison has the same rows from one release to the
// next.
func buildTrends(catalog Catalog, previous, current Report) *Trends {
	trends := &Trends{PreviousTag: previous.Release.Tag}
	previousChecks := make(map[string]ReportCheck, len(previous.Checks))
	for _, check := range previous.Checks {
		previousChecks[check.ID] = check
	}
	measurements := make(map[string][]Measurement, len(catalog.Checks))
	for _, check := range catalog.Checks {
		measurements[check.ID] = check.Measurements
	}
	for _, check := range current.Checks {
		before, exists := previousChecks[check.ID]
		if !exists {
			continue
		}
		if before.Status != check.Status {
			trends.Changed = append(trends.Changed, StatusChange{
				CheckID: check.ID, Previous: before.Status, Current: check.Status,
			})
		}
		for _, measurement := range measurements[check.ID] {
			was, hadBefore := before.Metrics[measurement.Metric]
			now, hasNow := check.Metrics[measurement.Metric]
			if !hadBefore || !hasNow {
				continue
			}
			trend := MetricTrend{
				CheckID: check.ID, Metric: measurement.Metric,
				Label: measurement.Label, Description: measurement.Description,
				Previous: was, Current: now, Delta: now - was, Better: measurement.Better,
			}
			if was != 0 {
				trend.DeltaPct = (now - was) / was * 100
			}
			trends.Metrics = append(trends.Metrics, trend)
		}
	}
	sort.Slice(trends.Changed, func(i, j int) bool { return trends.Changed[i].CheckID < trends.Changed[j].CheckID })
	// Stable, so measurements keep the order the catalog declares them in.
	sort.SliceStable(trends.Metrics, func(i, j int) bool {
		return trends.Metrics[i].CheckID < trends.Metrics[j].CheckID
	})
	return trends
}
