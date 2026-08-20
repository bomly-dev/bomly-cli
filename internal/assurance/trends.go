package assurance

import (
	"sort"
	"strings"
)

// Direction names whether a rising metric is an improvement.
const (
	betterLower   = "lower"
	betterHigher  = "higher"
	betterNeutral = "neutral"
)

// lowerIsBetterSuffixes name metrics where a smaller number is an improvement.
var lowerIsBetterSuffixes = []string{"_ms", "_bytes", "_seconds", "_failed"}

// higherIsBetterSuffixes name metrics where a larger number is an improvement.
var higherIsBetterSuffixes = []string{"_passed", "_completed", "_total", "targets", "cases", "assets", "checks"}

// metricDirection reports whether higher or lower is better for a metric.
func metricDirection(name string) string {
	for _, suffix := range lowerIsBetterSuffixes {
		if strings.HasSuffix(name, suffix) {
			return betterLower
		}
	}
	for _, suffix := range higherIsBetterSuffixes {
		if strings.HasSuffix(name, suffix) {
			return betterHigher
		}
	}
	return betterNeutral
}

// buildTrends compares the current report against the previous release's report
// and records metric deltas plus every check whose status changed.
func buildTrends(previous, current Report) *Trends {
	trends := &Trends{PreviousTag: previous.Release.Tag}
	previousChecks := make(map[string]ReportCheck, len(previous.Checks))
	for _, check := range previous.Checks {
		previousChecks[check.ID] = check
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
		names := make([]string, 0, len(check.Metrics))
		for name := range check.Metrics {
			if _, present := before.Metrics[name]; present {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			was := before.Metrics[name]
			now := check.Metrics[name]
			if was == now {
				continue
			}
			trend := MetricTrend{
				CheckID: check.ID, Metric: name, Previous: was, Current: now,
				Delta: now - was, Better: metricDirection(name),
			}
			if was != 0 {
				trend.DeltaPct = (now - was) / was * 100
			}
			trends.Metrics = append(trends.Metrics, trend)
		}
	}
	sort.Slice(trends.Changed, func(i, j int) bool { return trends.Changed[i].CheckID < trends.Changed[j].CheckID })
	sort.Slice(trends.Metrics, func(i, j int) bool {
		if trends.Metrics[i].CheckID != trends.Metrics[j].CheckID {
			return trends.Metrics[i].CheckID < trends.Metrics[j].CheckID
		}
		return trends.Metrics[i].Metric < trends.Metrics[j].Metric
	})
	return trends
}
