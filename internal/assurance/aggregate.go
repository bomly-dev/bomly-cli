package assurance

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// BuildOptions configures how a report is assembled from check results.
type BuildOptions struct {
	// Release identifies the release being reported on.
	Release Release
	// Stages limits the report to these stages; empty means every stage.
	Stages []Stage
	// StageRuns maps a stage to the workflow run that produced its results.
	StageRuns map[Stage]string
	// Previous is the previous release's report, used for trends.
	Previous *Report
	// IncludeEvidence attaches the public evidence claims to the report.
	IncludeEvidence bool
	// GeneratedBy names the tool version that produced the report.
	GeneratedBy string
	// Now is the report timestamp; the zero value means time.Now().
	Now time.Time
}

// BuildReport merges check results into the catalog and produces the report
// that the public assurance page renders. Declared checks without a result are
// reported as missing; reported checks the catalog does not declare are listed
// separately so nothing is silently dropped.
func BuildReport(catalog Catalog, results []CheckResult, opts BuildOptions) Report {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	stages := opts.Stages
	if len(stages) == 0 {
		stages = Stages()
	}
	selected := make(map[Stage]struct{}, len(stages))
	for _, stage := range stages {
		selected[stage] = struct{}{}
	}

	byCheck := make(map[string][]CheckResult, len(results))
	for _, result := range results {
		byCheck[result.ID] = append(byCheck[result.ID], result)
	}

	report := Report{
		SchemaVersion: ReportSchema,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Release:       opts.Release,
		Environment:   Environment{GeneratedBy: opts.GeneratedBy, Runners: collectRunners(results)},
	}

	statusByCheck := make(map[string]Status, len(catalog.Checks))
	for _, check := range catalog.Checks {
		if _, wanted := selected[check.Stage]; !wanted {
			continue
		}
		reported := buildCheck(check, byCheck[check.ID])
		statusByCheck[check.ID] = reported.Status
		report.Checks = append(report.Checks, reported)
	}
	sort.SliceStable(report.Checks, func(i, j int) bool { return report.Checks[i].ID < report.Checks[j].ID })

	declared := make(map[string]struct{}, len(catalog.Checks))
	for _, check := range catalog.Checks {
		declared[check.ID] = struct{}{}
	}
	for _, result := range results {
		if _, known := declared[result.ID]; known {
			continue
		}
		report.Unknown = append(report.Unknown, UnknownResult{
			ID: result.ID, Instance: result.Instance, Stage: result.Stage, Status: result.Status,
		})
	}
	sort.Slice(report.Unknown, func(i, j int) bool {
		if report.Unknown[i].ID != report.Unknown[j].ID {
			return report.Unknown[i].ID < report.Unknown[j].ID
		}
		return report.Unknown[i].Instance < report.Unknown[j].Instance
	})

	for _, stage := range Stages() {
		if _, wanted := selected[stage]; !wanted {
			continue
		}
		stageReport := StageReport{ID: stage, Title: stage.Title(), RunURL: opts.StageRuns[stage]}
		var stageChecks []ReportCheck
		for _, check := range report.Checks {
			if check.Stage != stage {
				continue
			}
			stageChecks = append(stageChecks, check)
			stageReport.CheckIDs = append(stageReport.CheckIDs, check.ID)
		}
		stageReport.Verdict = summarize(stageChecks)
		stageReport.Status = stageReport.Verdict.Overall
		report.Stages = append(report.Stages, stageReport)
	}
	report.Verdict = summarize(report.Checks)

	if opts.IncludeEvidence {
		report.Evidence = buildEvidence(catalog, report, selected)
	}

	// Areas are listed in catalog order, which is the order the published page
	// reads in. An area earns a section when it has checks or evidence.
	for _, area := range catalog.Areas {
		reported := AreaReport{ID: area.ID, Title: area.Title, Description: area.Description}
		var areaChecks []ReportCheck
		for _, check := range report.Checks {
			if check.Area == area.ID {
				areaChecks = append(areaChecks, check)
				reported.CheckIDs = append(reported.CheckIDs, check.ID)
			}
		}
		for _, evidence := range report.Evidence {
			if evidence.Area == area.ID {
				reported.EvidenceIDs = append(reported.EvidenceIDs, evidence.ID)
			}
		}
		if len(reported.CheckIDs) == 0 && len(reported.EvidenceIDs) == 0 {
			continue
		}
		reported.Verdict = summarize(areaChecks)
		reported.Status = reported.Verdict.Overall
		// An area proven only by evidence takes the status of the checks
		// backing those claims, so it can never look better than they are.
		if len(areaChecks) == 0 {
			reported.Status = evidenceAreaStatus(report, reported.EvidenceIDs)
		}
		report.Areas = append(report.Areas, reported)
	}
	report.Coverage = buildCoverage(catalog, report, selected)
	if opts.Previous != nil {
		report.Trends = buildTrends(*opts.Previous, report)
	}
	return report
}

func buildCheck(check Check, results []CheckResult) ReportCheck {
	reported := ReportCheck{
		ID: check.ID, Title: check.Title, Area: check.Area, Stage: check.Stage,
		Level: check.Level, Description: check.Description, Source: check.Source,
		Reproduce: check.Reproduce, Proves: check.Proves, Limitations: check.Limitations,
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Key() < results[j].Key() })

	seen := make(map[string]struct{}, len(results))
	status := Status("")
	for _, result := range results {
		name := result.Instance
		if name == "" {
			name = "default"
		}
		seen[name] = struct{}{}
		reported.Instances = append(reported.Instances, InstanceReport{
			Name: name, Status: result.Status, Summary: result.Summary,
			DurationMS: result.DurationMS, RunURL: result.RunURL, Runner: result.Runner,
			Metrics: result.Metrics, Details: result.Details,
			Artifacts: result.Artifacts, Links: result.Links,
		})
		reported.DurationMS += result.DurationMS
		if status == "" {
			status = result.Status
		} else {
			status = Worse(status, result.Status)
		}
	}
	for _, expected := range check.ExpectedInstances {
		if _, present := seen[expected.Name]; !present {
			reported.MissingInstances = append(reported.MissingInstances, expected.Name)
		}
	}
	switch {
	case len(results) == 0:
		reported.Status = StatusMissing
		reported.Summary = "No result was reported for this check."
	default:
		reported.Status = status
		if len(reported.MissingInstances) > 0 {
			reported.Status = Worse(reported.Status, StatusMissing)
		}
		reported.Summary = checkSummary(reported)
	}
	reported.Metrics = mergeMetrics(reported.Instances)
	return reported
}

func checkSummary(check ReportCheck) string {
	if len(check.Instances) == 1 && len(check.MissingInstances) == 0 {
		return check.Instances[0].Summary
	}
	counts := map[Status]int{}
	for _, instance := range check.Instances {
		counts[instance.Status]++
	}
	parts := []string{plural(counts[StatusPass], "instance", "instances") + " passed"}
	for _, status := range []Status{StatusFail, StatusDegraded, StatusSkip} {
		if counts[status] > 0 {
			parts = append(parts, plural(counts[status], "instance", "instances")+" "+string(status))
		}
	}
	if len(check.MissingInstances) > 0 {
		parts = append(parts, plural(len(check.MissingInstances), "instance", "instances")+" reported nothing")
	}
	return strings.Join(parts, ", ") + "."
}

func plural(count int, singular, pluralWord string) string {
	word := pluralWord
	if count == 1 {
		word = singular
	}
	return strconv.Itoa(count) + " " + word
}

// additiveMetrics are the metric names that stay meaningful when summed across
// the instances of one check. Everything else (medians, percentiles, sizes)
// stays visible per instance only, because summing it would be misleading.
var additiveMetrics = map[string]bool{
	"assets":           true,
	"builds_completed": true,
	"builds_planned":   true,
	"cases":            true,
	"checks":           true,
	"completed_runs":   true,
	"packages":         true,
	"planned_runs":     true,
	"targets":          true,
	"tests_failed":     true,
	"tests_passed":     true,
	"tests_skipped":    true,
	"tests_total":      true,
}

func mergeMetrics(instances []InstanceReport) map[string]float64 {
	if len(instances) == 0 {
		return nil
	}
	if len(instances) == 1 {
		if len(instances[0].Metrics) == 0 {
			return nil
		}
		merged := make(map[string]float64, len(instances[0].Metrics))
		for key, value := range instances[0].Metrics {
			merged[key] = value
		}
		return merged
	}
	merged := map[string]float64{}
	for _, instance := range instances {
		for key, value := range instance.Metrics {
			if !additiveMetrics[key] {
				continue
			}
			merged[key] += value
		}
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

func summarize(checks []ReportCheck) Verdict {
	verdict := Verdict{Overall: StatusPass, Checks: len(checks)}
	gateStatus := StatusPass
	advisoryStatus := StatusPass
	for _, check := range checks {
		switch check.Status {
		case StatusPass:
			verdict.Passed++
		case StatusFail:
			verdict.Failed++
		case StatusDegraded:
			verdict.Degraded++
		case StatusSkip:
			verdict.Skipped++
		case StatusMissing:
			verdict.Missing++
		}
		if check.Status == StatusMissing {
			verdict.MissingChecks = append(verdict.MissingChecks, check.ID)
		}
		if check.Level == LevelGate {
			gateStatus = Worse(gateStatus, check.Status)
			// A gate that was skipped did not hold; it simply did not run, and
			// treating that as a pass is exactly the silence this framework is
			// meant to prevent.
			if check.Status == StatusFail || check.Status == StatusDegraded || check.Status == StatusSkip {
				verdict.GatesFailed = append(verdict.GatesFailed, check.ID)
			}
			continue
		}
		advisoryStatus = Worse(advisoryStatus, check.Status)
		if check.Status == StatusFail || check.Status == StatusDegraded {
			verdict.AdvisoriesFailed = append(verdict.AdvisoriesFailed, check.ID)
		}
	}
	verdict.Overall = gateStatus
	if verdict.Overall == StatusPass && advisoryStatus != StatusPass {
		verdict.Overall = StatusDegraded
	}
	return verdict
}

// evidenceAreaStatus is the worst status among the claims in an area.
func evidenceAreaStatus(report Report, ids []string) Status {
	status := StatusPass
	for _, id := range ids {
		for _, evidence := range report.Evidence {
			if evidence.ID == id {
				status = Worse(status, evidence.Status)
			}
		}
	}
	return status
}

func buildEvidence(catalog Catalog, report Report, selected map[Stage]struct{}) []ReportEvidence {
	var entries []ReportEvidence
	for _, evidence := range catalog.Evidence {
		check, exists := catalog.Check(evidence.CheckID)
		if !exists {
			continue
		}
		if _, wanted := selected[check.Stage]; !wanted {
			continue
		}
		status := StatusMissing
		if reported, found := report.Check(evidence.CheckID); found {
			status = reported.Status
			if evidence.Instance != "" {
				status = StatusMissing
				for _, instance := range reported.Instances {
					if instance.Name == evidence.Instance {
						status = instance.Status
						break
					}
				}
			}
		}
		entries = append(entries, ReportEvidence{
			ID: evidence.ID, Title: evidence.Title, Area: evidence.Area,
			EvidenceLevel: evidence.EvidenceLevel, CheckID: evidence.CheckID,
			Instance: evidence.Instance, Status: status, Inputs: evidence.Inputs,
			RequiredTools: evidence.RequiredTools, Reproduce: evidence.Reproduce,
			Artifacts: evidence.Artifacts, Proves: evidence.Proves, Limitations: evidence.Limitations,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

func buildCoverage(catalog Catalog, report Report, selected map[Stage]struct{}) Coverage {
	ecosystems := map[string]struct{}{}
	var rows []CoverageRow
	for _, check := range catalog.Checks {
		if _, wanted := selected[check.Stage]; !wanted {
			continue
		}
		reported, found := report.Check(check.ID)
		if !found {
			continue
		}
		cells := map[string]Status{}
		for _, expected := range check.ExpectedInstances {
			if len(expected.Ecosystems) == 0 {
				continue
			}
			status := StatusMissing
			for _, instance := range reported.Instances {
				if instance.Name == expected.Name {
					status = instance.Status
					break
				}
			}
			for _, ecosystem := range expected.Ecosystems {
				ecosystems[ecosystem] = struct{}{}
				if existing, present := cells[ecosystem]; present {
					cells[ecosystem] = Worse(existing, status)
					continue
				}
				cells[ecosystem] = status
			}
		}
		if len(cells) == 0 {
			continue
		}
		rows = append(rows, CoverageRow{CheckID: check.ID, Title: check.Title, Cells: cells})
	}
	names := make([]string, 0, len(ecosystems))
	for ecosystem := range ecosystems {
		names = append(names, ecosystem)
	}
	sort.Strings(names)
	sort.Slice(rows, func(i, j int) bool { return rows[i].CheckID < rows[j].CheckID })
	return Coverage{Ecosystems: names, Rows: rows}
}

func collectRunners(results []CheckResult) []Runner {
	seen := map[Runner]struct{}{}
	var runners []Runner
	for _, result := range results {
		if result.Runner == (Runner{}) {
			continue
		}
		if _, exists := seen[result.Runner]; exists {
			continue
		}
		seen[result.Runner] = struct{}{}
		runners = append(runners, result.Runner)
	}
	sort.Slice(runners, func(i, j int) bool {
		if runners[i].OS != runners[j].OS {
			return runners[i].OS < runners[j].OS
		}
		if runners[i].Arch != runners[j].Arch {
			return runners[i].Arch < runners[j].Arch
		}
		return runners[i].GoVersion < runners[j].GoVersion
	})
	return runners
}
