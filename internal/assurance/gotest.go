package assurance

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// MaxGoTestDetails caps how many individual test outcomes a check result
// records, so one slice with thousands of subtests cannot bloat the report.
const MaxGoTestDetails = 200

// maxGoTestLine bounds one line of `go test -json` output.
const maxGoTestLine = 1 << 20

// GoTestSummary is the outcome of one `go test -json` stream.
type GoTestSummary struct {
	Packages   int
	Total      int
	Passed     int
	Failed     int
	Skipped    int
	ElapsedSec float64
	Details    []Detail
	Truncated  int
	// FailedTests names the tests that failed, in report order.
	FailedTests []string
	// Anomalies records non-JSON lines, which usually mean a build failure.
	Anomalies []string
}

type goTestEvent struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Elapsed float64 `json:"Elapsed"`
	Output  string  `json:"Output"`
}

// ParseGoTestEvents reads a `go test -json` stream and summarises it. Lines that
// are not JSON events (build errors, toolchain notices) are recorded as
// anomalies instead of failing the parse. When echo is non-nil, test output is
// replayed to it so CI logs stay readable.
func ParseGoTestEvents(reader io.Reader, echo io.Writer) (GoTestSummary, error) {
	summary := GoTestSummary{}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxGoTestLine)

	type outcome struct {
		status  Status
		elapsed float64
	}
	tests := map[string]outcome{}
	packages := map[string]struct{}{}

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var event goTestEvent
		if err := json.Unmarshal(line, &event); err != nil || event.Action == "" {
			text := strings.TrimSpace(string(line))
			if text != "" && len(summary.Anomalies) < 20 {
				summary.Anomalies = append(summary.Anomalies, truncate(text, 300))
			}
			if echo != nil {
				fmt.Fprintln(echo, text)
			}
			continue
		}
		if event.Package != "" {
			packages[event.Package] = struct{}{}
		}
		if event.Action == "output" {
			if echo != nil {
				fmt.Fprint(echo, event.Output)
			}
			continue
		}
		if event.Test == "" {
			if event.Action == "fail" && event.Elapsed > summary.ElapsedSec {
				summary.ElapsedSec = event.Elapsed
			}
			if event.Action == "pass" && event.Elapsed > summary.ElapsedSec {
				summary.ElapsedSec = event.Elapsed
			}
			continue
		}
		name := event.Test
		if event.Package != "" {
			name = shortPackage(event.Package) + "." + event.Test
		}
		switch event.Action {
		case "pass":
			tests[name] = outcome{status: StatusPass, elapsed: event.Elapsed}
		case "fail":
			tests[name] = outcome{status: StatusFail, elapsed: event.Elapsed}
		case "skip":
			tests[name] = outcome{status: StatusSkip, elapsed: event.Elapsed}
		}
	}
	if err := scanner.Err(); err != nil {
		return summary, fmt.Errorf("read go test output: %w", err)
	}

	summary.Packages = len(packages)
	names := make([]string, 0, len(tests))
	for name := range tests {
		names = append(names, name)
	}
	sort.Strings(names)

	var reportable []string
	for _, name := range names {
		result := tests[name]
		summary.Total++
		switch result.status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
			summary.FailedTests = append(summary.FailedTests, name)
		case StatusSkip:
			summary.Skipped++
		}
		if result.status == StatusFail || testDepth(name) <= 2 {
			reportable = append(reportable, name)
		}
	}
	for _, name := range reportable {
		if len(summary.Details) >= MaxGoTestDetails {
			summary.Truncated = len(reportable) - len(summary.Details)
			break
		}
		result := tests[name]
		summary.Details = append(summary.Details, Detail{
			Name: name, Status: result.status, DurationMS: result.elapsed * 1000,
		})
	}
	return summary, nil
}

// testDepth counts the subtest levels in a `Package.TestName/sub/case` label.
func testDepth(name string) int {
	if index := strings.Index(name, "."); index >= 0 {
		name = name[index+1:]
	}
	return strings.Count(name, "/") + 1
}

func shortPackage(pkg string) string {
	parts := strings.Split(pkg, "/")
	if len(parts) == 0 {
		return pkg
	}
	return parts[len(parts)-1]
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// ToCheckResult turns a `go test -json` summary into a check result. exitCode is
// the test command's exit status, which catches build failures that produce no
// test events at all.
func (s GoTestSummary) ToCheckResult(base CheckResult, exitCode int) CheckResult {
	result := base
	result.SchemaVersion = CheckSchema
	result.Status = StatusPass
	switch {
	case s.Failed > 0 || exitCode != 0:
		result.Status = StatusFail
	case s.Total == 0:
		result.Status = StatusSkip
	}
	result.Metrics = map[string]float64{
		"tests_total":   float64(s.Total),
		"tests_passed":  float64(s.Passed),
		"tests_failed":  float64(s.Failed),
		"tests_skipped": float64(s.Skipped),
		"packages":      float64(s.Packages),
	}
	result.Details = s.Details
	if result.DurationMS == 0 && s.ElapsedSec > 0 {
		result.DurationMS = s.ElapsedSec * 1000
	}
	result.Summary = s.summaryLine(exitCode)
	return result
}

func (s GoTestSummary) summaryLine(exitCode int) string {
	if s.Total == 0 {
		if exitCode != 0 {
			detail := ""
			if len(s.Anomalies) > 0 {
				detail = " " + s.Anomalies[0]
			}
			return fmt.Sprintf("No tests ran and the command exited with code %d.%s", exitCode, detail)
		}
		return "No tests ran."
	}
	parts := []string{fmt.Sprintf("%d of %d tests passed", s.Passed, s.Total)}
	if s.Failed > 0 {
		failed := s.FailedTests
		if len(failed) > 3 {
			failed = failed[:3]
		}
		parts = append(parts, fmt.Sprintf("%d failed (%s)", s.Failed, strings.Join(failed, ", ")))
	}
	if s.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", s.Skipped))
	}
	if s.Failed == 0 && exitCode != 0 {
		parts = append(parts, fmt.Sprintf("the command exited with code %d", exitCode))
	}
	if s.Truncated > 0 {
		parts = append(parts, fmt.Sprintf("%d further results are not listed", s.Truncated))
	}
	return strings.Join(parts, ", ") + "."
}
