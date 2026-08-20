package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/assurance"
)

func goos() string      { return runtime.GOOS }
func goarch() string    { return runtime.GOARCH }
func goVersion() string { return runtime.Version() }

// ------------------------------------------------------------------ emit ---

func runEmit(args []string) error {
	flags := flag.NewFlagSet("emit", flag.ExitOnError)
	id := flags.String("id", "", "catalog check id")
	instance := flags.String("instance", "", "matrix instance name, such as an ecosystem or platform")
	stage := flags.String("stage", "", "override the stage declared in the catalog")
	level := flags.String("level", "", "override the level declared in the catalog")
	status := flags.String("status", "", "explicit status: pass, fail, degraded, or skip")
	exitCode := flags.Int("exit-code", 0, "command exit code that decides the status")
	summary := flags.String("summary", "", "one-line plain-language summary")
	durationMS := flags.Float64("duration-ms", 0, "check duration in milliseconds")
	startedAt := flags.String("started-at", "", "RFC 3339 start time")
	out := flags.String("out", "assurance-results", "directory to write the check result into")
	catalogPath := flags.String("catalog", "", "assurance catalog path")
	detailsFile := flags.String("details-jsonl", "", "file of JSON detail objects, one per line")
	stepSummary := flags.Bool("step-summary", false, "append a markdown block to the workflow step summary")
	var metrics, details, artifacts, links stringList
	flags.Var(&metrics, "metric", "numeric metric as name=value (repeatable)")
	flags.Var(&details, "detail", "sub-result as name=status[:note] (repeatable)")
	flags.Var(&artifacts, "artifact", "produced file as name=path (repeatable)")
	flags.Var(&links, "link", "related link as label=url (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *id == "" || *summary == "" {
		return fmt.Errorf("emit requires --id and --summary")
	}

	result := baseResult(*id, *instance)
	if *startedAt != "" {
		result.StartedAt = *startedAt
	}
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	result.DurationMS = *durationMS
	if result.DurationMS == 0 {
		result.DurationMS = elapsedMS(result.StartedAt, result.FinishedAt)
	}
	result.Summary = *summary
	result.Status = statusFromExit(*exitCode)
	if *status != "" {
		result.Status = assurance.Status(*status)
	}
	catalogCtx := loadContext(*catalogPath)
	if err := applyCatalog(&result, catalogCtx.catalog, *stage, *level); err != nil {
		return err
	}
	for _, entry := range metrics {
		name, raw, err := splitPair(entry, "metric")
		if err != nil {
			return err
		}
		value, convErr := strconv.ParseFloat(raw, 64)
		if convErr != nil {
			return fmt.Errorf("metric %q must be numeric: %w", entry, convErr)
		}
		if result.Metrics == nil {
			result.Metrics = map[string]float64{}
		}
		result.Metrics[name] = value
	}
	for _, entry := range details {
		detail, err := parseDetail(entry)
		if err != nil {
			return err
		}
		result.Details = append(result.Details, detail)
	}
	if *detailsFile != "" {
		loaded, err := readDetailLines(*detailsFile)
		if err != nil {
			return err
		}
		result.Details = append(result.Details, loaded...)
	}
	for _, entry := range artifacts {
		name, path, err := splitPair(entry, "artifact")
		if err != nil {
			return err
		}
		artifact := assurance.Artifact{Name: name}
		if info, statErr := os.Stat(path); statErr == nil && info.Mode().IsRegular() {
			artifact.Bytes = info.Size()
		}
		result.Artifacts = append(result.Artifacts, artifact)
	}
	for _, entry := range links {
		label, url, err := splitPair(entry, "link")
		if err != nil {
			return err
		}
		result.Links = append(result.Links, assurance.Link{Label: label, URL: url})
	}
	return writeResult(*out, result, *stepSummary, reproduceFor(catalogCtx.catalog, result.ID))
}

func parseDetail(entry string) (assurance.Detail, error) {
	name, rest, err := splitPair(entry, "detail")
	if err != nil {
		return assurance.Detail{}, err
	}
	status, note, _ := strings.Cut(rest, ":")
	detail := assurance.Detail{
		Name:   name,
		Status: assurance.Status(strings.TrimSpace(status)),
		Note:   strings.TrimSpace(note),
	}
	if !detail.Status.Valid() {
		return assurance.Detail{}, fmt.Errorf("detail %q has unsupported status %q", entry, status)
	}
	return detail, nil
}

// readDetailLines reads sub-results from a JSONL file so shell steps can record
// many items without building long command lines.
func readDetailLines(path string) ([]assurance.Detail, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open details file: %w", err)
	}
	defer file.Close()
	var details []assurance.Detail
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var raw struct {
			Name       string  `json:"name"`
			Status     string  `json:"status"`
			ExitCode   *int    `json:"exit_code"`
			Note       string  `json:"note"`
			DurationMS float64 `json:"duration_ms"`
			DurationS  float64 `json:"duration_s"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("decode details file line: %w", err)
		}
		detail := assurance.Detail{Name: raw.Name, Note: raw.Note, DurationMS: raw.DurationMS}
		if detail.DurationMS == 0 && raw.DurationS > 0 {
			detail.DurationMS = raw.DurationS * 1000
		}
		switch {
		case raw.Status != "":
			detail.Status = assurance.Status(raw.Status)
		case raw.ExitCode != nil:
			detail.Status = statusFromExit(*raw.ExitCode)
		default:
			detail.Status = assurance.StatusPass
		}
		if detail.Name == "" || !detail.Status.Valid() {
			return nil, fmt.Errorf("details file line %q needs a name and a valid status", line)
		}
		details = append(details, detail)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read details file: %w", err)
	}
	return details, nil
}

func elapsedMS(started, finished string) float64 {
	start, err := time.Parse(time.RFC3339, started)
	if err != nil {
		return 0
	}
	end, err := time.Parse(time.RFC3339, finished)
	if err != nil {
		return 0
	}
	return float64(end.Sub(start).Milliseconds())
}

// ---------------------------------------------------------------- gotest ---

func runGoTest(args []string) error {
	flags := flag.NewFlagSet("gotest", flag.ExitOnError)
	id := flags.String("id", "", "catalog check id")
	instance := flags.String("instance", "", "matrix instance name")
	stage := flags.String("stage", "", "override the stage declared in the catalog")
	level := flags.String("level", "", "override the level declared in the catalog")
	input := flags.String("input", "", `file holding "go test -json" output`)
	exitCode := flags.Int("exit-code", 0, "exit code of the test command")
	echo := flags.Bool("echo", false, "replay test output to stdout so CI logs stay readable")
	out := flags.String("out", "assurance-results", "directory to write the check result into")
	catalogPath := flags.String("catalog", "", "assurance catalog path")
	stepSummary := flags.Bool("step-summary", false, "append a markdown block to the workflow step summary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *id == "" || *input == "" {
		return fmt.Errorf("gotest requires --id and --input")
	}
	file, err := os.Open(*input)
	if err != nil {
		return fmt.Errorf("open test output: %w", err)
	}
	defer file.Close()
	var echoWriter *os.File
	if *echo {
		echoWriter = os.Stdout
	}
	summary, err := assurance.ParseGoTestEvents(file, writerOrNil(echoWriter))
	if err != nil {
		return err
	}
	result := baseResult(*id, *instance)
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	catalogCtx := loadContext(*catalogPath)
	if err := applyCatalog(&result, catalogCtx.catalog, *stage, *level); err != nil {
		return err
	}
	return writeResult(*out, summary.ToCheckResult(result, *exitCode), *stepSummary, reproduceFor(catalogCtx.catalog, result.ID))
}

// reproduceFor returns the catalog's local reproduction command for a check.
func reproduceFor(catalog *assurance.Catalog, id string) [][]string {
	if catalog == nil {
		return nil
	}
	if check, found := catalog.Check(id); found {
		return check.Reproduce
	}
	return nil
}

func writerOrNil(file *os.File) *os.File {
	if file == nil {
		return nil
	}
	return file
}

// --------------------------------------------------------------- convert ---

func runConvert(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("convert requires a manifest kind: benchmark-run or sbom-assurance")
	}
	kind := args[0]
	flags := flag.NewFlagSet("convert "+kind, flag.ExitOnError)
	id := flags.String("id", "", "catalog check id")
	instance := flags.String("instance", "", "matrix instance name")
	stage := flags.String("stage", "", "override the stage declared in the catalog")
	level := flags.String("level", "", "override the level declared in the catalog")
	input := flags.String("input", "", "manifest path")
	out := flags.String("out", "assurance-results", "directory to write the check result into")
	catalogPath := flags.String("catalog", "", "assurance catalog path")
	stepSummary := flags.Bool("step-summary", false, "append a markdown block to the workflow step summary")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *id == "" || *input == "" {
		return fmt.Errorf("convert requires --id and --input")
	}
	data, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	result := baseResult(*id, *instance)
	result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	catalogCtx := loadContext(*catalogPath)
	if err := applyCatalog(&result, catalogCtx.catalog, *stage, *level); err != nil {
		return err
	}
	var converted assurance.CheckResult
	switch kind {
	case "benchmark-run":
		converted, err = assurance.ConvertBenchmarkRun(data, result)
	case "sbom-assurance":
		converted, err = assurance.ConvertSBOMAssurance(data, result)
	default:
		return fmt.Errorf("unsupported manifest kind %q", kind)
	}
	if err != nil {
		return err
	}
	return writeResult(*out, converted, *stepSummary, reproduceFor(catalogCtx.catalog, converted.ID))
}

// -------------------------------------------------------- verify-release ---

func runVerifyRelease(args []string) error {
	flags := flag.NewFlagSet("verify-release", flag.ExitOnError)
	dir := flags.String("dir", "", "directory holding downloaded release assets")
	version := flags.String("version", "", "release version without the leading v")
	scope := flags.String("scope", "full", "full checks every expected asset; native checks only this platform's")
	out := flags.String("out", "assurance-results", "directory to write check results into")
	workDir := flags.String("work", "", "extraction directory (a temporary directory by default)")
	catalogPath := flags.String("catalog", "", "assurance catalog path")
	stepSummary := flags.Bool("step-summary", false, "append markdown blocks to the workflow step summary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *version == "" {
		return fmt.Errorf("verify-release requires --dir and --version")
	}
	trimmed := strings.TrimPrefix(*version, "v")
	catalogCtx := loadContext(*catalogPath)
	work := *workDir
	if work == "" {
		created, err := os.MkdirTemp("", "assurance-release-")
		if err != nil {
			return fmt.Errorf("create extraction directory: %w", err)
		}
		defer os.RemoveAll(created)
		work = created
	}

	failures := 0
	emit := func(result assurance.CheckResult) error {
		if result.Status == assurance.StatusFail {
			failures++
		}
		return writeResult(*out, result, *stepSummary, reproduceFor(catalogCtx.catalog, result.ID))
	}

	if *scope == "full" {
		presence, err := assurance.InspectAssets(*dir, trimmed)
		if err != nil {
			return err
		}
		result := baseResult("release-assets", "")
		result.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		if err := applyCatalog(&result, catalogCtx.catalog, "", ""); err != nil {
			return err
		}
		result.Status = assurance.StatusPass
		result.Metrics = map[string]float64{
			"assets":         float64(len(presence.Present)),
			"assets_missing": float64(len(presence.Missing)),
		}
		for _, name := range presence.Present {
			result.Details = append(result.Details, assurance.Detail{Name: name, Status: assurance.StatusPass})
		}
		for _, name := range presence.Missing {
			result.Status = assurance.StatusFail
			result.Details = append(result.Details, assurance.Detail{
				Name: name, Status: assurance.StatusFail, Note: "not attached to the release",
			})
		}
		result.Summary = fmt.Sprintf("%d of %d expected release assets are attached.",
			len(presence.Present), len(presence.Present)+len(presence.Missing))
		if len(presence.Extra) > 0 {
			result.Summary += fmt.Sprintf(" %d unexpected file(s): %s.",
				len(presence.Extra), strings.Join(presence.Extra, ", "))
		}
		if err := emit(result); err != nil {
			return err
		}
	}

	sumsData, err := os.ReadFile(filepath.Join(*dir, "SHA256SUMS"))
	if err != nil {
		return fmt.Errorf("read SHA256SUMS: %w", err)
	}
	entries, err := assurance.ParseSHA256SUMS(sumsData)
	if err != nil {
		return err
	}
	outcome, err := assurance.VerifyChecksums(*dir, entries)
	if err != nil {
		return err
	}
	checksums := baseResult("release-checksums", "")
	checksums.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if err := applyCatalog(&checksums, catalogCtx.catalog, "", ""); err != nil {
		return err
	}
	checksums.Status = assurance.StatusPass
	checksums.Metrics = map[string]float64{
		"verified":   float64(len(outcome.Verified)),
		"mismatched": float64(len(outcome.Mismatched)),
		"listed":     float64(len(entries)),
	}
	for _, name := range outcome.Verified {
		checksums.Details = append(checksums.Details, assurance.Detail{Name: name, Status: assurance.StatusPass})
	}
	for _, name := range outcome.Mismatched {
		checksums.Status = assurance.StatusFail
		checksums.Details = append(checksums.Details, assurance.Detail{
			Name: name, Status: assurance.StatusFail, Note: "hash does not match SHA256SUMS",
		})
	}
	for _, name := range outcome.Unlisted {
		checksums.Status = assurance.StatusFail
		checksums.Details = append(checksums.Details, assurance.Detail{
			Name: name, Status: assurance.StatusFail, Note: "downloaded but absent from SHA256SUMS",
		})
	}
	if *scope == "full" && len(outcome.NotDownloaded) > 0 {
		checksums.Status = assurance.StatusFail
		for _, name := range outcome.NotDownloaded {
			checksums.Details = append(checksums.Details, assurance.Detail{
				Name: name, Status: assurance.StatusFail, Note: "listed in SHA256SUMS but not attached",
			})
		}
	}
	checksums.Summary = fmt.Sprintf("%d downloaded assets match SHA256SUMS, which lists %d files.",
		len(outcome.Verified), len(entries))
	if len(outcome.Mismatched) > 0 {
		checksums.Summary = fmt.Sprintf("%d assets do not match SHA256SUMS: %s.",
			len(outcome.Mismatched), strings.Join(outcome.Mismatched, ", "))
	}
	if err := emit(checksums); err != nil {
		return err
	}

	probes, err := assurance.ProbeNativeBinaries(context.Background(), *dir, trimmed, work)
	if err != nil {
		return err
	}
	binaries := baseResult("release-binaries", runtime.GOOS+"-"+runtime.GOARCH)
	binaries.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if err := applyCatalog(&binaries, catalogCtx.catalog, "", ""); err != nil {
		return err
	}
	binaries.Status = assurance.StatusPass
	passed := 0
	for _, probe := range probes {
		note := probe.Note
		if probe.Status == assurance.StatusPass {
			note = probe.Output
			passed++
		} else {
			binaries.Status = assurance.StatusFail
		}
		binaries.Details = append(binaries.Details, assurance.Detail{
			Name: probe.Archive, Status: probe.Status, Note: firstLine(note),
		})
	}
	binaries.Metrics = map[string]float64{"binaries": float64(len(probes)), "binaries_passed": float64(passed)}
	binaries.Summary = fmt.Sprintf("%d of %d %s/%s binaries report version %s.",
		passed, len(probes), runtime.GOOS, runtime.GOARCH, trimmed)
	if err := emit(binaries); err != nil {
		return err
	}

	if failures > 0 {
		return blockingError{message: fmt.Sprintf("%d release verification check(s) failed", failures), code: 1}
	}
	return nil
}

func firstLine(value string) string {
	if index := strings.IndexAny(value, "\r\n"); index >= 0 {
		return strings.TrimSpace(value[:index])
	}
	return strings.TrimSpace(value)
}

// --------------------------------------------------------------- verdict ---

func runVerdict(args []string) error {
	flags := flag.NewFlagSet("verdict", flag.ExitOnError)
	resultsDir := flags.String("results", "assurance-results", "directory of collected check results")
	stage := flags.String("stage", "", "stage to judge")
	catalogPath := flags.String("catalog", "", "assurance catalog path")
	tag := flags.String("tag", "", "release tag, when one exists")
	stepSummary := flags.Bool("step-summary", false, "append the verdict to the workflow step summary")
	jsonOut := flags.String("json", "", "also write the stage report as JSON to this path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *stage == "" {
		return fmt.Errorf("verdict requires --stage")
	}
	selected := assurance.Stage(*stage)
	if !selected.Valid() {
		return fmt.Errorf("unsupported stage %q", *stage)
	}
	catalog, _, err := mustLoadCatalog(*catalogPath)
	if err != nil {
		return err
	}
	results, err := assurance.LoadResults(*resultsDir)
	if err != nil {
		return err
	}
	report := assurance.BuildReport(catalog, filterStage(results, selected), assurance.BuildOptions{
		Release:     assurance.Release{Tag: *tag, Version: strings.TrimPrefix(*tag, "v")},
		Stages:      []assurance.Stage{selected},
		StageRuns:   map[assurance.Stage]string{selected: runURL()},
		GeneratedBy: "assurance",
	})
	markdown := assurance.RenderMarkdown(report, assurance.MarkdownOptions{
		Heading:       selected.Title(),
		IncludeChecks: true,
	})
	fmt.Print(markdown)
	if *stepSummary {
		if err := appendStepSummary(markdown); err != nil {
			return err
		}
	}
	if *jsonOut != "" {
		data, encodeErr := report.Encode()
		if encodeErr != nil {
			return encodeErr
		}
		if err := os.WriteFile(*jsonOut, data, 0o644); err != nil {
			return fmt.Errorf("write stage report: %w", err)
		}
	}
	if report.Verdict.Blocking() {
		return blockingError{
			message: fmt.Sprintf("%s did not pass: %s", selected.Title(), strings.Join(blockers(report.Verdict), ", ")),
			code:    1,
		}
	}
	return nil
}

func blockers(verdict assurance.Verdict) []string {
	var names []string
	names = append(names, verdict.GatesFailed...)
	for _, id := range verdict.MissingChecks {
		names = append(names, id+" (no result)")
	}
	sort.Strings(names)
	return names
}

func filterStage(results []assurance.CheckResult, stage assurance.Stage) []assurance.CheckResult {
	var selected []assurance.CheckResult
	for _, result := range results {
		if result.Stage == stage {
			selected = append(selected, result)
		}
	}
	return selected
}
