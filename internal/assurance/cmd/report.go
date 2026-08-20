package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bomly-dev/bomly-cli/internal/assurance"
)

// defaultReportDir is the repository directory holding published reports.
const defaultReportDir = "docs/assurance"

func runReport(args []string) error {
	flags := flag.NewFlagSet("report", flag.ExitOnError)
	resultsDir := flags.String("results", "assurance-results", "directory of collected check results")
	catalogPath := flags.String("catalog", "", "assurance catalog path")
	tag := flags.String("tag", "", "release tag, such as v0.24.0")
	commit := flags.String("commit", "", "release commit")
	releaseURL := flags.String("url", "", "release page URL")
	publishedAt := flags.String("published-at", "", "RFC 3339 publication time")
	previous := flags.String("previous", "", "previous release report for trends (auto by default)")
	outDir := flags.String("out", "", "directory to write reports and the index into")
	summaryOut := flags.String("summary-out", "", "write the markdown summary to this path")
	stepSummary := flags.Bool("step-summary", false, "append the markdown summary to the workflow step summary")
	stages := flags.String("stages", "", "comma-separated stages to include (every stage by default)")
	prerequisitesRun := flags.String("prerequisites-run", "", "workflow run URL for the prerequisites stage")
	preReleaseRun := flags.String("pre-release-run", "", "workflow run URL for the pre-release stage")
	assessmentRun := flags.String("assessment-run", "", "workflow run URL for the post-release stage")
	failOnBlocking := flags.Bool("fail-on-blocking", false, "exit non-zero when a gate check did not pass")
	allowUnknown := flags.Bool("allow-unknown", false, "report results the catalog does not declare instead of failing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *tag == "" {
		return fmt.Errorf("report requires --tag")
	}
	catalog, catalogFile, err := mustLoadCatalog(*catalogPath)
	if err != nil {
		return err
	}
	results, err := assurance.LoadResults(*resultsDir)
	if err != nil {
		return err
	}
	targetDir := *outDir
	if targetDir == "" {
		root := filepath.Dir(filepath.Dir(catalogFile))
		targetDir = filepath.Join(root, filepath.FromSlash(defaultReportDir))
		if filepath.Base(filepath.Dir(catalogFile)) == "assurance" {
			targetDir = filepath.Dir(catalogFile)
		}
	}
	indexPath := filepath.Join(targetDir, "index.json")

	index := assurance.Index{SchemaVersion: assurance.IndexSchema}
	if data, readErr := os.ReadFile(indexPath); readErr == nil {
		loaded, parseErr := assurance.ParseIndex(data)
		if parseErr != nil {
			return parseErr
		}
		index = loaded
	}

	previousReport, previousTag, err := resolvePrevious(*previous, *tag, targetDir, index)
	if err != nil {
		return err
	}

	options := assurance.BuildOptions{
		Release: assurance.Release{
			Tag: *tag, Version: strings.TrimPrefix(*tag, "v"),
			Commit: *commit, URL: *releaseURL, PublishedAt: *publishedAt,
		},
		StageRuns: map[assurance.Stage]string{
			assurance.StagePrerequisites: *prerequisitesRun,
			assurance.StagePreRelease:    *preReleaseRun,
			assurance.StagePostRelease:   *assessmentRun,
		},
		Previous:        previousReport,
		IncludeEvidence: true,
		GeneratedBy:     "assurance",
	}
	if *stages != "" {
		for _, name := range strings.Split(*stages, ",") {
			stage := assurance.Stage(strings.TrimSpace(name))
			if !stage.Valid() {
				return fmt.Errorf("unsupported stage %q", name)
			}
			options.Stages = append(options.Stages, stage)
		}
	}
	report := assurance.BuildReport(catalog, results, options)

	reportPath := filepath.Join(targetDir, "reports", *tag+".json")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	data, err := report.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		return fmt.Errorf("write assurance report: %w", err)
	}

	index.SchemaVersion = assurance.IndexSchema
	index.GeneratedAt = report.GeneratedAt
	index.Releases = upsertIndexEntry(index.Releases, assurance.IndexEntry{
		Tag: report.Release.Tag, Version: report.Release.Version,
		PublishedAt: report.Release.PublishedAt, GeneratedAt: report.GeneratedAt,
		Verdict: report.Verdict.Overall, Gates: len(report.Verdict.GatesFailed),
		Path: "reports/" + report.Release.Tag + ".json",
	})
	if len(index.Releases) > 0 {
		index.Latest = index.Releases[0].Tag
	}
	indexData, err := index.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(indexPath, indexData, 0o644); err != nil {
		return fmt.Errorf("write assurance index: %w", err)
	}

	markdown := assurance.RenderMarkdown(report, assurance.MarkdownOptions{
		IncludeChecks: true, IncludeTrends: true,
	})
	fmt.Print(markdown)
	if *summaryOut != "" {
		if err := os.WriteFile(*summaryOut, []byte(markdown), 0o644); err != nil {
			return fmt.Errorf("write markdown summary: %w", err)
		}
	}
	if *stepSummary {
		if err := appendStepSummary(markdown); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", reportPath, indexPath)
	if previousTag != "" {
		fmt.Fprintf(os.Stderr, "compared against %s\n", previousTag)
	}
	if len(report.Unknown) > 0 && !*allowUnknown {
		return blockingError{
			message: fmt.Sprintf("%d reported check(s) are not declared in the catalog", len(report.Unknown)),
			code:    3,
		}
	}
	if *failOnBlocking && report.Verdict.Blocking() {
		return blockingError{
			message: "the release did not pass every gate check: " + strings.Join(blockers(report.Verdict), ", "),
			code:    1,
		}
	}
	return nil
}

func resolvePrevious(flagValue, tag, targetDir string, index assurance.Index) (*assurance.Report, string, error) {
	switch flagValue {
	case "none":
		return nil, "", nil
	case "":
		previousTag := previousRelease(tag, index)
		if previousTag == "" {
			return nil, "", nil
		}
		path := filepath.Join(targetDir, "reports", previousTag+".json")
		report, err := assurance.LoadReport(path)
		if err != nil {
			// A missing previous report is not an error: the first release has
			// none, and an older one may predate the framework.
			return nil, "", nil
		}
		return &report, previousTag, nil
	default:
		report, err := assurance.LoadReport(flagValue)
		if err != nil {
			return nil, "", err
		}
		return &report, report.Release.Tag, nil
	}
}

// previousRelease returns the highest released tag below the current one.
func previousRelease(tag string, index assurance.Index) string {
	current, err := semver.NewVersion(strings.TrimPrefix(tag, "v"))
	if err != nil {
		return ""
	}
	best := ""
	var bestVersion *semver.Version
	for _, entry := range index.Releases {
		candidate, parseErr := semver.NewVersion(strings.TrimPrefix(entry.Tag, "v"))
		if parseErr != nil || !candidate.LessThan(current) {
			continue
		}
		if bestVersion == nil || candidate.GreaterThan(bestVersion) {
			bestVersion = candidate
			best = entry.Tag
		}
	}
	return best
}

func upsertIndexEntry(entries []assurance.IndexEntry, entry assurance.IndexEntry) []assurance.IndexEntry {
	replaced := false
	for index, existing := range entries {
		if existing.Tag == entry.Tag {
			entries[index] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		left, leftErr := semver.NewVersion(strings.TrimPrefix(entries[i].Tag, "v"))
		right, rightErr := semver.NewVersion(strings.TrimPrefix(entries[j].Tag, "v"))
		if leftErr != nil || rightErr != nil {
			return entries[i].Tag > entries[j].Tag
		}
		return left.GreaterThan(right)
	})
	return entries
}

// -------------------------------------------------------- catalog-validate ---

func runCatalogValidate(args []string) error {
	flags := flag.NewFlagSet("catalog-validate", flag.ExitOnError)
	catalogPath := flags.String("catalog", "", "assurance catalog path")
	checkID := flags.String("check", "", "print one check")
	evidenceID := flags.String("evidence", "", "print one evidence claim")
	skipArtifacts := flags.Bool("skip-artifacts", false, "skip repository artifact hash verification")
	refresh := flags.Bool("refresh", false, "rewrite recorded checksums from the files they name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	catalog, catalogFile, err := mustLoadCatalog(*catalogPath)
	if err != nil {
		return err
	}
	if *refresh {
		root, rootErr := repositoryRoot()
		if rootErr != nil {
			return rootErr
		}
		changed, refreshErr := catalog.RefreshArtifacts(root)
		if refreshErr != nil {
			return refreshErr
		}
		if changed > 0 {
			data, encodeErr := catalog.Encode()
			if encodeErr != nil {
				return encodeErr
			}
			if err := os.WriteFile(catalogFile, data, 0o644); err != nil {
				return fmt.Errorf("write assurance catalog: %w", err)
			}
		}
		fmt.Printf("Refreshed %d recorded checksum(s) in %s.\n", changed, relativeToWorkingDir(catalogFile))
		return nil
	}
	if !*skipArtifacts {
		root, rootErr := repositoryRoot()
		if rootErr != nil {
			return rootErr
		}
		if err := catalog.VerifyArtifacts(root); err != nil {
			return err
		}
	}
	fmt.Printf("Validated %s: %d areas, %d checks, %d evidence claims.\n",
		relativeToWorkingDir(catalogFile), len(catalog.Areas), len(catalog.Checks), len(catalog.Evidence))

	if *checkID != "" || *evidenceID != "" {
		if *checkID != "" {
			check, found := catalog.Check(*checkID)
			if !found {
				return fmt.Errorf("unknown check %q", *checkID)
			}
			printCheck(catalog, check)
		}
		if *evidenceID != "" {
			for _, evidence := range catalog.Evidence {
				if evidence.ID == *evidenceID {
					printEvidence(evidence)
					return nil
				}
			}
			return fmt.Errorf("unknown evidence claim %q", *evidenceID)
		}
		return nil
	}
	for _, stage := range assurance.Stages() {
		checks := catalog.ChecksForStage(stage)
		if len(checks) == 0 {
			continue
		}
		fmt.Printf("\n%s (%d checks)\n", stage.Title(), len(checks))
		for _, check := range checks {
			instances := ""
			if len(check.ExpectedInstances) > 0 {
				instances = fmt.Sprintf(", %d instances", len(check.ExpectedInstances))
			}
			fmt.Printf("  %-24s %-9s %s%s\n", check.ID, check.Level, check.Title, instances)
		}
	}
	fmt.Printf("\nEvidence (%d claims)\n", len(catalog.Evidence))
	for _, evidence := range catalog.Evidence {
		fmt.Printf("  %-26s %-16s backed by %s\n", evidence.ID, evidence.EvidenceLevel, evidence.CheckID)
	}
	return nil
}

func printCheck(catalog assurance.Catalog, check assurance.Check) {
	fmt.Printf("\n%s — %s\n", check.ID, check.Title)
	fmt.Printf("  Area: %s (%s); stage: %s; level: %s\n",
		check.Area, catalog.AreaTitle(check.Area), check.Stage, check.Level)
	fmt.Printf("  Source: %s job %s\n", check.Source.Workflow, check.Source.Job)
	for _, instance := range check.ExpectedInstances {
		fmt.Printf("  Instance: %s\n", instance.Name)
	}
	for _, command := range check.Reproduce {
		fmt.Printf("  Reproduce: %s\n", shellCommand(command))
	}
	for _, claim := range check.Proves {
		fmt.Printf("  Proves: %s\n", claim)
	}
	for _, limitation := range check.Limitations {
		fmt.Printf("  Limitation: %s\n", limitation)
	}
}

func printEvidence(evidence assurance.Evidence) {
	fmt.Printf("\n%s — %s\n", evidence.ID, evidence.Title)
	fmt.Printf("  Area: %s; evidence: %s; backed by check %s\n",
		evidence.Area, evidence.EvidenceLevel, evidence.CheckID)
	for _, input := range evidence.Inputs {
		fmt.Printf("  Input: %s %s\n", input.Kind, input.Location)
	}
	for _, command := range evidence.Reproduce {
		fmt.Printf("  Reproduce: %s\n", shellCommand(command))
	}
	for _, claim := range evidence.Proves {
		fmt.Printf("  Proves: %s\n", claim)
	}
	for _, limitation := range evidence.Limitations {
		fmt.Printf("  Limitation: %s\n", limitation)
	}
}

func relativeToWorkingDir(path string) string {
	working, err := os.Getwd()
	if err != nil {
		return path
	}
	relative, err := filepath.Rel(working, path)
	if err != nil {
		return path
	}
	return relative
}

func shellCommand(command []string) string {
	quoted := make([]string, len(command))
	for index, argument := range command {
		if argument != "" && strings.IndexFunc(argument, func(r rune) bool {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return false
			}
			return !strings.ContainsRune("@%_+=:,./-", r)
		}) == -1 {
			quoted[index] = argument
			continue
		}
		quoted[index] = "'" + strings.ReplaceAll(argument, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}
