package qa

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var githubAPIBaseURL = "https://api.github.com"
var githubTokenEnvNames = []string{"BOMLY_QA_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"}

// RunOptions configures one Dependency Graph QA run.
type RunOptions struct {
	ManifestPath    string
	RunDir          string
	BomlyPath       string
	SelectedCases   []string
	SelectedSources []string
}

// Run executes the Dependency Graph QA harness.
func Run(ctx context.Context, opts RunOptions) error {
	return run(ctx, opts.ManifestPath, opts.RunDir, opts.BomlyPath, opts.SelectedCases, opts.SelectedSources)
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func run(ctx context.Context, manifest, runDir, bomlyPath string, selectedCases, selectedSources []string) error {
	targets, err := LoadScanTargets(manifest)
	if err != nil {
		return err
	}
	sources, err := filterBaselineSources(defaultBaselineSources(), selectedSources)
	if err != nil {
		return err
	}
	targets = QAScanTargets(targets)
	selectedRun := len(selectedCases) > 0
	targets, err = filterScanTargets(targets, selectedCases)
	if err != nil {
		return err
	}

	casesDir := filepath.Join(runDir, "cases")
	if err := prepareCasesDir(casesDir, targets, selectedRun); err != nil {
		return err
	}

	failures := 0
	for _, target := range targets {
		caseDir := filepath.Join(casesDir, target.Name)
		if err := os.MkdirAll(caseDir, 0o755); err != nil {
			return fmt.Errorf("create case dir: %w", err)
		}
		if missing := missingTool(target.Tools); missing != "" {
			if err := WriteStatusSummary(filepath.Join(caseDir, "qa-summary.json"), target.Name, "skipped", "missing required tool: "+missing); err != nil {
				return err
			}
			fmt.Printf("%s: skipped (missing required tool: %s)\n", target.Name, missing)
			continue
		}

		fmt.Printf("qa: running %s (%s)\n", target.Name, repoSlug(target.URL))
		if err := runCase(ctx, bomlyPath, caseDir, target, sources); err != nil {
			failures++
			summaryPath := filepath.Join(caseDir, "qa-summary.json")
			if _, statErr := os.Stat(summaryPath); os.IsNotExist(statErr) {
				if writeErr := WriteStatusSummary(summaryPath, target.Name, "failed", err.Error()); writeErr != nil {
					return writeErr
				}
			}
			fmt.Printf("%s: failed (%s)\n", target.Name, err)
			continue
		}
	}

	fmt.Printf("qa: wrote artifacts to %s\n", runDir)
	fmt.Printf("qa: completed %d case(s) with %d failure(s)\n", len(targets), failures)
	if failures > 0 {
		return fmt.Errorf("%d QA case(s) failed", failures)
	}
	return nil
}

func prepareCasesDir(casesDir string, targets []ScanTarget, selectedRun bool) error {
	if !selectedRun {
		if err := os.RemoveAll(casesDir); err != nil {
			return fmt.Errorf("clean cases dir: %w", err)
		}
	}
	if err := os.MkdirAll(casesDir, 0o755); err != nil {
		return fmt.Errorf("create cases dir: %w", err)
	}
	if !selectedRun {
		return nil
	}
	for _, target := range targets {
		caseDir := filepath.Join(casesDir, target.Name)
		if err := os.RemoveAll(caseDir); err != nil {
			return fmt.Errorf("clean case dir %s: %w", target.Name, err)
		}
	}
	return nil
}

// ParseCaseNames parses a comma-separated case list.
func ParseCaseNames(value string) []string {
	return parseNameList(value)
}

// ParseSourceNames parses a comma-separated baseline source list.
func ParseSourceNames(value string) []string {
	return parseNameList(value)
}

func parseNameList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func filterScanTargets(targets []ScanTarget, selectedCases []string) ([]ScanTarget, error) {
	if len(selectedCases) == 0 {
		return targets, nil
	}
	targetsByName := make(map[string]ScanTarget, len(targets))
	for _, target := range targets {
		targetsByName[target.Name] = target
	}
	filtered := make([]ScanTarget, 0, len(selectedCases))
	missing := make([]string, 0)
	for _, name := range selectedCases {
		target, ok := targetsByName[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		filtered = append(filtered, target)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("unknown or non-QA-enabled case(s): %s", strings.Join(missing, ", "))
	}
	return filtered, nil
}

func runCase(ctx context.Context, bomlyPath, caseDir string, target ScanTarget, sources []baselineSource) error {
	checkoutDir := filepath.Join(caseDir, "checkout")

	if err := checkoutTarget(ctx, filepath.Join(caseDir, "logs", "checkout.log"), target, checkoutDir); err != nil {
		return fmt.Errorf("checkout failed: %w", err)
	}

	bomlySBOMs := requiredBomlySBOMs(sources)
	if len(bomlySBOMs) == 0 {
		return fmt.Errorf("no QA baseline sources selected")
	}
	for _, bomlySBOM := range bomlySBOMs {
		if err := os.MkdirAll(filepath.Join(caseDir, filepath.Dir(bomlySBOM.Artifact)), 0o755); err != nil {
			return fmt.Errorf("create bomly source dir: %w", err)
		}
	}
	scanArgs := []string{"scan", "-vv", "--path", checkoutDir}
	scanArgs = append(scanArgs, target.QAArgs()...)
	scanArgs = append(scanArgs, "--detectors", "-syft")
	for _, bomlySBOM := range bomlySBOMs {
		scanArgs = append(scanArgs, "--sbom-output", bomlySBOM.Format+"="+filepath.Join(caseDir, bomlySBOM.Artifact))
	}
	if err := runLoggedCommand(ctx, filepath.Join(caseDir, "sources", "bomly", "scan.log"), bomlyPath, scanArgs...); err != nil {
		return fmt.Errorf("bomly scan failed: %w", err)
	}

	provenanceSBOM, ok := bomlySBOMs["spdx-json"]
	if !ok {
		for _, artifact := range bomlySBOMs {
			provenanceSBOM = artifact
			break
		}
	}
	detectors, err := detectorsFromSBOM(filepath.Join(caseDir, provenanceSBOM.Artifact))
	if err != nil {
		return fmt.Errorf("read bomly detector provenance: %w", err)
	}

	sourceSummaries := make([]QASourceSummary, 0)
	for _, source := range sources {
		artifacts := sourceArtifacts(source.Name())
		summaryPath := filepath.Join(caseDir, artifacts.Summary)
		if missing := missingTool(source.Tools()); missing != "" {
			summary := QASourceSummary{Case: target.Name, Source: source.Name(), Status: "skipped", Reason: "missing required tool: " + missing, Artifacts: artifacts, Detectors: detectors}
			if err := WriteQASourceSummary(summaryPath, summary); err != nil {
				return err
			}
			sourceSummaries = append(sourceSummaries, summary)
			fmt.Printf("%s/%s: skipped (missing required tool: %s)\n", target.Name, source.Name(), missing)
			continue
		}
		sourceSBOM := filepath.Join(caseDir, artifacts.SBOM)
		artifactDir := filepath.Dir(sourceSBOM)
		if err := source.ProduceSBOM(ctx, artifactDir, checkoutDir, target, sourceSBOM); err != nil {
			summary := QASourceSummary{Case: target.Name, Source: source.Name(), Status: "failed", Reason: err.Error(), Artifacts: artifacts, Detectors: detectors}
			if writeErr := WriteQASourceSummary(summaryPath, summary); writeErr != nil {
				return writeErr
			}
			sourceSummaries = append(sourceSummaries, summary)
			fmt.Printf("%s/%s: failed (%s)\n", target.Name, source.Name(), err)
			continue
		}
		bomlyArtifact, ok := bomlySBOMs[source.BomlyFormat()]
		if !ok {
			return fmt.Errorf("missing bomly SBOM for source %s format %s", source.Name(), source.BomlyFormat())
		}
		bomlySBOM := filepath.Join(caseDir, bomlyArtifact.Artifact)
		diffPath := filepath.Join(caseDir, artifacts.Diff)
		diffLog := filepath.Join(caseDir, artifacts.DiffLog)
		if err := runOutputCommand(ctx, diffPath, diffLog, bomlyPath, "diff", "-vv", "--sbom", "--base", sourceSBOM, "--head", bomlySBOM, "--format", "json"); err != nil {
			summary := QASourceSummary{Case: target.Name, Source: source.Name(), Status: "failed", Reason: "bomly diff failed: " + err.Error(), Artifacts: artifacts, Detectors: detectors}
			if writeErr := WriteQASourceSummary(summaryPath, summary); writeErr != nil {
				return writeErr
			}
			sourceSummaries = append(sourceSummaries, summary)
			fmt.Printf("%s/%s: failed (%s)\n", target.Name, source.Name(), err)
			continue
		}
		summary, err := BuildQASourceSummary(target.Name, source.Name(), bomlySBOM, sourceSBOM, diffPath, artifacts)
		if err != nil {
			return fmt.Errorf("qa %s summary failed: %w", source.Name(), err)
		}
		if err := WriteQASourceSummary(summaryPath, summary); err != nil {
			return err
		}
		sourceSummaries = append(sourceSummaries, summary)
		fmt.Printf("%s/%s: completed packages(+%d ~%d -%d) relationships(bomly=%d source=%d matched=%d)\n",
			summary.Case,
			summary.Source,
			summary.PackageDiff.AddedPackageCount,
			summary.PackageDiff.ChangedPackageCount,
			summary.PackageDiff.RemovedPackageCount,
			summary.Relationships.BomlyRelationshipCount,
			summary.Relationships.SourceRelationshipCount,
			summary.Relationships.MatchedCount,
		)
	}

	summary := BuildQASummary(target.Name, sourceSummaries, detectors)
	if err := WriteQASummary(filepath.Join(caseDir, "qa-summary.json"), summary); err != nil {
		return err
	}
	if summary.Status == "failed" {
		return fmt.Errorf("one or more QA baseline sources failed")
	}
	return nil
}

type baselineSource interface {
	Name() string
	Tools() []string
	BomlyFormat() string
	ProduceSBOM(ctx context.Context, artifactDir, checkoutDir string, target ScanTarget, outputPath string) error
}

func defaultBaselineSources() []baselineSource {
	return []baselineSource{
		githubBaselineSource{},
		syftBaselineSource{format: "spdx-json", name: "syft", logName: "source.log"},
		syftBaselineSource{format: "cyclonedx-json", name: "syft-cyclonedx", logName: "source.log"},
	}
}

type githubBaselineSource struct{}

func (githubBaselineSource) Name() string        { return "github" }
func (githubBaselineSource) Tools() []string     { return nil }
func (githubBaselineSource) BomlyFormat() string { return "spdx-json" }
func (githubBaselineSource) ProduceSBOM(ctx context.Context, artifactDir, checkoutDir string, target ScanTarget, outputPath string) error {
	_ = checkoutDir
	responsePath := filepath.Join(artifactDir, "response.json")
	if err := fetchGitHubSBOM(ctx, repoSlug(target.URL), responsePath); err != nil {
		return fmt.Errorf("github sbom fetch failed: %w", err)
	}
	if err := UnwrapGitHubSBOM(responsePath, outputPath); err != nil {
		return fmt.Errorf("github sbom unwrap failed: %w", err)
	}
	return nil
}

type syftBaselineSource struct {
	name    string
	format  string
	logName string
}

func (s syftBaselineSource) Name() string        { return s.name }
func (syftBaselineSource) Tools() []string       { return []string{"syft"} }
func (s syftBaselineSource) BomlyFormat() string { return s.format }
func (s syftBaselineSource) ProduceSBOM(ctx context.Context, artifactDir, checkoutDir string, target ScanTarget, outputPath string) error {
	_ = target
	return runLoggedCommand(ctx, filepath.Join(artifactDir, s.logName), "syft", checkoutDir, "-o", s.format+"="+outputPath)
}

func sourceArtifacts(sourceName string) SourceArtifacts {
	prefix := filepath.ToSlash(filepath.Join("sources", sourceName))
	return SourceArtifacts{
		SBOM:    filepath.ToSlash(filepath.Join(prefix, "source.sbom.json")),
		Diff:    filepath.ToSlash(filepath.Join(prefix, "diff.json")),
		DiffLog: filepath.ToSlash(filepath.Join(prefix, "diff.log")),
		Log:     filepath.ToSlash(filepath.Join(prefix, "source.log")),
		Summary: filepath.ToSlash(filepath.Join(prefix, "qa-summary.json")),
	}
}

type bomlySBOMArtifact struct {
	Format   string
	Artifact string
}

func requiredBomlySBOMs(sources []baselineSource) map[string]bomlySBOMArtifact {
	out := make(map[string]bomlySBOMArtifact)
	for _, source := range sources {
		format := source.BomlyFormat()
		if _, exists := out[format]; exists {
			continue
		}
		out[format] = bomlySBOMArtifact{Format: format, Artifact: filepath.ToSlash(filepath.Join("sources", "bomly", bomlySBOMFilename(format)))}
	}
	return out
}

func bomlySBOMFilename(format string) string {
	switch format {
	case "cyclonedx-json":
		return "cyclonedx.sbom.json"
	default:
		return "spdx.sbom.json"
	}
}

func filterBaselineSources(sources []baselineSource, selectedSources []string) ([]baselineSource, error) {
	if len(selectedSources) == 0 {
		return sources, nil
	}
	byName := make(map[string]baselineSource, len(sources))
	for _, source := range sources {
		byName[source.Name()] = source
	}
	filtered := make([]baselineSource, 0, len(selectedSources))
	missing := make([]string, 0)
	for _, name := range selectedSources {
		source, ok := byName[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		filtered = append(filtered, source)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("unknown QA source(s): %s; available sources: %s", strings.Join(missing, ", "), strings.Join(sourceNames(sources), ", "))
	}
	return filtered, nil
}

func sourceNames(sources []baselineSource) []string {
	names := make([]string, 0, len(sources))
	for _, source := range sources {
		names = append(names, source.Name())
	}
	return names
}

func checkoutTarget(ctx context.Context, logPath string, target ScanTarget, checkoutDir string) error {
	args := []string{"clone", "--depth", "1", "--branch", target.Ref, target.URL, checkoutDir}
	return runLoggedCommand(ctx, logPath, "git", args...)
}

type githubSBOMHTTPError struct {
	StatusCode int
	Status     string
	URL        string
	Body       string
	OutputPath string
	AuthSource string
	Rate       githubRateInfo
}

func (e *githubSBOMHTTPError) Error() string {
	message := fmt.Sprintf("GET %s returned %s", e.URL, e.Status)
	if e.AuthSource != "" {
		message += "; authenticated with " + e.AuthSource
	} else {
		message += "; unauthenticated request (set BOMLY_QA_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN)"
	}
	if rate := e.Rate.String(); rate != "" {
		message += "; " + rate
	}
	if e.OutputPath != "" {
		message += "; response saved to " + e.OutputPath
	}
	if body := singleLine(e.Body); body != "" {
		message += "; response body: " + truncate(body, 500)
	}
	return message
}

type githubRateInfo struct {
	Limit      string
	Remaining  string
	Used       string
	Reset      string
	Resource   string
	RetryAfter string
	RequestID  string
}

func (r githubRateInfo) String() string {
	parts := make([]string, 0, 7)
	if r.Limit != "" {
		parts = append(parts, "limit="+r.Limit)
	}
	if r.Remaining != "" {
		parts = append(parts, "remaining="+r.Remaining)
	}
	if r.Used != "" {
		parts = append(parts, "used="+r.Used)
	}
	if r.Reset != "" {
		parts = append(parts, "reset="+r.Reset)
	}
	if r.Resource != "" {
		parts = append(parts, "resource="+r.Resource)
	}
	if r.RetryAfter != "" {
		parts = append(parts, "retry-after="+r.RetryAfter)
	}
	if r.RequestID != "" {
		parts = append(parts, "request-id="+r.RequestID)
	}
	if len(parts) == 0 {
		return ""
	}
	return "github rate limit: " + strings.Join(parts, " ")
}

func runLoggedCommand(ctx context.Context, logPath, name string, args ...string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("create log parent dir: %w", err)
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create log: %w", err)
	}
	defer func() { _ = logFile.Close() }()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	return cmd.Run()
}

func runOutputCommand(ctx context.Context, outputPath, logPath, name string, args ...string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output parent dir: %w", err)
	}
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = outFile.Close() }()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("create log parent dir: %w", err)
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create log: %w", err)
	}
	defer func() { _ = logFile.Close() }()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = outFile
	cmd.Stderr = logFile
	return cmd.Run()
}

func fetchGitHubSBOM(ctx context.Context, slug, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create github response parent dir: %w", err)
	}
	apiURL := githubAPIBaseURL + "/repos/" + slug + "/dependency-graph/sbom"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	authSource := ""
	if token, envName := githubTokenFromEnv(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		authSource = envName
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read github response body: %w", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("write github response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &githubSBOMHTTPError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			URL:        apiURL,
			Body:       string(body),
			OutputPath: path,
			AuthSource: authSource,
			Rate:       githubRateInfoFromHeaders(resp.Header),
		}
	}
	return nil
}

func githubTokenFromEnv() (string, string) {
	for _, name := range githubTokenEnvNames {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token, name
		}
	}
	return "", ""
}

func githubRateInfoFromHeaders(header http.Header) githubRateInfo {
	return githubRateInfo{
		Limit:      header.Get("X-RateLimit-Limit"),
		Remaining:  header.Get("X-RateLimit-Remaining"),
		Used:       header.Get("X-RateLimit-Used"),
		Reset:      formatGitHubRateReset(header.Get("X-RateLimit-Reset")),
		Resource:   header.Get("X-RateLimit-Resource"),
		RetryAfter: header.Get("Retry-After"),
		RequestID:  header.Get("X-GitHub-Request-Id"),
	}
}

func formatGitHubRateReset(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return value
	}
	return fmt.Sprintf("%s (%s)", value, time.Unix(seconds, 0).UTC().Format(time.RFC3339))
}

func singleLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}

func repoSlug(url string) string {
	slug := strings.TrimPrefix(url, "https://github.com/")
	slug = strings.TrimPrefix(slug, "git@github.com:")
	return strings.TrimSuffix(slug, ".git")
}

func missingTool(tools []string) string {
	for _, tool := range tools {
		tool = strings.TrimSpace(tool)
		if tool == "" {
			continue
		}
		if _, err := exec.LookPath(tool); err != nil {
			if runtime.GOOS == "windows" {
				if _, winErr := exec.LookPath(tool + ".exe"); winErr == nil {
					continue
				}
			}
			return tool
		}
	}
	return ""
}
