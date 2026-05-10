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
	ManifestPath  string
	RunDir        string
	BomlyPath     string
	SelectedCases []string
}

// Run executes the Dependency Graph QA harness.
func Run(ctx context.Context, opts RunOptions) error {
	return run(ctx, opts.ManifestPath, opts.RunDir, opts.BomlyPath, opts.SelectedCases)
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func run(ctx context.Context, manifest, runDir, bomlyPath string, selectedCases []string) error {
	targets, err := LoadScanTargets(manifest)
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
		if err := runCase(ctx, bomlyPath, caseDir, target); err != nil {
			failures++
			if writeErr := WriteStatusSummary(filepath.Join(caseDir, "qa-summary.json"), target.Name, "failed", err.Error()); writeErr != nil {
				return writeErr
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

func runCase(ctx context.Context, bomlyPath, caseDir string, target ScanTarget) error {
	bomlySBOM := filepath.Join(caseDir, "bomly.sbom.json")
	githubResponse := filepath.Join(caseDir, "github.response.json")
	githubSBOM := filepath.Join(caseDir, "github.sbom.json")
	diffJSON := filepath.Join(caseDir, "diff.json")

	scanArgs := []string{"scan", "--url", target.URL}
	scanArgs = append(scanArgs, target.QAArgs()...)
	scanArgs = append(scanArgs, "--sbom-output", "spdx-json="+bomlySBOM)
	if err := runLoggedCommand(ctx, filepath.Join(caseDir, "bomly.scan.log"), bomlyPath, scanArgs...); err != nil {
		return fmt.Errorf("bomly scan failed: %w", err)
	}
	if err := fetchGitHubSBOM(ctx, repoSlug(target.URL), githubResponse); err != nil {
		return fmt.Errorf("github sbom fetch failed: %w", err)
	}
	if err := UnwrapGitHubSBOM(githubResponse, githubSBOM); err != nil {
		return fmt.Errorf("github sbom unwrap failed: %w", err)
	}
	diffLog := filepath.Join(caseDir, "bomly.diff.log")
	if err := runOutputCommand(ctx, diffJSON, diffLog, bomlyPath, "diff", "--sbom", "--base", githubSBOM, "--head", bomlySBOM, "--format", "json"); err != nil {
		return fmt.Errorf("bomly diff failed: %w", err)
	}
	summary, err := BuildQASummary(target.Name, bomlySBOM, githubSBOM, diffJSON)
	if err != nil {
		return fmt.Errorf("qa summary failed: %w", err)
	}
	if err := WriteQASummary(filepath.Join(caseDir, "qa-summary.json"), summary); err != nil {
		return err
	}
	fmt.Printf("%s: completed packages(+%d ~%d -%d) relationships(bomly=%d github=%d matched=%d)\n",
		summary.Case,
		summary.PackageDiff.AddedPackageCount,
		summary.PackageDiff.ChangedPackageCount,
		summary.PackageDiff.RemovedPackageCount,
		summary.Relationships.BomlyRelationshipCount,
		summary.Relationships.GitHubRelationshipCount,
		summary.Relationships.MatchedCount,
	)
	return nil
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
	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer func() { _ = outFile.Close() }()
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
