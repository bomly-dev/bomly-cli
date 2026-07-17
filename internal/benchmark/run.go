package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/sbom"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

var githubAPIBaseURL = "https://api.github.com"

var githubTokenEnvNames = []string{"BOMLY_BENCHMARK_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"}

// RunOptions configures one hidden benchmark invocation.
type RunOptions struct {
	ManifestPath       string
	RunDir             string
	SelectedCases      []string
	SelectedSources    []string
	SelectedEcosystems []string
	CustomRepository   string
	InstallFirst       bool
	Notifications      io.Writer
	HTTPClient         *http.Client
	Logger             *zap.Logger
	NativeScan         NativeScanFunc
}

// NativeScanRequest describes one in-process Bomly native-detector scan.
type NativeScanRequest struct {
	CheckoutDir  string
	Repository   string
	Revision     string
	Ecosystem    sdk.Ecosystem
	InstallFirst bool
}

// NativeScanResult contains the graph and detector provenance from one native scan.
type NativeScanResult struct {
	Graph     *sdk.Graph
	Detectors []string
}

// NativeScanFunc executes Bomly's native detectors without managed plugins or configuration files.
type NativeScanFunc func(context.Context, NativeScanRequest) (NativeScanResult, error)

// Run executes the hidden local benchmark and writes deterministic artifacts.
func Run(ctx context.Context, opts RunOptions) (RunSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(opts.RunDir) == "" {
		opts.RunDir = filepath.Join(".benchmark-runs", "latest")
	}
	if opts.NativeScan == nil {
		return RunSummary{}, fmt.Errorf("benchmark native scanner is required")
	}
	if opts.Notifications == nil {
		opts.Notifications = io.Discard
	}
	opts.Logger = loggerOrNop(opts.Logger)
	if opts.HTTPClient == nil {
		provider, err := sdk.NewHTTPClientProviderFromEnv()
		if err != nil {
			return RunSummary{}, fmt.Errorf("configure benchmark HTTP client: %w", err)
		}
		opts.HTTPClient = provider.Client(30 * time.Second)
	}

	sources, err := filterBaselineSources(defaultBaselineSources(), opts.SelectedSources)
	if err != nil {
		return RunSummary{}, err
	}
	ecosystems, err := parseEcosystems(opts.SelectedEcosystems)
	if err != nil {
		return RunSummary{}, err
	}
	targets, selectedRun, err := resolveTargets(ctx, opts, ecosystems)
	if err != nil {
		return RunSummary{}, err
	}

	casesDir, err := benchmarkCasesDir(opts.RunDir)
	if err != nil {
		return RunSummary{}, err
	}
	if err := prepareCasesDir(casesDir, targets, selectedRun); err != nil {
		return RunSummary{}, err
	}
	opts.Logger.Info("benchmark: starting run", zap.Int("cases", len(targets)), zap.Int("sources", len(sources)), zap.String("run_dir", opts.RunDir))

	summary := RunSummary{SchemaVersion: summarySchemaVersion, Status: "completed", RunDir: opts.RunDir}
	completedComparisons := 0
	failures := make([]string, 0)
	caseScores := make([]*ScoreSummary, 0, len(targets))
	caseAgreements := make([]*ScoreSummary, 0, len(targets))
	for _, target := range targets {
		caseDir := filepath.Join(casesDir, target.Name)
		if err := os.MkdirAll(caseDir, 0o755); err != nil {
			return summary, fmt.Errorf("create benchmark case dir: %w", err)
		}
		_, _ = fmt.Fprintf(opts.Notifications, "benchmark: running %s (%s)\n", target.Name, repoSlug(target.URL))
		opts.Logger.Info("benchmark: case starting", zap.String("case", target.Name), zap.String("repository", target.URL), zap.String("ecosystem", string(target.Ecosystem)))
		caseSummary, caseCompleted, caseErr := runCase(ctx, opts, caseDir, target, sources)
		completedComparisons += caseCompleted
		if caseSummary.Scores != nil {
			caseScores = append(caseScores, caseSummary.Scores)
		}
		if caseSummary.Agreement != nil {
			caseAgreements = append(caseAgreements, caseSummary.Agreement)
		}
		if caseErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", target.Name, caseErr))
		}
		summary.Cases = append(summary.Cases, caseSummary)
		if err := writeJSON(filepath.Join(caseDir, "benchmark-summary.json"), caseSummary); err != nil {
			return summary, err
		}
		opts.Logger.Info("benchmark: case completed", zap.String("case", target.Name), zap.String("status", caseSummary.Status), zap.Int("completed_comparisons", caseCompleted))
	}
	summary.Scores = averageScores(caseScores)
	summary.Agreement = averageScores(caseAgreements)
	switch {
	case len(failures) > 0:
		summary.Status = "failed"
		summary.Reason = strings.Join(failures, "; ")
	case completedComparisons == 0:
		summary.Status = "failed"
		summary.Reason = "no benchmark comparisons completed"
	}
	if err := writeJSON(filepath.Join(opts.RunDir, "benchmark-summary.json"), summary); err != nil {
		return summary, err
	}
	_, _ = fmt.Fprintf(opts.Notifications, "benchmark: wrote artifacts to %s\n", opts.RunDir)
	opts.Logger.Info("benchmark: run completed", zap.String("status", summary.Status), zap.Int("completed_comparisons", completedComparisons), zap.String("run_dir", opts.RunDir))
	if summary.Status == "failed" {
		return summary, errors.New(summary.Reason)
	}
	return summary, nil
}

func resolveTargets(ctx context.Context, opts RunOptions, ecosystems []sdk.Ecosystem) ([]Target, bool, error) {
	if strings.TrimSpace(opts.CustomRepository) != "" {
		if len(opts.SelectedCases) > 0 {
			return nil, false, fmt.Errorf("--repo cannot be combined with --case")
		}
		if len(ecosystems) != 1 {
			return nil, false, fmt.Errorf("--repo requires exactly one --ecosystem")
		}
		repo, err := ParsePublicGitHubRepository(opts.CustomRepository)
		if err != nil {
			return nil, false, err
		}
		if err := verifyPublicGitHubRepository(ctx, opts.HTTPClient, repo); err != nil {
			return nil, false, err
		}
		args := []string(nil)
		if opts.InstallFirst {
			args = append(args, "--install-first")
		}
		return []Target{{
			Name:             "custom-" + strings.ReplaceAll(repo.Slug, "/", "-"),
			URL:              repo.URL,
			Ecosystem:        ecosystems[0],
			Args:             args,
			BenchmarkEnabled: true,
		}}, true, nil
	}
	if opts.InstallFirst {
		return nil, false, fmt.Errorf("--install-first requires --repo")
	}
	targets, err := LoadTargets(opts.ManifestPath)
	if err != nil {
		return nil, false, err
	}
	targets = Targets(targets)
	targets, err = filterTargetsByCase(targets, opts.SelectedCases)
	if err != nil {
		return nil, false, err
	}
	targets = filterTargetsByEcosystem(targets, ecosystems)
	if len(targets) == 0 {
		return nil, false, fmt.Errorf("no benchmark targets matched the selected filters")
	}
	return targets, len(opts.SelectedCases) > 0 || len(ecosystems) > 0, nil
}

func runCase(ctx context.Context, opts RunOptions, caseDir string, target Target, sources []baselineSource) (CaseSummary, int, error) {
	summary := CaseSummary{
		SchemaVersion: summarySchemaVersion,
		Case:          target.Name,
		Repository:    target.URL,
		Ecosystem:     target.Ecosystem,
		Status:        "completed",
	}
	if missing := missingTool(target.Tools); missing != "" {
		summary.Status = "unavailable"
		summary.Reason = "missing required tool: " + missing
		return summary, 0, nil
	}

	checkoutDir := filepath.Join(caseDir, "checkout")
	if err := checkoutTarget(ctx, opts.Logger, filepath.Join(caseDir, "logs", "checkout.log"), target.URL, checkoutDir); err != nil {
		summary.Status = "failed"
		summary.Reason = err.Error()
		return summary, 0, err
	}
	revision, err := resolveCheckoutHEAD(ctx, opts.Logger, filepath.Join(caseDir, "logs", "revision.log"), checkoutDir)
	if err != nil {
		summary.Status = "failed"
		summary.Reason = err.Error()
		return summary, 0, err
	}
	summary.HeadSHA = revision
	installFirst, err := benchmarkInstallFirst(target, opts.InstallFirst)
	if err != nil {
		summary.Status = "failed"
		summary.Reason = err.Error()
		return summary, 0, err
	}

	bomlyArtifacts := requiredBomlySBOMs(sources)
	scanResult, err := opts.NativeScan(ctx, NativeScanRequest{
		CheckoutDir: checkoutDir, Repository: target.URL, Revision: revision, Ecosystem: target.Ecosystem, InstallFirst: installFirst,
	})
	if err != nil {
		summary.Status = "failed"
		summary.Reason = "Bomly scan failed: " + err.Error()
		return summary, 0, errors.New(summary.Reason)
	}
	if scanResult.Graph == nil {
		summary.Status = "failed"
		summary.Reason = "Bomly scan failed: native scanner returned no graph"
		return summary, 0, errors.New(summary.Reason)
	}
	if err := writeBomlySBOMs(caseDir, scanResult, bomlyArtifacts); err != nil {
		return summary, 0, err
	}
	for format, artifact := range bomlyArtifacts {
		if err := filterSBOMFile(filepath.Join(caseDir, artifact.RawSBOM), filepath.Join(caseDir, artifact.SBOM), target.Ecosystem); err != nil {
			return summary, 0, fmt.Errorf("filter Bomly %s SBOM: %w", format, err)
		}
	}
	summary.Detectors = append([]string(nil), scanResult.Detectors...)

	completed := 0
	failures := make([]string, 0)
	sourceScores := make([]*ScoreSummary, 0, len(sources))
	sourceAgreements := make(map[string][]*ScoreSummary)
	policy := comparisonPolicy(scanResult.Graph, target)
	for _, source := range sources {
		artifacts := sourceArtifacts(source.Name())
		sourceSummary := SourceSummary{Source: source.Name(), Role: source.Role(), Status: "completed", Artifacts: artifacts, Detectors: summary.Detectors}
		if missing := missingTool(source.Tools()); missing != "" {
			sourceSummary.Status = "unavailable"
			sourceSummary.Reason = "missing required tool: " + missing
			summary.Sources = append(summary.Sources, sourceSummary)
			opts.Logger.Warn("benchmark: source unavailable", zap.String("case", target.Name), zap.String("source", source.Name()), zap.String("reason", sourceSummary.Reason))
			if err := writeJSON(filepath.Join(caseDir, artifacts.Summary), sourceSummary); err != nil {
				return summary, completed, err
			}
			continue
		}
		rawSourcePath := filepath.Join(caseDir, artifacts.RawSBOM)
		opts.Logger.Info("benchmark: source starting", zap.String("case", target.Name), zap.String("source", source.Name()))
		if err := source.ProduceSBOM(ctx, opts.Logger, opts.HTTPClient, caseDir, checkoutDir, target, rawSourcePath); err != nil {
			sourceSummary.Reason = err.Error()
			if isUnavailable(err) {
				sourceSummary.Status = "unavailable"
			} else {
				sourceSummary.Status = "failed"
				failures = append(failures, source.Name()+": "+err.Error())
			}
			summary.Sources = append(summary.Sources, sourceSummary)
			opts.Logger.Warn("benchmark: source did not complete", zap.String("case", target.Name), zap.String("source", source.Name()), zap.String("status", sourceSummary.Status), zap.Error(err))
			if err := writeJSON(filepath.Join(caseDir, artifacts.Summary), sourceSummary); err != nil {
				return summary, completed, err
			}
			continue
		}
		sourcePath := filepath.Join(caseDir, artifacts.SBOM)
		if err := filterSBOMFile(rawSourcePath, sourcePath, target.Ecosystem); err != nil {
			return summary, completed, fmt.Errorf("filter %s SBOM: %w", source.Name(), err)
		}
		bomlyArtifact := bomlyArtifacts[source.BomlyFormat()]
		diffPath := filepath.Join(caseDir, artifacts.Diff)
		if err := writeSBOMDiffArtifact(sourcePath, filepath.Join(caseDir, bomlyArtifact.SBOM), diffPath); err != nil {
			sourceSummary.Status = "failed"
			sourceSummary.Reason = "Bomly diff failed: " + err.Error()
			failures = append(failures, source.Name()+": "+sourceSummary.Reason)
			summary.Sources = append(summary.Sources, sourceSummary)
			if err := writeJSON(filepath.Join(caseDir, artifacts.Summary), sourceSummary); err != nil {
				return summary, completed, err
			}
			continue
		}
		filteredBomlyDoc, _, err := loadSBOMDocument(filepath.Join(caseDir, bomlyArtifact.SBOM))
		if err != nil {
			return summary, completed, err
		}
		filteredSourceDoc, _, err := loadSBOMDocument(sourcePath)
		if err != nil {
			return summary, completed, err
		}
		var report ComparisonReport
		sourceSummary, report = BuildSourceSummaryWithPolicy(source.Name(), filteredBomlyDoc, filteredSourceDoc, artifacts, policy)
		sourceSummary.Role = source.Role()
		if source.Role() != "evidence" {
			sourceSummary.Scores = nil
		}
		if err := writeJSON(filepath.Join(caseDir, artifacts.Mismatches), report); err != nil {
			return summary, completed, fmt.Errorf("write %s mismatch report: %w", source.Name(), err)
		}
		summary.Sources = append(summary.Sources, sourceSummary)
		if sourceSummary.Scores != nil {
			sourceScores = append(sourceScores, sourceSummary.Scores)
		}
		sourceAgreements[source.AgreementGroup()] = append(sourceAgreements[source.AgreementGroup()], sourceSummary.Agreement)
		completed++
		overallAgreement := 0.0
		if sourceSummary.Agreement != nil {
			overallAgreement = sourceSummary.Agreement.Overall
		}
		opts.Logger.Info("benchmark: source completed", zap.String("case", target.Name), zap.String("source", source.Name()), zap.Float64("agreement_score", overallAgreement))
		if err := writeJSON(filepath.Join(caseDir, artifacts.Summary), sourceSummary); err != nil {
			return summary, completed, err
		}
	}
	summary.Scores = averageScores(sourceScores)
	agreementGroups := make([]*ScoreSummary, 0, len(sourceAgreements))
	for _, group := range sourceAgreements {
		agreementGroups = append(agreementGroups, averageScores(group))
	}
	summary.Agreement = averageScores(agreementGroups)
	switch {
	case len(failures) > 0:
		summary.Status = "failed"
		summary.Reason = strings.Join(failures, "; ")
		return summary, completed, errors.New(summary.Reason)
	case completed == 0:
		summary.Status = "unavailable"
		summary.Reason = "no benchmark sources completed"
	}
	return summary, completed, nil
}

type baselineSource interface {
	Name() string
	Role() string
	AgreementGroup() string
	Tools() []string
	BomlyFormat() string
	ProduceSBOM(context.Context, *zap.Logger, *http.Client, string, string, Target, string) error
}

type githubBaselineSource struct{}

func (githubBaselineSource) Name() string           { return "github" }
func (githubBaselineSource) Role() string           { return "evidence" }
func (githubBaselineSource) AgreementGroup() string { return "github" }
func (githubBaselineSource) Tools() []string        { return nil }
func (githubBaselineSource) BomlyFormat() string    { return "spdx" }
func (githubBaselineSource) ProduceSBOM(ctx context.Context, _ *zap.Logger, client *http.Client, caseDir, _ string, target Target, outputPath string) error {
	responsePath := filepath.Join(caseDir, "sources", "github", "response.json")
	if err := fetchGitHubSBOM(ctx, client, repoSlug(target.URL), responsePath); err != nil {
		return fmt.Errorf("GitHub SBOM fetch failed: %w", err)
	}
	return unwrapGitHubSBOM(responsePath, outputPath)
}

type syftBaselineSource struct {
	name        string
	bomlyFormat string
	syftFormat  string
}

func (s syftBaselineSource) Name() string         { return s.name }
func (syftBaselineSource) Role() string           { return "observation" }
func (syftBaselineSource) AgreementGroup() string { return "syft" }
func (syftBaselineSource) Tools() []string        { return []string{"syft"} }
func (s syftBaselineSource) BomlyFormat() string  { return s.bomlyFormat }
func (s syftBaselineSource) ProduceSBOM(ctx context.Context, logger *zap.Logger, _ *http.Client, caseDir, checkoutDir string, _ Target, outputPath string) error {
	return runLoggedCommandWithLogger(ctx, logger, nil, filepath.Join(caseDir, "sources", s.name, "source.log"), "syft", checkoutDir, "-o", s.syftFormat+"="+outputPath)
}

func defaultBaselineSources() []baselineSource {
	return []baselineSource{
		githubBaselineSource{},
		syftBaselineSource{name: "syft", bomlyFormat: "spdx", syftFormat: "spdx-json"},
		syftBaselineSource{name: "syft-cyclonedx", bomlyFormat: "cyclonedx", syftFormat: "cyclonedx-json"},
	}
}

type bomlySBOMArtifact struct {
	Format  string
	SBOM    string
	RawSBOM string
}

func requiredBomlySBOMs(sources []baselineSource) map[string]bomlySBOMArtifact {
	out := make(map[string]bomlySBOMArtifact)
	for _, source := range sources {
		format := source.BomlyFormat()
		if _, ok := out[format]; ok {
			continue
		}
		filename := format + ".sbom.json"
		out[format] = bomlySBOMArtifact{
			Format:  format,
			SBOM:    filepath.ToSlash(filepath.Join("sources", "bomly", filename)),
			RawSBOM: filepath.ToSlash(filepath.Join("sources", "bomly", format+".raw.sbom.json")),
		}
	}
	return out
}

func sortedBomlyArtifacts(values map[string]bomlySBOMArtifact) []bomlySBOMArtifact {
	out := make([]bomlySBOMArtifact, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Format < out[j].Format })
	return out
}

func writeBomlySBOMs(caseDir string, result NativeScanResult, artifacts map[string]bomlySBOMArtifact) error {
	toolNames := make([]string, 0, len(result.Detectors))
	for _, detector := range result.Detectors {
		if name := strings.TrimSpace(detector); name != "" {
			toolNames = append(toolNames, "bomly-detector:"+name)
		}
	}
	for _, artifact := range sortedBomlyArtifacts(artifacts) {
		target, err := bomlySBOMTarget(artifact.Format)
		if err != nil {
			return err
		}
		raw, err := sbom.MarshalDepGraphJSON(result.Graph, target, sbom.BuildOptions{ToolNames: toolNames}, sbom.EncodeOptions{Pretty: true})
		if err != nil {
			return fmt.Errorf("marshal Bomly %s SBOM: %w", artifact.Format, err)
		}
		path := filepath.Join(caseDir, artifact.RawSBOM)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("create Bomly artifact dir: %w", err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			return fmt.Errorf("write Bomly %s SBOM: %w", artifact.Format, err)
		}
	}
	return nil
}

func bomlySBOMTarget(format string) (sbom.Target, error) {
	switch format {
	case "spdx":
		return sbom.TargetSPDX23JSON, nil
	case "cyclonedx":
		return sbom.TargetCycloneDX16JSON, nil
	default:
		return "", fmt.Errorf("unsupported Bomly benchmark SBOM format %q", format)
	}
}

func writeSBOMDiffArtifact(basePath, headPath, outputPath string) error {
	baseDoc, _, err := loadSBOMDocument(basePath)
	if err != nil {
		return fmt.Errorf("read diff base SBOM: %w", err)
	}
	headDoc, _, err := loadSBOMDocument(headPath)
	if err != nil {
		return fmt.Errorf("read diff head SBOM: %w", err)
	}
	baseGraph, err := sbom.ToGraph(baseDoc)
	if err != nil {
		return fmt.Errorf("convert diff base SBOM to graph: %w", err)
	}
	headGraph, err := sbom.ToGraph(headDoc)
	if err != nil {
		return fmt.Errorf("convert diff head SBOM to graph: %w", err)
	}
	payload := output.BuildDiffResponse(
		"benchmark",
		basePath,
		headPath,
		benchmarkSBOMConsolidatedGraph(basePath, baseGraph),
		benchmarkSBOMConsolidatedGraph(headPath, headGraph),
		nil,
		time.Now(),
	)
	return writeJSON(outputPath, payload)
}

func benchmarkSBOMConsolidatedGraph(path string, graph *sdk.Graph) sdk.ConsolidatedGraph {
	target := sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: path}
	subproject := sdk.Subproject{
		ExecutionTarget:         target,
		RelativePath:            filepath.Base(path),
		PrimaryDetector:         "sbom-detector",
		DetectedPackageManagers: []sdk.PackageManager{sdk.PackageManagerSBOM},
		Ecosystem:               sdk.EcosystemSBOM,
	}
	entry := sdk.GraphEntry{Graph: graph, Manifest: sdk.ManifestMetadata{Path: path, Kind: "sbom"}}
	return sdk.ConsolidatedGraph{
		ExecutionTarget: target,
		Graphs:          sdk.SingleGraphContainer(graph, entry.Manifest),
		Manifests: []sdk.ConsolidatedManifest{{
			Entry: entry, Subproject: subproject, DetectorName: "sbom-detector", Origin: sdk.CoreOrigin, Technique: sdk.SBOMTechnique,
		}},
		Subprojects: []sdk.ConsolidatedSubproject{{Subproject: subproject, DetectorName: "sbom-detector"}},
	}
}

func benchmarkInstallFirst(target Target, requested bool) (bool, error) {
	installFirst := requested
	for _, arg := range target.Args {
		switch strings.TrimSpace(arg) {
		case "":
		case "--install-first":
			installFirst = true
		default:
			return false, fmt.Errorf("benchmark target %q has unsupported scan argument %q", target.Name, arg)
		}
	}
	return installFirst, nil
}

func sourceArtifacts(source string) SourceArtifacts {
	prefix := filepath.ToSlash(filepath.Join("sources", source))
	artifacts := SourceArtifacts{
		SBOM:       filepath.ToSlash(filepath.Join(prefix, "source.sbom.json")),
		RawSBOM:    filepath.ToSlash(filepath.Join(prefix, "source.raw.sbom.json")),
		Diff:       filepath.ToSlash(filepath.Join(prefix, "diff.json")),
		Log:        filepath.ToSlash(filepath.Join(prefix, "source.log")),
		Summary:    filepath.ToSlash(filepath.Join(prefix, "benchmark-summary.json")),
		Mismatches: filepath.ToSlash(filepath.Join(prefix, "mismatches.json")),
	}
	if source == "github" {
		artifacts.Log = ""
		artifacts.Response = filepath.ToSlash(filepath.Join(prefix, "response.json"))
	}
	return artifacts
}

func comparisonPolicy(graph *sdk.Graph, target Target) ComparisonPolicy {
	policy := ComparisonPolicy{PackageExtensions: make(map[string]string), RelationshipExtensions: make(map[string]string)}
	if graph == nil {
		return policy
	}
	extensionIDs := make(map[string]string)
	graph.WalkNodes(func(dependency *sdk.Dependency) bool {
		if dependency == nil || dependency.RegistryMatchEligible() {
			return true
		}
		purl := sdk.CanonicalizePackageURL(dependency.PURL)
		if purl == "" {
			return true
		}
		reason := "non-registry graph occurrence: " + string(dependency.Source)
		if dependency.Type == sdk.PackageTypeApplication || dependency.Type == sdk.PackageTypeManifest {
			reason = "project graph identity"
		}
		policy.PackageExtensions[purl] = reason
		extensionIDs[dependency.ID] = reason
		return true
	})
	graph.WalkEdges(func(from, to *sdk.Dependency) bool {
		if from == nil || to == nil {
			return true
		}
		reason := extensionIDs[from.ID]
		if reason == "" {
			reason = extensionIDs[to.ID]
		}
		if reason == "" {
			return true
		}
		fromPURL := sdk.CanonicalizePackageURL(from.PURL)
		toPURL := sdk.CanonicalizePackageURL(to.PURL)
		if fromPURL != "" && toPURL != "" {
			policy.RelationshipExtensions[relationshipKey(fromPURL, toPURL)] = reason
		}
		return true
	})
	for _, relationship := range target.AdjudicatedRelationships {
		from := sdk.CanonicalizePackageURL(relationship.From)
		to := sdk.CanonicalizePackageURL(relationship.To)
		policy.RelationshipExtensions[relationshipKey(from, to)] = strings.TrimSpace(relationship.Reason)
	}
	return policy
}

func loggerOrNop(logger *zap.Logger) *zap.Logger {
	if logger == nil {
		return zap.NewNop()
	}
	return logger
}

// ParseNames parses a comma-separated selector list.
func ParseNames(values ...string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
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
	}
	return out
}

func filterBaselineSources(sources []baselineSource, selected []string) ([]baselineSource, error) {
	if len(selected) == 0 {
		return sources, nil
	}
	byName := make(map[string]baselineSource, len(sources))
	for _, source := range sources {
		byName[source.Name()] = source
	}
	out := make([]baselineSource, 0, len(selected))
	for _, name := range selected {
		source, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown benchmark source %q; available sources: github, syft, syft-cyclonedx", name)
		}
		out = append(out, source)
	}
	return out, nil
}

func filterTargetsByCase(targets []Target, selected []string) ([]Target, error) {
	if len(selected) == 0 {
		return targets, nil
	}
	byName := make(map[string]Target, len(targets))
	for _, target := range targets {
		byName[target.Name] = target
	}
	out := make([]Target, 0, len(selected))
	for _, name := range selected {
		target, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("unknown or disabled benchmark case %q", name)
		}
		out = append(out, target)
	}
	return out, nil
}

func filterTargetsByEcosystem(targets []Target, ecosystems []sdk.Ecosystem) []Target {
	if len(ecosystems) == 0 {
		return targets
	}
	selected := make(map[sdk.Ecosystem]struct{}, len(ecosystems))
	for _, ecosystem := range ecosystems {
		selected[ecosystem] = struct{}{}
	}
	out := make([]Target, 0, len(targets))
	for _, target := range targets {
		if _, ok := selected[target.Ecosystem]; ok {
			out = append(out, target)
		}
	}
	return out
}

func parseEcosystems(values []string) ([]sdk.Ecosystem, error) {
	names := ParseNames(values...)
	out := make([]sdk.Ecosystem, 0, len(names))
	for _, name := range names {
		ecosystem, err := sdk.ParseEcosystem(name)
		if err != nil {
			return nil, err
		}
		out = append(out, ecosystem)
	}
	return out, nil
}

func prepareCasesDir(casesDir string, targets []Target, selectedRun bool) error {
	if !selectedRun {
		if err := os.RemoveAll(casesDir); err != nil {
			return fmt.Errorf("clean benchmark cases dir: %w", err)
		}
	}
	if err := os.MkdirAll(casesDir, 0o755); err != nil {
		return fmt.Errorf("create benchmark cases dir: %w", err)
	}
	if selectedRun {
		for _, target := range targets {
			if err := os.RemoveAll(filepath.Join(casesDir, target.Name)); err != nil {
				return fmt.Errorf("clean benchmark case %s: %w", target.Name, err)
			}
		}
	}
	return nil
}

func benchmarkCasesDir(runDir string) (string, error) {
	casesDir, err := filepath.Abs(filepath.Join(runDir, "cases"))
	if err != nil {
		return "", fmt.Errorf("resolve benchmark cases dir: %w", err)
	}
	return casesDir, nil
}

func filterSBOMFile(inputPath, outputPath string, ecosystem sdk.Ecosystem) error {
	doc, target, err := loadSBOMDocument(inputPath)
	if err != nil {
		return err
	}
	raw, err := sbom.MarshalJSON(FilterDocument(doc, ecosystem), target, sbom.EncodeOptions{Pretty: true})
	if err != nil {
		return fmt.Errorf("marshal filtered SBOM: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create filtered SBOM parent dir: %w", err)
	}
	if err := os.WriteFile(outputPath, raw, 0o644); err != nil {
		return fmt.Errorf("write filtered SBOM: %w", err)
	}
	return nil
}

func loadSBOMDocument(path string) (*sbom.Document, sbom.Target, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read SBOM: %w", err)
	}
	doc, target, err := sbom.UnmarshalAutoJSON(raw)
	if err != nil {
		return nil, "", fmt.Errorf("parse SBOM: %w", err)
	}
	if doc == nil {
		return nil, "", fmt.Errorf("unsupported SBOM target %s", target)
	}
	return doc, target, nil
}

func checkoutTarget(ctx context.Context, logger *zap.Logger, logPath, repository, checkoutDir string) error {
	if err := runLoggedCommandWithLogger(ctx, logger, nil, logPath, "git", "clone", "--depth", "1", repository, checkoutDir); err != nil {
		return fmt.Errorf("checkout repository: %w", err)
	}
	return nil
}

func resolveCheckoutHEAD(ctx context.Context, logger *zap.Logger, logPath, checkoutDir string) (string, error) {
	outputPath := logPath + ".stdout"
	if err := runOutputCommand(ctx, logger, nil, outputPath, logPath, "git", "-C", checkoutDir, "rev-parse", "HEAD"); err != nil {
		return "", fmt.Errorf("resolve checkout HEAD: %w", err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		return "", fmt.Errorf("read checkout HEAD: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func runLoggedCommandWithLogger(ctx context.Context, logger *zap.Logger, env []string, logPath, name string, args ...string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("create log parent dir: %w", err)
	}
	logFile, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("create log: %w", err)
	}
	defer func() { _ = logFile.Close() }()
	_, _ = fmt.Fprintf(logFile, "$ %s %s\n", name, strings.Join(args, " "))
	loggerOrNop(logger).Debug("benchmark: running command", zap.String("binary", name), zap.Strings("args", args), zap.String("working_dir", inheritedWorkingDir()))
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s: %w (see %s)", name, err, logPath)
	}
	return nil
}

func runOutputCommand(ctx context.Context, logger *zap.Logger, env []string, outputPath, logPath, name string, args ...string) error {
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
	_, _ = fmt.Fprintf(logFile, "$ %s %s\n", name, strings.Join(args, " "))
	loggerOrNop(logger).Debug("benchmark: running command", zap.String("binary", name), zap.Strings("args", args), zap.String("working_dir", inheritedWorkingDir()))
	cmd := exec.CommandContext(ctx, name, args...)
	if env != nil {
		cmd.Env = env
	}
	cmd.Stdout = outFile
	cmd.Stderr = logFile
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s: %w (see %s)", name, err, logPath)
	}
	return nil
}

func inheritedWorkingDir() string {
	cwd, _ := os.Getwd()
	return cwd
}

func unwrapGitHubSBOM(inputPath, outputPath string) error {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read GitHub SBOM response: %w", err)
	}
	var payload struct {
		SBOM json.RawMessage `json:"sbom"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("parse GitHub SBOM response: %w", err)
	}
	if len(payload.SBOM) == 0 {
		return fmt.Errorf("GitHub SBOM response is missing sbom")
	}
	var normalized any
	if err := json.Unmarshal(payload.SBOM, &normalized); err != nil {
		return fmt.Errorf("parse GitHub SBOM document: %w", err)
	}
	return writeJSON(outputPath, normalized)
}

type unavailableError struct{ err error }

func (e *unavailableError) Error() string { return e.err.Error() }
func (e *unavailableError) Unwrap() error { return e.err }

func isUnavailable(err error) bool {
	var unavailable *unavailableError
	return errors.As(err, &unavailable)
}

type githubHTTPError struct {
	StatusCode int
	Status     string
	URL        string
	Body       string
	OutputPath string
	AuthSource string
	Rate       githubRateInfo
}

func (e *githubHTTPError) Error() string {
	message := fmt.Sprintf("GET %s returned %s", e.URL, e.Status)
	if e.AuthSource != "" {
		message += "; authenticated with " + e.AuthSource
	} else {
		message += "; unauthenticated request (set BOMLY_BENCHMARK_GITHUB_TOKEN, GITHUB_TOKEN, or GH_TOKEN)"
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
	Limit, Remaining, Used, Reset, Resource, RetryAfter, RequestID string
}

func (r githubRateInfo) String() string {
	values := []struct{ name, value string }{
		{"limit", r.Limit}, {"remaining", r.Remaining}, {"used", r.Used}, {"reset", r.Reset},
		{"resource", r.Resource}, {"retry-after", r.RetryAfter}, {"request-id", r.RequestID},
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if value.value != "" {
			parts = append(parts, value.name+"="+value.value)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "GitHub rate limit: " + strings.Join(parts, " ")
}

func fetchGitHubSBOM(ctx context.Context, client *http.Client, slug, outputPath string) error {
	apiURL := githubAPIBaseURL + "/repos/" + slug + "/dependency-graph/sbom"
	body, response, authSource, err := fetchGitHub(ctx, client, apiURL, true)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create GitHub response parent dir: %w", err)
	}
	if err := os.WriteFile(outputPath, body, 0o644); err != nil {
		return fmt.Errorf("write GitHub response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		httpErr := &githubHTTPError{StatusCode: response.StatusCode, Status: response.Status, URL: apiURL, Body: string(body), OutputPath: outputPath, AuthSource: authSource, Rate: githubRateInfoFromHeaders(response.Header)}
		if response.StatusCode == http.StatusNotFound {
			return &unavailableError{err: httpErr}
		}
		return httpErr
	}
	return nil
}

func fetchGitHub(ctx context.Context, client *http.Client, apiURL string, authenticate bool) ([]byte, *http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	authSource := ""
	if authenticate {
		if token, envName := githubTokenFromEnv(); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
			authSource = envName
		}
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, nil, authSource, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, response, authSource, fmt.Errorf("read GitHub response body: %w", err)
	}
	return body, response, authSource, nil
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
		Limit: header.Get("X-RateLimit-Limit"), Remaining: header.Get("X-RateLimit-Remaining"),
		Used: header.Get("X-RateLimit-Used"), Reset: formatGitHubRateReset(header.Get("X-RateLimit-Reset")),
		Resource: header.Get("X-RateLimit-Resource"), RetryAfter: header.Get("Retry-After"), RequestID: header.Get("X-GitHub-Request-Id"),
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

// PublicGitHubRepository is a validated public GitHub repository selector.
type PublicGitHubRepository struct {
	URL  string
	Slug string
}

// ParsePublicGitHubRepository validates a public-repository URL shape.
func ParsePublicGitHubRepository(value string) (PublicGitHubRepository, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return PublicGitHubRepository{}, fmt.Errorf("parse --repo: %w", err)
	}
	if parsed.Scheme != "https" || !strings.EqualFold(parsed.Host, "github.com") || parsed.User != nil {
		return PublicGitHubRepository{}, fmt.Errorf("--repo must be an HTTPS github.com repository URL without credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return PublicGitHubRepository{}, fmt.Errorf("--repo must not include a query string or fragment")
	}
	parts := strings.Split(strings.Trim(strings.TrimSuffix(parsed.Path, ".git"), "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return PublicGitHubRepository{}, fmt.Errorf("--repo must have the form https://github.com/<owner>/<repo>")
	}
	slug := parts[0] + "/" + parts[1]
	return PublicGitHubRepository{URL: "https://github.com/" + slug, Slug: slug}, nil
}

func verifyPublicGitHubRepository(ctx context.Context, client *http.Client, repo PublicGitHubRepository) error {
	apiURL := githubAPIBaseURL + "/repos/" + repo.Slug
	body, response, authSource, err := fetchGitHub(ctx, client, apiURL, false)
	if err != nil {
		return fmt.Errorf("verify public GitHub repository: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("verify public GitHub repository: %w", &githubHTTPError{StatusCode: response.StatusCode, Status: response.Status, URL: apiURL, Body: string(body), AuthSource: authSource, Rate: githubRateInfoFromHeaders(response.Header)})
	}
	var payload struct {
		Private bool `json:"private"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("verify public GitHub repository response: %w", err)
	}
	if payload.Private {
		return fmt.Errorf("--repo must identify a public GitHub repository")
	}
	return nil
}

func repoSlug(value string) string {
	return strings.TrimSuffix(strings.TrimPrefix(value, "https://github.com/"), ".git")
}

func missingTool(tools []string) string {
	for _, tool := range tools {
		if strings.TrimSpace(tool) == "" {
			continue
		}
		if _, err := exec.LookPath(tool); err != nil {
			return tool
		}
	}
	return ""
}

func singleLine(value string) string { return strings.Join(strings.Fields(value), " ") }

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return value[:limit-3] + "..."
}
