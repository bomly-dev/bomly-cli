package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/registry"
	"github.com/bomly/bomly-cli/internal/viewmodel"

	"github.com/bomly/bomly-cli/internal/scan"
	"go.uber.org/zap"
)

// auditEnrichResult holds the outcome of running auditors against a dependency graph.
type auditEnrichResult struct {
	Findings []scan.Finding
}

type graphResolution struct {
	Results          []scan.ResolveGraphResult
	PartialFailure   error
	DetectorWarnings []scan.PipelineWarning
}

func enrichResolvedGraphs(
	ctx commandContext,
	logger *zap.Logger,
	results []scan.ResolveGraphResult,
	stderr io.Writer,
) []scan.ResolveGraphResult {
	if len(results) == 0 {
		return results
	}
	aggregateGraph, packageRefs, seed := aggregateResolvedGraphsForLicenseEnrichment(results)
	if aggregateGraph == nil || aggregateGraph.Size() == 0 {
		return results
	}

	engine := newScanEngine(ctx, logger)
	req := scan.MatchRequest{
		ProjectPath:     seed.ExecutionTarget.Location,
		ExecutionTarget: seed.ExecutionTarget,
		SubprojectInfo:  seed,
		Ecosystem:       seed.Ecosystem,
		PackageManager:  seed.PackageManager,
		Mode:            scan.TargetModeFullGraph,
		Graph:           aggregateGraph,
		MatcherFilter:   defaultMatcherFilter(ctx.config.Matchers),
		Stderr:          stderr,
	}
	result, err := engine.Match(context.Background(), req)
	if err != nil {
		logger.Warn("matchers: one or more matchers reported errors", zap.Error(err))
	}
	if len(result.MatcherRuns) == 0 {
		logger.Info("matcher enrichment completed with no matcher runs", zap.String("mode", string(req.Mode)))
	} else {
		logger.Info("matcher enrichment completed", zap.Int("runs", len(result.MatcherRuns)), zap.Strings("matchers", result.MatcherRuns), zap.String("mode", string(req.Mode)))
		if containsStringValue(result.MatcherRuns, eolCheckerName) {
			logger.Debug("eol matcher invoked for aggregate graph", zap.Int("packages", len(aggregateGraph.Packages())))
		} else {
			logger.Debug("eol matcher not invoked for aggregate graph", zap.Strings("matchers", result.MatcherRuns))
		}
	}
	if result.Graph != nil {
		syncEnrichmentBackToResolvedGraphs(packageRefs)
	}
	return results
}

func enrichGraph(
	ctx commandContext,
	logger *zap.Logger,
	g *model.Graph,
	subproject scan.Subproject,
	stderr io.Writer,
) *model.Graph {
	if g == nil {
		return nil
	}
	engine := newScanEngine(ctx, logger)
	req := scan.MatchRequest{
		ProjectPath:     subproject.ExecutionTarget.Location,
		ExecutionTarget: subproject.ExecutionTarget,
		SubprojectInfo:  subproject,
		Ecosystem:       subproject.Ecosystem,
		PackageManager:  subproject.PackageManager,
		Mode:            scan.TargetModeFullGraph,
		Graph:           g,
		MatcherFilter:   defaultMatcherFilter(ctx.config.Matchers),
		Stderr:          stderr,
	}
	result, err := engine.Match(context.Background(), req)
	if err != nil {
		logger.Warn("matchers: one or more matchers reported errors", zap.Error(err))
	}
	if len(result.MatcherRuns) == 0 {
		logger.Info("matcher enrichment completed with no matcher runs", zap.String("mode", string(req.Mode)))
	} else {
		logger.Info("matcher enrichment completed", zap.Int("runs", len(result.MatcherRuns)), zap.Strings("matchers", result.MatcherRuns), zap.String("mode", string(req.Mode)))
		if containsStringValue(result.MatcherRuns, eolCheckerName) {
			logger.Debug("eol matcher invoked for graph", zap.Int("packages", len(g.Packages())), zap.String("subproject", subproject.RelativePath))
		} else {
			logger.Debug("eol matcher not invoked for graph", zap.Strings("matchers", result.MatcherRuns), zap.String("subproject", subproject.RelativePath))
		}
	}
	if result.Graph != nil {
		return result.Graph
	}
	return g
}

// sourceRank returns a priority rank for auditor sources (lower = higher quality).
func sourceRank(source string) int {
	switch source {
	case "grype":
		return 0
	case "osv":
		return 1
	default:
		return 2
	}
}

// deduplicateFindings removes duplicate (package, vuln-ID) pairs, keeping the
// finding from the highest-ranking source (Grype > OSV > other).
// Findings with an empty ID or non-vulnerability kind are passed through as-is.
func deduplicateFindings(findings []scan.Finding) []scan.Finding {
	type key struct{ pkgID, vulnID string }
	type entry struct {
		idx  int
		rank int
	}
	best := make(map[key]entry, len(findings))
	out := make([]scan.Finding, 0, len(findings))

	for _, f := range findings {
		if f.ID == "" || f.Kind != scan.FindingKindVulnerability {
			out = append(out, f)
			continue
		}
		pkgID := ""
		if f.Package != nil {
			pkgID = f.Package.ID
		}
		k := key{pkgID: pkgID, vulnID: f.ID}
		rank := sourceRank(f.Source)
		if e, exists := best[k]; !exists {
			best[k] = entry{idx: len(out), rank: rank}
			out = append(out, f)
		} else if rank < e.rank {
			out[e.idx] = f
			best[k] = entry{idx: e.idx, rank: rank}
		}
	}
	return out
}

// auditGraph runs all registered auditors against g.
// Errors from auditors are logged as warnings — partial results are returned rather
// than aborting. This function is safe to call from scan, diff, and explain commands.
func auditGraph(
	ctx commandContext,
	logger *zap.Logger,
	g *model.Graph,
	filter scan.AuditorFilter,
	stderr io.Writer,
) auditEnrichResult {
	engine := newScanEngine(ctx, logger)
	req := scan.AuditRequest{
		Mode:          scan.TargetModeFullGraph,
		Graph:         g,
		AuditorFilter: defaultAuditorFilterFromFilter(filter),
		Stderr:        stderr,
	}

	result, err := engine.Audit(context.Background(), req)
	if err != nil {
		logger.Warn("audit: one or more auditors reported errors", zap.Error(err))
	}

	findings := deduplicateFindings(result.Findings)
	return auditEnrichResult{Findings: findings}
}

func auditComponent(
	ctx commandContext,
	logger *zap.Logger,
	g *model.Graph,
	target *model.Package,
	stderr io.Writer,
) auditEnrichResult {
	if g == nil || target == nil {
		return auditEnrichResult{}
	}
	engine := newScanEngine(ctx, logger)
	req := scan.AuditRequest{
		Mode:          scan.TargetModeComponent,
		Graph:         g,
		Target:        target,
		Ecosystem:     scan.Ecosystem(target.Ecosystem),
		AuditorFilter: defaultAuditorFilter(ctx.config.Auditors),
		Stderr:        stderr,
	}
	result, err := engine.Audit(context.Background(), req)
	if err != nil {
		logger.Warn("audit: one or more auditors reported errors", zap.Error(err))
	}
	return auditEnrichResult{Findings: deduplicateFindings(result.Findings)}
}

func diffAuditSummary(baseFindings, headFindings []scan.Finding) *viewmodel.DiffAudit {
	introduced, resolved, persisted := diffFindingSets(baseFindings, headFindings)
	combined := append(append([]scan.Finding{}, introduced...), persisted...)
	combined = append(combined, resolved...)
	return &viewmodel.DiffAudit{
		Introduced:   viewmodel.FindingsFromScan(introduced),
		Resolved:     viewmodel.FindingsFromScan(resolved),
		Persisted:    viewmodel.FindingsFromScan(persisted),
		AuditSummary: viewmodel.SummaryFromFindings(combined),
	}
}

func diffFindingSets(baseFindings, headFindings []scan.Finding) ([]scan.Finding, []scan.Finding, []scan.Finding) {
	baseByKey := make(map[string]scan.Finding, len(baseFindings))
	headByKey := make(map[string]scan.Finding, len(headFindings))
	for _, finding := range baseFindings {
		baseByKey[diffFindingKey(finding)] = finding
	}
	for _, finding := range headFindings {
		headByKey[diffFindingKey(finding)] = finding
	}
	introduced := make([]scan.Finding, 0)
	resolved := make([]scan.Finding, 0)
	persisted := make([]scan.Finding, 0)
	for key, finding := range headByKey {
		if _, ok := baseByKey[key]; ok {
			persisted = append(persisted, finding)
			continue
		}
		introduced = append(introduced, finding)
	}
	for key, finding := range baseByKey {
		if _, ok := headByKey[key]; ok {
			continue
		}
		resolved = append(resolved, finding)
	}
	return introduced, resolved, persisted
}

func diffFindingKey(finding scan.Finding) string {
	packageID := ""
	if finding.Package != nil {
		packageID = finding.Package.ID
	}
	return fmt.Sprintf("%s|%s|%s|%s", finding.ID, finding.Kind, finding.Source, packageID)
}

func aggregateResolvedGraphsForLicenseEnrichment(results []scan.ResolveGraphResult) (*model.Graph, map[string][]*model.Package, scan.Subproject) {
	aggregate := model.New()
	packageRefs := make(map[string][]*model.Package)
	var seed scan.Subproject
	seedSet := false

	for _, result := range results {
		if result.Graphs == nil {
			continue
		}
		if !seedSet {
			seed = result.SubprojectInfo
			seedSet = true
		}
		for _, entry := range result.Graphs.Entries {
			if entry.Graph == nil {
				continue
			}
			for _, pkg := range entry.Graph.Packages() {
				if pkg == nil {
					continue
				}
				key := scanCanonicalPackageKey(pkg)
				if key == "" {
					key = pkg.ID
				}
				packageRefs[key] = append(packageRefs[key], pkg)
				if _, exists := aggregate.Package(pkg.ID); exists {
					continue
				}
				if err := aggregate.AddPackage(pkg); err != nil && !errors.Is(err, model.ErrPackageAlreadyExist) {
					return nil, nil, scan.Subproject{}
				}
			}
			entry.Graph.WalkRelationships(func(from, to *model.Package) bool {
				if from == nil || to == nil {
					return true
				}
				_ = aggregate.AddDependency(from.ID, to.ID)
				return true
			})
		}
	}

	return aggregate, packageRefs, seed
}

func syncEnrichmentBackToResolvedGraphs(packageRefs map[string][]*model.Package) {
	for _, packages := range packageRefs {
		if len(packages) == 0 {
			continue
		}
		var shared []model.PackageLicense
		var sharedEOL any
		for _, pkg := range packages {
			if pkg != nil && len(pkg.Licenses) > 0 {
				shared = append([]model.PackageLicense(nil), pkg.Licenses...)
			}
			if pkg != nil && pkg.Metadata != nil {
				if value, ok := pkg.Metadata[eolMetadataKey]; ok {
					sharedEOL = value
				}
			}
			if len(shared) > 0 && sharedEOL != nil {
				break
			}
		}
		if len(shared) == 0 && sharedEOL == nil {
			continue
		}
		for _, pkg := range packages {
			if pkg == nil {
				continue
			}
			if len(shared) > 0 && len(pkg.Licenses) == 0 {
				pkg.Licenses = append([]model.PackageLicense(nil), shared...)
			}
			if sharedEOL != nil {
				if pkg.Metadata == nil {
					pkg.Metadata = map[string]any{}
				}
				if _, exists := pkg.Metadata[eolMetadataKey]; !exists {
					pkg.Metadata[eolMetadataKey] = sharedEOL
				}
			}
		}
	}
}

func scanCanonicalPackageKey(pkg *model.Package) string {
	if pkg == nil {
		return ""
	}
	if strings.TrimSpace(pkg.PURL) != "" {
		return "purl:" + strings.ToLower(strings.TrimSpace(pkg.PURL))
	}
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(pkg.Ecosystem)),
		strings.ToLower(strings.TrimSpace(pkg.BuildSystem)),
		strings.ToLower(strings.TrimSpace(pkg.Type)),
		strings.ToLower(strings.TrimSpace(pkg.Org)),
		strings.ToLower(strings.TrimSpace(pkg.Name)),
		strings.TrimSpace(pkg.Version),
	}, "\x00")
}

func resolveGraphs(ctx commandContext, logger *zap.Logger, stderrWriter io.Writer) (graphResolution, error) {
	pipeline := newPipeline(ctx, logger)
	logger.Info(fmt.Sprintf("Resolving dependency graphs for %d subproject(s)", len(ctx.subprojects)))
	resolveResults, err := pipeline.ResolveAll(context.Background(), scan.PipelineRequest{
		ProjectPath:     ctx.executionTarget.Location,
		ExecutionTarget: ctx.executionTarget,
		Subprojects:     ctx.subprojects,
		DetectorFilter:  ctx.detectorFilter,
		InstallFirst:    ctx.config.InstallFirst,
		InstallArgs:     append([]string(nil), ctx.config.InstallArgs...),
		Stderr:          stderrWriter,
		Verbose:         ctx.verbose,
	})
	if err != nil && len(resolveResults) == 0 {
		logger.Error(fmt.Sprintf("Dependency graph resolution failed: %v", err))
		logger.Debug("dependency graph resolution failed", zap.Error(err))
		return graphResolution{}, resolutionFailure(err)
	}
	if err != nil {
		logger.Error(fmt.Sprintf("Dependency graph resolution finished with partial failures after resolving %d subproject(s): %v", len(resolveResults), err))
		logger.Debug("dependency graph resolution partial failure details", zap.Error(err), zap.Int("resolved_count", len(resolveResults)))
	} else {
		logger.Info(fmt.Sprintf("Resolved dependency graphs for %d subproject(s)", len(resolveResults)))
	}
	return graphResolution{Results: resolveResults, PartialFailure: err, DetectorWarnings: scan.PipelineWarningsFromError(err, "detector")}, nil
}

func newScanEngine(ctx commandContext, logger *zap.Logger) *scan.Engine {
	if ctx.runtime != nil && ctx.runtime.Registry != nil {
		return scan.NewEngine(ctx.runtime.Registry)
	}
	return scan.NewEngine(registry.BuildScanRegistry(logger, registryBuilderConfig(ctx.config)))
}

func newPipeline(ctx commandContext, logger *zap.Logger) *scan.Pipeline {
	if ctx.runtime != nil && ctx.runtime.Registry != nil {
		return scan.NewPipeline(ctx.runtime.Registry, logger)
	}
	cfg := registryBuilderConfig(ctx.config)
	registry := registry.BuildScanRegistry(logger, cfg)
	return scan.NewPipeline(registry, logger)
}

func registryBuilderConfig(cfg resolvedConfig) registry.Config {
	return registry.Config{
		HTTPProxy:   cfg.HTTPProxy,
		OsvAPIBase:  cfg.OsvAPIBase,
		OsvCacheDir: cfg.OsvCacheDir,
		OsvCacheTTL: cfg.OsvCacheTTL,
		KEVCacheDir: cfg.KEVCacheDir,
		KEVCacheTTL: cfg.KEVCacheTTL,
		EOLAPIBase:  cfg.EOLAPIBase,
		EOLCacheDir: cfg.EOLCacheDir,
		EOLCacheTTL: cfg.EOLCacheTTL,
	}
}

func pipelineRequest(ctx commandContext, selectedScope scan.Scope, stderr io.Writer) scan.PipelineRequest {
	auditorFilter := ctx.auditorFilter
	if len(auditorFilter.Include) == 0 && len(auditorFilter.Exclude) == 0 {
		auditorFilter = defaultAuditorFilter(ctx.config.Auditors)
	}
	matcherFilter := ctx.matcherFilter
	if len(matcherFilter.Include) == 0 && len(matcherFilter.Exclude) == 0 {
		matcherFilter = defaultMatcherFilter(ctx.config.Matchers)
	}
	return scan.PipelineRequest{
		ProjectPath:     ctx.executionTarget.Location,
		ExecutionTarget: ctx.executionTarget,
		Subprojects:     ctx.subprojects,
		AuditEnabled:    ctx.config.Audit,
		MatchEnabled:    ctx.config.Audit,
		ScopeFilter:     selectedScope,
		AuditorFilter:   auditorFilter,
		MatcherFilter:   matcherFilter,
		DetectorFilter:  ctx.detectorFilter,
		InstallFirst:    ctx.config.InstallFirst,
		InstallArgs:     append([]string(nil), ctx.config.InstallArgs...),
		Stderr:          stderr,
		Verbose:         ctx.verbose,
	}
}

const (
	osvAuditorName             = "osv"
	clearlyDefinedCheckerName  = "clearlydefined-license-checker"
	clearlyDefinedCheckerAlias = "clearlydefined"
	depsdevCheckerName         = "depsdev-license-checker"
	depsdevCheckerAlias        = "deps.dev"
	eolCheckerName             = "eol-checker"
	eolCheckerAlias            = "eol"
	eolMetadataKey             = "endoflife.date"
)

func defaultAuditorFilter(auditors string) scan.AuditorFilter {
	reg := registry.BuildScanRegistry(zap.NewNop(), registry.Config{})
	filter, err := resolveAuditorFilter(auditors, reg)
	if err != nil {
		return scan.AuditorFilter{Exclude: []string{osvAuditorName}}
	}
	return filter
}

func defaultAuditorFilterFromFilter(filter scan.AuditorFilter) scan.AuditorFilter {
	resolved := filter
	if len(resolved.Include) == 0 && len(resolved.Exclude) == 0 {
		resolved = defaultAuditorFilter("")
		return resolved
	}
	if !containsStringValue(resolved.Include, osvAuditorName) {
		resolved.Exclude = appendUnique(resolved.Exclude, osvAuditorName)
	}
	return resolved
}

func defaultMatcherFilter(matchers string) scan.MatcherFilter {
	reg := registry.BuildScanRegistry(zap.NewNop(), registry.Config{})
	filter, err := resolveMatcherFilter(matchers, reg)
	if err != nil {
		return scan.MatcherFilter{Exclude: []string{clearlyDefinedCheckerName, eolCheckerName}}
	}
	return filter
}

func appendUnique(values []string, value string) []string {
	if value == "" || containsStringValue(values, value) {
		return values
	}
	return append(values, value)
}

func containsStringValue(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
