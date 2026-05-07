package resolve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/selector"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// auditEnrichResult holds the outcome of running auditors against a dependency graph.
type auditEnrichResult struct {
	Findings []model.Finding
}

func EnrichResolvedGraphs(
	ctx opts.Options,
	logger *zap.Logger,
	results []model.DetectionResult,
	stderr io.Writer,
) []model.DetectionResult {
	if len(results) == 0 {
		return results
	}
	aggregateGraph, packageRefs, seed := aggregateResolvedGraphsForLicenseEnrichment(results)
	if aggregateGraph == nil || aggregateGraph.Size() == 0 {
		return results
	}

	engine := newScanEngine(ctx, logger)
	req := model.MatchRequest{
		ProjectPath:     seed.ExecutionTarget.Location,
		ExecutionTarget: seed.ExecutionTarget,
		SubprojectInfo:  seed,
		Ecosystem:       seed.Ecosystem,
		PackageManager:  seed.PrimaryPackageManager(),
		Mode:            model.TargetModeFullGraph,
		Graph:           aggregateGraph,
		MatcherFilter:   defaultMatcherFilter(ctx.ResolvedConfig.Matchers),
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
		if selector.Contains(result.MatcherRuns, opts.EOLCheckerName) {
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
	ctx opts.Options,
	logger *zap.Logger,
	g *model.Graph,
	subproject model.Subproject,
	stderr io.Writer,
) *model.Graph {
	if g == nil {
		return nil
	}
	engine := newScanEngine(ctx, logger)
	req := model.MatchRequest{
		ProjectPath:     subproject.ExecutionTarget.Location,
		ExecutionTarget: subproject.ExecutionTarget,
		SubprojectInfo:  subproject,
		Ecosystem:       subproject.Ecosystem,
		PackageManager:  subproject.PrimaryPackageManager(),
		Mode:            model.TargetModeFullGraph,
		Graph:           g,
		MatcherFilter:   defaultMatcherFilter(ctx.ResolvedConfig.Matchers),
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
		if selector.Contains(result.MatcherRuns, opts.EOLCheckerName) {
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

func EnrichGraph(
	ctx opts.Options,
	logger *zap.Logger,
	g *model.Graph,
	subproject model.Subproject,
	stderr io.Writer,
) *model.Graph {
	return enrichGraph(ctx, logger, g, subproject, stderr)
}

func DeduplicateFindings(findings []model.Finding) []model.Finding {
	return scan.DeduplicateFindings(findings)
}

// AuditGraph runs all registered auditors against g.
// Errors from auditors are logged as warnings; partial results are returned.
func AuditGraph(
	ctx opts.Options,
	logger *zap.Logger,
	g *model.Graph,
	filter model.AuditorFilter,
	stderr io.Writer,
) auditEnrichResult {
	engine := newScanEngine(ctx, logger)
	req := model.AuditRequest{
		Mode:          model.TargetModeFullGraph,
		Graph:         g,
		AuditorFilter: defaultAuditorFilterFromFilter(filter),
		Stderr:        stderr,
	}

	result, err := engine.Audit(context.Background(), req)
	if err != nil {
		logger.Warn("audit: one or more auditors reported errors", zap.Error(err))
	}

	return auditEnrichResult{Findings: scan.DeduplicateFindings(result.Findings)}
}

func auditComponent(
	ctx opts.Options,
	logger *zap.Logger,
	g *model.Graph,
	target *model.Package,
	stderr io.Writer,
) auditEnrichResult {
	if g == nil || target == nil {
		return auditEnrichResult{}
	}
	engine := newScanEngine(ctx, logger)
	req := model.AuditRequest{
		Mode:          model.TargetModeComponent,
		Graph:         g,
		Target:        target,
		Ecosystem:     model.Ecosystem(target.Ecosystem),
		AuditorFilter: defaultAuditorFilter(ctx.ResolvedConfig.Auditors),
		Stderr:        stderr,
	}
	result, err := engine.Audit(context.Background(), req)
	if err != nil {
		logger.Warn("audit: one or more auditors reported errors", zap.Error(err))
	}
	return auditEnrichResult{Findings: scan.DeduplicateFindings(result.Findings)}
}

func AuditComponent(
	ctx opts.Options,
	logger *zap.Logger,
	g *model.Graph,
	target *model.Package,
	stderr io.Writer,
) auditEnrichResult {
	return auditComponent(ctx, logger, g, target, stderr)
}

func DiffAuditSummary(baseFindings, headFindings []model.Finding) *output.DiffAudit {
	introduced, resolved, persisted := diffFindingSets(baseFindings, headFindings)
	combined := append(append([]model.Finding{}, introduced...), persisted...)
	combined = append(combined, resolved...)
	return &output.DiffAudit{
		Introduced:   output.FindingsFromScan(introduced),
		Resolved:     output.FindingsFromScan(resolved),
		Persisted:    output.FindingsFromScan(persisted),
		AuditSummary: output.SummaryFromFindings(combined),
	}
}

func diffFindingSets(baseFindings, headFindings []model.Finding) ([]model.Finding, []model.Finding, []model.Finding) {
	baseByKey := make(map[string]model.Finding, len(baseFindings))
	headByKey := make(map[string]model.Finding, len(headFindings))
	for _, finding := range baseFindings {
		baseByKey[diffFindingKey(finding)] = finding
	}
	for _, finding := range headFindings {
		headByKey[diffFindingKey(finding)] = finding
	}
	introduced := make([]model.Finding, 0)
	resolved := make([]model.Finding, 0)
	persisted := make([]model.Finding, 0)
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

func diffFindingKey(finding model.Finding) string {
	packageID := ""
	if finding.Package != nil {
		packageID = finding.Package.ID
	}
	return fmt.Sprintf("%s|%s|%s|%s", finding.ID, finding.Kind, finding.Source, packageID)
}

func aggregateResolvedGraphsForLicenseEnrichment(results []model.DetectionResult) (*model.Graph, map[string][]*model.Package, model.Subproject) {
	aggregate := model.New()
	packageRefs := make(map[string][]*model.Package)
	var seed model.Subproject
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
					return nil, nil, model.Subproject{}
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
				if value, ok := pkg.Metadata[opts.EOLMetadataKey]; ok {
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
				if _, exists := pkg.Metadata[opts.EOLMetadataKey]; !exists {
					pkg.Metadata[opts.EOLMetadataKey] = sharedEOL
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

type graphResolution struct {
	Results          []model.DetectionResult
	PartialFailure   error
	DetectorWarnings []scan.PipelineWarning
}

func ResolveGraphs(ctx opts.Options, logger *zap.Logger, stderrWriter io.Writer) (graphResolution, error) {
	pipeline := newPipeline(ctx, logger)
	logger.Info(fmt.Sprintf("Resolving dependency graphs for %d subproject(s)", len(ctx.Subprojects())))
	resolveResults, err := pipeline.ResolveAll(context.Background(), scan.PipelineRequest{
		ProjectPath:     ctx.ExecutionTarget().Location,
		ExecutionTarget: ctx.ExecutionTarget(),
		Subprojects:     ctx.Subprojects(),
		DetectorFilter:  ctx.DetectorFilter(),
		InstallFirst:    ctx.ResolvedConfig.InstallFirst,
		InstallArgs:     append([]string(nil), ctx.ResolvedConfig.InstallArgs...),
		Stderr:          stderrWriter,
		Verbose:         ctx.Verbose(),
	})
	if err != nil && len(resolveResults) == 0 {
		logger.Error(fmt.Sprintf("Dependency graph resolution failed: %v", err))
		logger.Debug("dependency graph resolution failed", zap.Error(err))
		return graphResolution{}, exit.ResolutionFailureError(err)
	}
	if err != nil {
		logger.Error(fmt.Sprintf("Dependency graph resolution finished with partial failures after resolving %d subproject(s): %v", len(resolveResults), err))
		logger.Debug("dependency graph resolution partial failure details", zap.Error(err), zap.Int("resolved_count", len(resolveResults)))
	} else {
		logger.Info(fmt.Sprintf("Resolved dependency graphs for %d subproject(s)", len(resolveResults)))
	}
	return graphResolution{Results: resolveResults, PartialFailure: err, DetectorWarnings: scan.PipelineWarningsFromError(err, "detector")}, nil
}

func newScanEngine(ctx opts.Options, logger *zap.Logger) *scan.Engine {
	if ctx.Registry() != nil {
		return scan.NewEngine(ctx.Registry())
	}
	cfg := RegistryBuilderConfig(ctx.ResolvedConfig)
	reg := scan.NewRegistry(cfg, *logger)
	reg.Build()
	return scan.NewEngine(reg)
}

func newPipeline(ctx opts.Options, logger *zap.Logger) *scan.Pipeline {
	if ctx.Registry() != nil {
		return scan.NewPipeline(ctx.Registry(), logger)
	}
	cfg := RegistryBuilderConfig(ctx.ResolvedConfig)
	reg := scan.NewRegistry(cfg, *logger)
	reg.Build()
	return scan.NewPipeline(reg, logger)
}

func NewPipeline(ctx opts.Options, logger *zap.Logger) *scan.Pipeline {
	return newPipeline(ctx, logger)
}

func RegistryBuilderConfig(cfg config.Resolved) scan.RegistryConfigs {
	return scan.RegistryConfigs{
		FailOn:      cfg.FailOn,
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

func pipelineRequest(ctx opts.Options, selectedScope model.Scope, stderr io.Writer) scan.PipelineRequest {
	auditorFilter := ctx.AuditorFilter()
	if len(auditorFilter.Include) == 0 && len(auditorFilter.Exclude) == 0 {
		auditorFilter = defaultAuditorFilter(ctx.ResolvedConfig.Auditors)
	}
	matcherFilter := ctx.MatcherFilter()
	if len(matcherFilter.Include) == 0 && len(matcherFilter.Exclude) == 0 {
		matcherFilter = defaultMatcherFilter(ctx.ResolvedConfig.Matchers)
	}
	return scan.PipelineRequest{
		ProjectPath:     ctx.ExecutionTarget().Location,
		ExecutionTarget: ctx.ExecutionTarget(),
		Subprojects:     ctx.Subprojects(),
		EnrichEnabled:   ctx.ResolvedConfig.Enrich,
		AuditEnabled:    ctx.ResolvedConfig.Audit,
		ScopeFilter:     selectedScope,
		AuditorFilter:   auditorFilter,
		MatcherFilter:   matcherFilter,
		DetectorFilter:  ctx.DetectorFilter(),
		InstallFirst:    ctx.ResolvedConfig.InstallFirst,
		InstallArgs:     append([]string(nil), ctx.ResolvedConfig.InstallArgs...),
		Stderr:          stderr,
		Verbose:         ctx.Verbose(),
	}
}

func PipelineRequest(ctx opts.Options, selectedScope model.Scope, stderr io.Writer) scan.PipelineRequest {
	return pipelineRequest(ctx, selectedScope, stderr)
}

func AuditDataAvailabilityWarnings(graphs ...*model.Graph) []scan.PipelineWarning {
	warnings := make([]scan.PipelineWarning, 0, len(graphs))
	for _, g := range graphs {
		if scan.GraphHasVulnerabilityData(g) {
			return warnings
		}
	}
	warnings = append(warnings, scan.PipelineWarning{
		Source:  opts.SeverityPolicyAuditorName,
		Message: "no vulnerability enrichment input was available; policy evaluation may produce no findings",
	})
	return warnings
}

func defaultAuditorFilter(auditorList string) model.AuditorFilter {
	reg := scan.NewRegistry(scan.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	filter, err := opts.ResolveAuditorFilter(auditorList, reg)
	if err != nil {
		return model.AuditorFilter{}
	}
	return filter
}

func defaultAuditorFilterFromFilter(filter model.AuditorFilter) model.AuditorFilter {
	resolved := filter
	if len(resolved.Include) == 0 && len(resolved.Exclude) == 0 {
		resolved = defaultAuditorFilter("")
		return resolved
	}
	return resolved
}

func defaultMatcherFilter(matchers string) model.MatcherFilter {
	reg := scan.NewRegistry(scan.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	filter, err := opts.ResolveMatcherFilter(matchers, reg)
	if err != nil {
		return model.MatcherFilter{}
	}
	return filter
}
