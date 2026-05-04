package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/bomly-dev/bomly-cli/internal/scan"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

type graphResolution struct {
	Results          []model.DetectionResult
	PartialFailure   error
	DetectorWarnings []scan.PipelineWarning
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
	cfg := registryBuilderConfig(ctx.config)
	reg := scan.NewRegistry(cfg, *logger)
	reg.Build()
	return scan.NewEngine(reg)
}

func newPipeline(ctx commandContext, logger *zap.Logger) *scan.Pipeline {
	if ctx.runtime != nil && ctx.runtime.Registry != nil {
		return scan.NewPipeline(ctx.runtime.Registry, logger)
	}
	cfg := registryBuilderConfig(ctx.config)
	reg := scan.NewRegistry(cfg, *logger)
	reg.Build()
	return scan.NewPipeline(reg, logger)
}

func registryBuilderConfig(cfg resolvedConfig) scan.RegistryConfigs {
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

func pipelineRequest(ctx commandContext, selectedScope model.Scope, stderr io.Writer) scan.PipelineRequest {
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
		EnrichEnabled:   ctx.config.Enrich,
		AuditEnabled:    ctx.config.Audit,
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

func auditDataAvailabilityWarnings(graphs ...*model.Graph) []scan.PipelineWarning {
	warnings := make([]scan.PipelineWarning, 0, len(graphs))
	for _, g := range graphs {
		if scan.GraphHasVulnerabilityData(g) {
			return warnings
		}
	}
	warnings = append(warnings, scan.PipelineWarning{
		Source:  severityPolicyAuditorName,
		Message: "no vulnerability enrichment input was available; policy evaluation may produce no findings",
	})
	return warnings
}

const (
	osvMatcherName             = "osv"
	grypeMatcherName           = "grype"
	severityPolicyAuditorName  = "severity-policy"
	clearlyDefinedCheckerName  = "clearlydefined-license-checker"
	clearlyDefinedCheckerAlias = "clearlydefined"
	depsdevCheckerName         = "depsdev-license-checker"
	depsdevCheckerAlias        = "deps.dev"
	eolCheckerName             = "eol-checker"
	eolCheckerAlias            = "eol"
	eolMetadataKey             = "endoflife.date"
)

func defaultAuditorFilter(auditorList string) model.AuditorFilter {
	reg := scan.NewRegistry(scan.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	filter, err := resolveAuditorFilter(auditorList, reg)
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
	filter, err := resolveMatcherFilter(matchers, reg)
	if err != nil {
		return model.MatcherFilter{}
	}
	return filter
}
