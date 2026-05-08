package jsreach

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Name is the analyzer's stable identifier (used in selectors and output).
const Name = "jsreach"

// Analyzer is a Tier-3 (package-level) reachability analyzer for npm
// packages. It groups npm packages in the input graph by project root,
// runs the configured Runner once per project, and annotates each
// PackageVulnerability on npm packages with a Reachability result.
//
// Tier-3 caveat: "unreachable" here means "the application source does
// not import this package, neither directly nor indirectly through app
// code". It does NOT mean "the vulnerability cannot be triggered".
// docs/REACHABILITY.md is the authoritative source on this distinction.
type Analyzer struct {
	// Runner is the underlying esbuild driver. Defaults to
	// NewDefaultRunner(Logger) when nil.
	Runner Runner
	Logger *zap.Logger
}

// Descriptor returns the registration metadata for the jsreach analyzer.
func (a Analyzer) Descriptor() model.AnalyzerDescriptor {
	return model.AnalyzerDescriptor{
		Name:                Name,
		Enabled:             true,
		Origin:              model.BundledOrigin,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:   []model.PackageManager{model.PackageManagerNPM, model.PackageManagerPNPM, model.PackageManagerYarn},
		SupportedLanguages:  []model.Language{model.LanguageJavaScript, model.LanguageTypeScript},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		SupportedTiers:      []model.ReachabilityTier{model.TierPackage},
	}
}

// Ready reports whether the analyzer is callable. Always true; the
// runner surfaces missing-toolchain or parser errors at Run time as
// Status=Unknown rather than blocking applicability.
func (a Analyzer) Ready() bool { return true }

// Applicable reports whether the request graph contains at least one
// npm package with attached vulnerabilities. Without vulnerabilities
// to annotate, the analyzer would do work without producing output.
func (a Analyzer) Applicable(_ context.Context, req model.AnalyzeRequest) (bool, error) {
	if req.Graph == nil {
		return false, nil
	}
	for _, pkg := range req.Graph.Packages() {
		if pkg == nil || len(pkg.Vulnerabilities) == 0 {
			continue
		}
		if isNPMPackage(pkg) {
			return true, nil
		}
	}
	return false, nil
}

// Analyze runs the configured Runner per discovered npm project root
// and writes Reachability onto every npm PackageVulnerability in the
// graph. Errors degrade to Status=Unknown with a stable Reason — the
// engine relies on this to keep the pipeline running.
func (a Analyzer) Analyze(ctx context.Context, req model.AnalyzeRequest) (model.AnalyzeResult, error) {
	logger := a.logger()
	if req.Graph == nil {
		return model.AnalyzeResult{}, nil
	}
	runner := a.Runner
	if runner == nil {
		runner = NewDefaultRunner(logger)
	}

	overallStart := time.Now()
	projectRoots := discoverProjectRoots(req)
	if len(projectRoots) == 0 {
		logger.Info("jsreach: no npm project roots discovered; marking all npm vulnerabilities as unknown")
		annotateAllUnknown(req.Graph, "no-project-root-discovered", time.Now())
		return resultFromGraph(req.Graph), nil
	}

	logger.Info("jsreach: starting reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("project_roots", len(projectRoots)),
	)
	logger.Debug("jsreach: discovered project roots", zap.Strings("paths", projectRoots))

	stats := model.ReachabilityStats{}
	for _, root := range projectRoots {
		select {
		case <-ctx.Done():
			logger.Info("jsreach: context cancelled; skipping project",
				zap.String("project_root", root))
			annotateProjectUnknown(req.Graph, root, "cancelled", time.Now())
			continue
		default:
		}

		projectStart := time.Now()
		runResult, err := runner.Run(ctx, root)
		if err != nil {
			logger.Warn("jsreach: runner failed",
				zap.String("project_root", root),
				zap.String("runner", runner.Name()),
				zap.Duration("duration", time.Since(projectStart)),
				zap.Error(err))
			reason := failureReason(err)
			added := annotateProjectUnknown(req.Graph, root, reason, time.Now())
			stats.Unknown += added
			continue
		}
		applied := applyRunnerResult(req.Graph, root, runResult, time.Now())
		stats.Reachable += applied.reachable
		stats.Unreachable += applied.unreachable
		stats.Unknown += applied.unknown
		logger.Info("jsreach: completed project",
			zap.String("project_root", root),
			zap.String("runner", runner.Name()),
			zap.Int("entry_points", len(runResult.EntryPoints)),
			zap.Int("source_files", runResult.SourceFiles),
			zap.Int("imported_packages", len(runResult.ImportedPackages)),
			zap.Int("reachable", applied.reachable),
			zap.Int("unreachable", applied.unreachable),
			zap.Duration("duration", time.Since(projectStart)),
		)
	}

	logger.Info("jsreach: completed reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("projects", len(projectRoots)),
		zap.Int("reachable", stats.Reachable),
		zap.Int("unreachable", stats.Unreachable),
		zap.Int("unknown", stats.Unknown),
		zap.Duration("duration", time.Since(overallStart)),
	)

	out := resultFromGraph(req.Graph)
	out.AnalyzerStats = map[string]model.ReachabilityStats{Name: stats}
	return out, nil
}

func (a Analyzer) logger() *zap.Logger { return ensureLogger(a.Logger) }

func resultFromGraph(g *model.Graph) model.AnalyzeResult {
	return model.AnalyzeResult{Graph: g, AnalyzerRuns: []string{Name}}
}

// applyOutcome reports per-vuln Reachability outcomes for telemetry.
type applyOutcome struct {
	reachable, unreachable, unknown int
}

// applyRunnerResult annotates every npm vulnerability whose owning
// package is attributable to projectRoot. A package is "reachable" iff
// its name (or any subpath) appears in the runner's import set;
// otherwise it's marked Unreachable at TierPackage.
func applyRunnerResult(g *model.Graph, projectRoot string, runRes RunnerResult, now time.Time) applyOutcome {
	var outcome applyOutcome
	timestamp := now.UTC().Format(time.RFC3339)
	for _, pkg := range g.Packages() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		if !packageBelongsToProjectRoot(pkg, projectRoot) {
			continue
		}
		for i := range pkg.Vulnerabilities {
			vuln := &pkg.Vulnerabilities[i]
			if vuln.Reachability != nil && vuln.Reachability.Analyzer == Name {
				continue // already annotated by an earlier project pass
			}
			r := &model.Reachability{
				Analyzer:   Name,
				AnalyzedAt: timestamp,
				Tier:       model.TierPackage,
			}
			if isPackageImported(pkg, runRes.ImportedPackages) {
				r.Status = model.ReachabilityReachable
				outcome.reachable++
			} else {
				r.Status = model.ReachabilityUnreachable
				r.Reason = "package-not-imported"
				outcome.unreachable++
			}
			vuln.Reachability = r
		}
	}
	return outcome
}

// isPackageImported reports whether pkg's npm name (or qualified
// scoped name) appears in the runner's bare-specifier import set.
func isPackageImported(pkg *model.Package, imports map[string]struct{}) bool {
	if pkg == nil || len(imports) == 0 {
		return false
	}
	candidates := []string{pkg.QualifiedName(), pkg.Name}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := imports[candidate]; ok {
			return true
		}
	}
	return false
}

func annotateProjectUnknown(g *model.Graph, projectRoot, reason string, now time.Time) int {
	timestamp := now.UTC().Format(time.RFC3339)
	count := 0
	for _, pkg := range g.Packages() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		if !packageBelongsToProjectRoot(pkg, projectRoot) {
			continue
		}
		for i := range pkg.Vulnerabilities {
			if pkg.Vulnerabilities[i].Reachability != nil {
				continue
			}
			pkg.Vulnerabilities[i].Reachability = &model.Reachability{
				Analyzer:   Name,
				Status:     model.ReachabilityUnknown,
				Tier:       model.TierNone,
				Reason:     reason,
				AnalyzedAt: timestamp,
			}
			count++
		}
	}
	return count
}

func annotateAllUnknown(g *model.Graph, reason string, now time.Time) {
	timestamp := now.UTC().Format(time.RFC3339)
	for _, pkg := range g.Packages() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		for i := range pkg.Vulnerabilities {
			if pkg.Vulnerabilities[i].Reachability != nil {
				continue
			}
			pkg.Vulnerabilities[i].Reachability = &model.Reachability{
				Analyzer:   Name,
				Status:     model.ReachabilityUnknown,
				Tier:       model.TierNone,
				Reason:     reason,
				AnalyzedAt: timestamp,
			}
		}
	}
}

// packageBelongsToProjectRoot is a best-effort attribution. jsreach
// runs per-project, so any npm package physically located under
// projectRoot (or with no recorded location) is treated as belonging
// to it. In multi-project repos this may over-attribute; the second
// pass through applyRunnerResult skips already-annotated vulns to
// avoid double-counting.
func packageBelongsToProjectRoot(pkg *model.Package, projectRoot string) bool {
	if pkg == nil {
		return false
	}
	if len(pkg.Locations) == 0 {
		return true
	}
	for _, loc := range pkg.Locations {
		path := loc.RealPath
		if path == "" {
			continue
		}
		if pathContainsRoot(path, projectRoot) {
			return true
		}
	}
	return true
}

func pathContainsRoot(path, root string) bool {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// failureReason maps runner errors to stable machine-readable codes.
// Mirrors govulncheck.failureReason so consumers can lump the two
// analyzers together when filtering / grouping.
func failureReason(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not implemented"), strings.Contains(msg, "not on path"), strings.Contains(msg, "not found"):
		return "missing-toolchain"
	case strings.Contains(msg, "no resolvable entry points"), strings.Contains(msg, "package.json not found"):
		return "no-entry-points"
	case strings.Contains(msg, "context"), strings.Contains(msg, "cancel"):
		return "cancelled"
	default:
		return "runner-error"
	}
}
