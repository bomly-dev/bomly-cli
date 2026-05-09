package pyreach

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Name is the analyzer's stable identifier (used in selectors and output).
const Name = "pyreach"

// Analyzer is a Tier-3 (package-level) reachability analyzer for
// Python packages. It groups Python packages in the input graph by
// project root, runs the configured Runner once per project, and
// annotates each PackageVulnerability on Python packages with a
// Reachability result.
//
// Tier-3 caveat: "unreachable" here means "the application source
// does not import this distribution, neither directly nor indirectly
// through app code". It does NOT mean "the vulnerability cannot be
// triggered". Python is highly dynamic — importlib.import_module on
// user input, plugin discovery via entry points, Django
// INSTALLED_APPS strings — and none of those are visible to a static
// scanner. docs/REACHABILITY.md is the authoritative source on this.
type Analyzer struct {
	// Runner is the underlying scanner. Defaults to
	// NewRunner(Logger) when nil.
	Runner Runner
	Logger *zap.Logger
	// CacheDir overrides the default per-project result cache
	// location. Empty means "use the OS user cache directory under
	// bomly/analyzers/pyreach".
	CacheDir string
	// CacheTTL overrides the default 24h cache lifetime. Zero means
	// use the default.
	CacheTTL time.Duration
	// DisableCache turns off the on-disk result cache entirely.
	// Useful in CI smoke runs where freshness matters more than
	// speed.
	DisableCache bool
}

// Descriptor returns the registration metadata for the pyreach analyzer.
func (a Analyzer) Descriptor() model.AnalyzerDescriptor {
	return model.AnalyzerDescriptor{
		Name:                Name,
		Enabled:             true,
		Origin:              model.BundledOrigin,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemPython},
		SupportedManagers: []model.PackageManager{
			model.PackageManagerPip,
			model.PackageManagerPipenv,
			model.PackageManagerPoetry,
			model.PackageManagerUV,
			model.PackageManagerPDM,
			model.PackageManagerSetupPy,
		},
		SupportedLanguages: []model.Language{model.LanguagePython},
		SupportedModes:     []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		SupportedTiers:     []model.ReachabilityTier{model.TierPackage},
	}
}

// Ready reports whether the analyzer is callable. Always true; the
// runner surfaces missing-source / parse errors at Run time as
// Status=Unknown rather than blocking applicability.
func (a Analyzer) Ready() bool { return true }

// Applicable reports whether the request graph contains at least one
// Python package with attached vulnerabilities.
func (a Analyzer) Applicable(_ context.Context, req model.AnalyzeRequest) (bool, error) {
	if req.Graph == nil {
		return false, nil
	}
	for _, pkg := range req.Graph.Packages() {
		if pkg == nil || len(pkg.Vulnerabilities) == 0 {
			continue
		}
		if isPythonPackage(pkg) {
			return true, nil
		}
	}
	return false, nil
}

// Analyze runs the configured Runner per discovered Python project
// root and writes Reachability onto every Python PackageVulnerability
// in the graph. Errors degrade to Status=Unknown with a stable Reason
// — the engine relies on this to keep the pipeline running.
func (a Analyzer) Analyze(ctx context.Context, req model.AnalyzeRequest) (model.AnalyzeResult, error) {
	logger := a.logger()
	if req.Graph == nil {
		return model.AnalyzeResult{}, nil
	}
	runner := a.Runner
	if runner == nil {
		runner = NewRunner(logger)
	}

	overallStart := time.Now()
	projectRoots := discoverProjectRoots(req)
	if len(projectRoots) == 0 {
		logger.Info("pyreach: no Python project roots discovered; marking all Python vulnerabilities as unknown")
		annotateAllUnknown(req.Graph, "no-project-root-discovered", time.Now())
		return resultFromGraph(req.Graph), nil
	}

	logger.Info("pyreach: starting reachability analysis",
		zap.String("runner", runner.Name()),
		zap.String("runner_version", runner.Version()),
		zap.Int("project_roots", len(projectRoots)),
		zap.Bool("cache_enabled", !a.DisableCache),
	)
	logger.Debug("pyreach: discovered project roots", zap.Strings("paths", projectRoots))

	cache := a.cache()
	stats := model.ReachabilityStats{}
	cacheHits, cacheMisses := 0, 0
	for _, root := range projectRoots {
		select {
		case <-ctx.Done():
			logger.Info("pyreach: context cancelled; skipping project",
				zap.String("project_root", root))
			annotateProjectUnknown(req.Graph, root, "cancelled", time.Now())
			continue
		default:
		}

		projectStart := time.Now()
		runResult, fromCache, err := a.runWithCache(ctx, runner, cache, root, logger)
		if err != nil {
			logger.Warn("pyreach: runner failed",
				zap.String("project_root", root),
				zap.String("runner", runner.Name()),
				zap.Duration("duration", time.Since(projectStart)),
				zap.Error(err))
			reason := failureReason(err)
			added := annotateProjectUnknown(req.Graph, root, reason, time.Now())
			stats.Unknown += added
			continue
		}
		if fromCache {
			cacheHits++
		} else {
			cacheMisses++
		}
		applied := applyRunnerResult(req.Graph, root, runResult, time.Now())
		stats.Reachable += applied.reachable
		stats.Unreachable += applied.unreachable
		stats.Unknown += applied.unknown
		logger.Info("pyreach: completed project",
			zap.String("project_root", root),
			zap.String("runner", runner.Name()),
			zap.Bool("cache_hit", fromCache),
			zap.Int("source_files", runResult.SourceFiles),
			zap.Int("imported_distributions", len(runResult.ImportedDistributions)),
			zap.Int("reachable", applied.reachable),
			zap.Int("unreachable", applied.unreachable),
			zap.Duration("duration", time.Since(projectStart)),
		)
	}

	logger.Info("pyreach: completed reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("projects", len(projectRoots)),
		zap.Int("cache_hits", cacheHits),
		zap.Int("cache_misses", cacheMisses),
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

// runWithCache returns (result, fromCache, error) for one project.
// Cache failures are non-fatal — the runner still gets a chance to
// produce fresh output. Cache writes after successful runs are also
// non-fatal.
func (a Analyzer) runWithCache(
	ctx context.Context,
	runner Runner,
	cache *resultCache,
	projectDir string,
	logger *zap.Logger,
) (RunnerResult, bool, error) {
	if cache != nil {
		if cached, ok := cache.get(projectDir, runner.Name(), runner.Version()); ok {
			logger.Debug("pyreach: cache hit",
				zap.String("project_root", projectDir),
				zap.String("runner", runner.Name()),
				zap.Int("imported_distributions", len(cached.ImportedDistributions)))
			return cached, true, nil
		}
		logger.Debug("pyreach: cache miss",
			zap.String("project_root", projectDir),
			zap.String("runner", runner.Name()))
	}
	result, err := runner.Run(ctx, projectDir)
	if err != nil {
		return RunnerResult{}, false, err
	}
	if cache != nil {
		if err := cache.set(projectDir, runner.Name(), runner.Version(), result); err != nil {
			logger.Debug("pyreach: cache write failed (non-fatal)",
				zap.String("project_root", projectDir),
				zap.Error(err))
		}
	}
	return result, false, nil
}

// cache returns the configured result cache, or nil when caching is
// disabled. Cache construction errors are swallowed deliberately —
// they degrade to "no cache" rather than failing the analyzer.
func (a Analyzer) cache() *resultCache {
	if a.DisableCache {
		return nil
	}
	return newResultCache(a.CacheDir, a.CacheTTL)
}

func resultFromGraph(g *model.Graph) model.AnalyzeResult {
	return model.AnalyzeResult{Graph: g, AnalyzerRuns: []string{Name}}
}

// applyOutcome reports per-vuln Reachability outcomes for telemetry.
type applyOutcome struct {
	reachable, unreachable, unknown int
}

// applyRunnerResult annotates every Python vulnerability whose
// owning package is attributable to projectRoot. A package is
// "reachable" iff it is in the transitive closure of the runner's
// imported-distribution set walked through the dep graph; otherwise
// it is marked Unreachable at TierPackage.
//
// The transitive closure is essential — the import scanner only
// captures distributions whose top-level module appears in app
// source. A CVE in a transitive dep (e.g. urllib3 pulled in by
// requests) would be missed otherwise. The closure follows
// Graph.Dependencies edges, so it sees exactly the dep tree the
// Python detector resolved from the lockfile.
func applyRunnerResult(g *model.Graph, projectRoot string, runRes RunnerResult, now time.Time) applyOutcome {
	var outcome applyOutcome
	timestamp := now.UTC().Format(time.RFC3339)
	reachableIDs := computeReachablePackageIDs(g, runRes.ImportedDistributions)
	for _, pkg := range g.Packages() {
		if pkg == nil || !isPythonPackage(pkg) {
			continue
		}
		if !packageBelongsToProjectRoot(pkg, projectRoot) {
			continue
		}
		for i := range pkg.Vulnerabilities {
			vuln := &pkg.Vulnerabilities[i]
			if vuln.Reachability != nil && vuln.Reachability.Analyzer == Name {
				continue
			}
			r := &model.Reachability{
				Analyzer:   Name,
				AnalyzedAt: timestamp,
				Tier:       model.TierPackage,
			}
			if _, ok := reachableIDs[pkg.ID]; ok {
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

// computeReachablePackageIDs returns the set of graph package IDs
// reachable from the imported-distribution set, expanded transitively
// through the dep graph. Working in IDs (rather than names) keeps the
// attribution honest when multiple versions of the same distribution
// coexist in the resolved lockfile.
func computeReachablePackageIDs(g *model.Graph, imports map[string]struct{}) map[string]struct{} {
	reachable := make(map[string]struct{})
	if g == nil || len(imports) == 0 {
		return reachable
	}
	queue := make([]string, 0)
	for _, pkg := range g.Packages() {
		if pkg == nil || !isPythonPackage(pkg) {
			continue
		}
		if !isPackageImported(pkg, imports) {
			continue
		}
		if _, ok := reachable[pkg.ID]; ok {
			continue
		}
		reachable[pkg.ID] = struct{}{}
		queue = append(queue, pkg.ID)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		deps, err := g.Dependencies(id)
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			if _, ok := reachable[dep.ID]; ok {
				continue
			}
			reachable[dep.ID] = struct{}{}
			queue = append(queue, dep.ID)
		}
	}
	return reachable
}

// isPackageImported reports whether pkg's distribution name (in any
// of its known forms) appears in the runner's import set. Names are
// compared in PEP 503 normalized form so that hyphens, underscores,
// and case differences don't cause mismatches.
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
		if _, ok := imports[canonicalDistName(candidate)]; ok {
			return true
		}
	}
	return false
}

func annotateProjectUnknown(g *model.Graph, projectRoot, reason string, now time.Time) int {
	timestamp := now.UTC().Format(time.RFC3339)
	count := 0
	for _, pkg := range g.Packages() {
		if pkg == nil || !isPythonPackage(pkg) {
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
		if pkg == nil || !isPythonPackage(pkg) {
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

// packageBelongsToProjectRoot is a best-effort attribution. pyreach
// runs per-project, so any Python package physically located under
// projectRoot (or with no recorded location) is treated as belonging
// to it.
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
func failureReason(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not implemented"), strings.Contains(msg, "not on path"), strings.Contains(msg, "not found"):
		return "missing-toolchain"
	case strings.Contains(msg, "not accessible"), strings.Contains(msg, "no recognised lockfile"):
		return "no-project-root"
	case strings.Contains(msg, "context"), strings.Contains(msg, "cancel"):
		return "cancelled"
	default:
		return "runner-error"
	}
}
