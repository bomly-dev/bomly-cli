package govulncheck

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Name is the analyzer's stable identifier (used in selectors and output).
const Name = "govulncheck"

// Analyzer is a Go reachability analyzer backed by govulncheck.
//
// It groups Go packages in the input graph by module root, runs the
// configured Runner once per module, and annotates each PackageVulnerability
// on Go packages with a Reachability result.
type Analyzer struct {
	// Runner is the underlying govulncheck driver. Defaults to
	// NewRunner(Logger) when nil.
	Runner Runner
	Logger *zap.Logger
	// CacheDir overrides the default per-module result cache location.
	// Empty means "use the OS user cache directory under bomly/analyzers/govulncheck".
	CacheDir string
	// CacheTTL overrides the default 24h cache lifetime. Zero means use
	// the default. Negative values are treated as "no cache" (the cache
	// helper coerces them to default; explicit disable is via DisableCache).
	CacheTTL time.Duration
	// DisableCache turns off the on-disk result cache entirely. Useful in
	// CI smoke runs where freshness matters more than speed.
	DisableCache bool
}

// Descriptor returns the registration metadata for the govulncheck analyzer.
func (a Analyzer) Descriptor() model.AnalyzerDescriptor {
	return model.AnalyzerDescriptor{
		Name:                Name,
		Enabled:             true,
		Origin:              model.BundledOrigin,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemGo},
		SupportedManagers:   []model.PackageManager{model.PackageManagerGoMod},
		SupportedLanguages:  []model.Language{model.LanguageGo},
		SupportedModes:      []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		SupportedTiers:      []model.ReachabilityTier{model.TierSymbol, model.TierPackage},
	}
}

// Ready reports whether the analyzer is callable. Always true; the runner
// surfaces missing-toolchain errors at Run time as Status=Unknown rather
// than blocking applicability.
func (a Analyzer) Ready() bool { return true }

// Applicable reports whether the request graph contains at least one Go
// package with attached vulnerabilities. Without vulnerabilities to
// annotate, the analyzer would do work without producing output.
func (a Analyzer) Applicable(_ context.Context, req model.AnalyzeRequest) (bool, error) {
	if req.Graph == nil || req.Registry == nil {
		return false, nil
	}
	for _, dep := range req.Graph.Nodes() {
		if dep == nil || !isGoPackage(dep) {
			continue
		}
		pkg, ok := req.Registry.Get(dependencyPURL(dep))
		if !ok || pkg == nil || len(pkg.Vulnerabilities) == 0 {
			continue
		}
		return true, nil
	}
	return false, nil
}

// dependencyPURL returns the registry key for a dependency node.
func dependencyPURL(dep *model.Dependency) string {
	if dep == nil {
		return ""
	}
	if dep.PackageRef != "" {
		return dep.PackageRef
	}
	return model.CanonicalPackageURLFromDependency(dep)
}

// Analyze runs govulncheck per Go module root and writes Reachability
// onto every Go PackageVulnerability in the graph. Errors degrade to
// Status=Unknown with a stable Reason — the engine relies on this to
// keep the pipeline running.
func (a Analyzer) Analyze(ctx context.Context, req model.AnalyzeRequest) (model.AnalyzeResult, error) {
	logger := a.logger()
	if req.Graph == nil || req.Registry == nil {
		return model.AnalyzeResult{}, nil
	}
	runner := a.Runner
	if runner == nil {
		runner = NewRunner(logger)
	}

	overallStart := time.Now()
	moduleRoots := discoverModuleRoots(req)
	if len(moduleRoots) == 0 {
		// No module roots discovered — annotate every Go vuln as
		// Unknown so consumers know the analyzer was attempted.
		logger.Info("govulncheck: no module roots discovered; marking all Go vulnerabilities as unknown")
		annotateAllUnknown(req, "no-module-root-discovered", time.Now())
		return resultForRequest(), nil
	}

	logger.Info("govulncheck: starting reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("module_roots", len(moduleRoots)),
		zap.Bool("cache_enabled", !a.DisableCache),
	)
	logger.Debug("govulncheck: discovered module roots", zap.Strings("paths", moduleRoots))

	cache := a.cache()
	stats := model.ReachabilityStats{}
	cacheHits, cacheMisses := 0, 0
	for _, root := range moduleRoots {
		select {
		case <-ctx.Done():
			logger.Info("govulncheck: context cancelled; skipping module",
				zap.String("module_root", root))
			annotateModuleUnknown(req, root, "cancelled", time.Now())
			continue
		default:
		}

		moduleStart := time.Now()
		runResult, fromCache, err := a.runWithCache(ctx, runner, cache, root, logger)
		if err != nil {
			logger.Warn("govulncheck: runner failed",
				zap.String("module_root", root),
				zap.String("runner", runner.Name()),
				zap.Duration("duration", time.Since(moduleStart)),
				zap.Error(err))
			reason := failureReason(err)
			added := annotateModuleUnknown(req, root, reason, time.Now())
			stats.Unknown += added
			continue
		}
		if fromCache {
			cacheHits++
		} else {
			cacheMisses++
		}
		applied := applyRunnerResult(req, root, runResult, runner.Name(), time.Now())
		stats.Reachable += applied.reachable
		stats.Unreachable += applied.unreachable
		stats.Unknown += applied.unknown
		logger.Info("govulncheck: completed module",
			zap.String("module_root", root),
			zap.String("runner", runner.Name()),
			zap.Bool("cache_hit", fromCache),
			zap.Int("findings", len(runResult.Findings)),
			zap.Int("reachable", applied.reachable),
			zap.Int("unreachable", applied.unreachable),
			zap.Duration("duration", time.Since(moduleStart)),
		)
	}

	logger.Info("govulncheck: completed reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("modules", len(moduleRoots)),
		zap.Int("cache_hits", cacheHits),
		zap.Int("cache_misses", cacheMisses),
		zap.Int("reachable", stats.Reachable),
		zap.Int("unreachable", stats.Unreachable),
		zap.Int("unknown", stats.Unknown),
		zap.Duration("duration", time.Since(overallStart)),
	)

	out := resultForRequest()
	out.AnalyzerStats = map[string]model.ReachabilityStats{Name: stats}
	return out, nil
}

// runWithCache returns (result, fromCache, error) for one module. Cache
// failures are non-fatal — the runner still gets a chance to produce
// fresh output. Cache writes after successful runs are also non-fatal.
func (a Analyzer) runWithCache(
	ctx context.Context,
	runner Runner,
	cache *resultCache,
	moduleDir string,
	logger *zap.Logger,
) (RunnerResult, bool, error) {
	if cache != nil {
		if cached, ok := cache.get(moduleDir, runner.Name()); ok {
			logger.Debug("govulncheck: cache hit",
				zap.String("module_root", moduleDir),
				zap.String("runner", runner.Name()),
				zap.Int("findings", len(cached.Findings)))
			return cached, true, nil
		}
		logger.Debug("govulncheck: cache miss",
			zap.String("module_root", moduleDir),
			zap.String("runner", runner.Name()))
	}
	result, err := runner.Run(ctx, moduleDir)
	if err != nil {
		return RunnerResult{}, false, err
	}
	if cache != nil {
		if err := cache.set(moduleDir, runner.Name(), result); err != nil {
			logger.Debug("govulncheck: cache write failed (non-fatal)",
				zap.String("module_root", moduleDir),
				zap.Error(err))
		}
	}
	return result, false, nil
}

// cache returns the configured result cache, or nil when caching is
// disabled. Cache construction errors are swallowed deliberately — they
// degrade to "no cache" rather than failing the analyzer.
func (a Analyzer) cache() *resultCache {
	if a.DisableCache {
		return nil
	}
	return newResultCache(a.CacheDir, a.CacheTTL)
}

func (a Analyzer) logger() *zap.Logger { return ensureLogger(a.Logger) }

func resultForRequest() model.AnalyzeResult {
	return model.AnalyzeResult{AnalyzerRuns: []string{Name}}
}

// vulnerabilitiesForDependency returns the registry vulnerabilities for a
// dependency node, or nil when the package is absent from the registry.
func vulnerabilitiesForDependency(req model.AnalyzeRequest, dep *model.Dependency) []model.Vulnerability {
	if req.Registry == nil || dep == nil {
		return nil
	}
	pkg, ok := req.Registry.Get(dependencyPURL(dep))
	if !ok || pkg == nil {
		return nil
	}
	return pkg.Vulnerabilities
}

// applyOutcome reports per-vuln Reachability outcomes for telemetry.
type applyOutcome struct {
	reachable, unreachable, unknown int
}

// applyRunnerResult annotates every Go vulnerability whose owning
// package's module path matches moduleRoot. Vulnerabilities not present
// in govulncheck's output are marked as either TierPackage Unreachable
// (module not imported) or TierSymbol Unreachable (imported but no call
// path).
func applyRunnerResult(req model.AnalyzeRequest, moduleRoot string, runRes RunnerResult, runnerName string, now time.Time) applyOutcome {
	var outcome applyOutcome
	timestamp := now.UTC().Format(time.RFC3339)
	for _, dep := range req.Graph.Nodes() {
		if dep == nil || !isGoPackage(dep) {
			continue
		}
		if !packageBelongsToModuleRoot(dep, moduleRoot) {
			continue
		}
		vulns := vulnerabilitiesForDependency(req, dep)
		for i := range vulns {
			vuln := &vulns[i]
			if vuln.Reachability != nil && vuln.Reachability.Analyzer == Name {
				continue // already annotated by an earlier module pass
			}
			finding, hit := lookupFinding(runRes, vuln)
			r := &model.Reachability{
				Analyzer:   Name,
				AnalyzedAt: timestamp,
			}
			switch {
			case hit && finding.CalledBy:
				r.Status = model.ReachabilityReachable
				r.Tier = model.TierSymbol
				r.Symbols = append([]model.AffectedSymbol(nil), finding.Symbols...)
				r.CallPaths = append([]model.CallPath(nil), finding.CallPaths...)
				outcome.reachable++
			case hit && finding.ImportedBy:
				r.Status = model.ReachabilityUnreachable
				r.Tier = model.TierSymbol
				r.Reason = "no-call-into-vulnerable-symbol"
				outcome.unreachable++
			case packageImportedByModule(dep, runRes.ImportedModules):
				r.Status = model.ReachabilityUnreachable
				r.Tier = model.TierSymbol
				r.Reason = "no-call-into-vulnerable-symbol"
				outcome.unreachable++
			default:
				r.Status = model.ReachabilityUnreachable
				r.Tier = model.TierPackage
				r.Reason = "package-not-imported"
				outcome.unreachable++
			}
			_ = runnerName // reserved for future Reason annotation
			vuln.Reachability = r
		}
	}
	return outcome
}

func annotateModuleUnknown(req model.AnalyzeRequest, moduleRoot, reason string, now time.Time) int {
	timestamp := now.UTC().Format(time.RFC3339)
	count := 0
	for _, dep := range req.Graph.Nodes() {
		if dep == nil || !isGoPackage(dep) {
			continue
		}
		if !packageBelongsToModuleRoot(dep, moduleRoot) {
			continue
		}
		vulns := vulnerabilitiesForDependency(req, dep)
		for i := range vulns {
			if vulns[i].Reachability != nil {
				continue
			}
			vulns[i].Reachability = &model.Reachability{
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

func annotateAllUnknown(req model.AnalyzeRequest, reason string, now time.Time) {
	timestamp := now.UTC().Format(time.RFC3339)
	for _, dep := range req.Graph.Nodes() {
		if dep == nil || !isGoPackage(dep) {
			continue
		}
		vulns := vulnerabilitiesForDependency(req, dep)
		for i := range vulns {
			if vulns[i].Reachability != nil {
				continue
			}
			vulns[i].Reachability = &model.Reachability{
				Analyzer:   Name,
				Status:     model.ReachabilityUnknown,
				Tier:       model.TierNone,
				Reason:     reason,
				AnalyzedAt: timestamp,
			}
		}
	}
}

// lookupFinding resolves a PackageVulnerability against the runner's
// findings via OSV id and aliases. Grype emits CVE-prefixed identifiers
// while govulncheck emits GO/GHSA ids; this function bridges the two via
// the alias arrays produced by the OSV envelopes.
func lookupFinding(r RunnerResult, vuln *model.Vulnerability) (Finding, bool) {
	if vuln == nil {
		return Finding{}, false
	}
	if f, ok := r.Findings[vuln.ID]; ok {
		return f, true
	}
	for _, alias := range vuln.Aliases {
		if f, ok := r.Findings[alias]; ok {
			return f, true
		}
	}
	for id, f := range r.Findings {
		if id == vuln.ID {
			return f, true
		}
		for _, alias := range f.Aliases {
			if alias == vuln.ID {
				return f, true
			}
			for _, vulnAlias := range vuln.Aliases {
				if alias == vulnAlias {
					return f, true
				}
			}
		}
	}
	return Finding{}, false
}

// isGoPackage reports whether pkg's ecosystem or build system identifies
// it as a Go module dependency.
func isGoPackage(pkg *model.Dependency) bool {
	if pkg == nil {
		return false
	}
	if strings.EqualFold(pkg.Ecosystem, string(model.EcosystemGo)) {
		return true
	}
	if strings.EqualFold(pkg.BuildSystem, "gomod") || strings.EqualFold(pkg.BuildSystem, "go") {
		return true
	}
	if strings.EqualFold(pkg.Language, string(model.LanguageGo)) {
		return true
	}
	return false
}

// packageBelongsToModuleRoot is a best-effort attribution. govulncheck
// runs per-module, so any Go package physically located under moduleRoot
// (or with no recorded location) is treated as belonging to it. In
// multi-module repos this may over-attribute; the second pass through
// applyRunnerResult skips already-annotated vulns to avoid double-counting.
func packageBelongsToModuleRoot(pkg *model.Dependency, moduleRoot string) bool {
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
		if pathContainsRoot(path, moduleRoot) {
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

func packageImportedByModule(pkg *model.Dependency, importedModules map[string]struct{}) bool {
	if pkg == nil || len(importedModules) == 0 {
		return false
	}
	if _, ok := importedModules[pkg.Name]; ok {
		return true
	}
	if _, ok := importedModules[pkg.QualifiedName()]; ok {
		return true
	}
	return false
}

// failureReason maps runner errors to stable machine-readable codes.
// Order matters: more-specific patterns are checked before the
// generic build-failed/runner-error fallbacks so SARIF / JSON
// consumers can branch on the exact failure mode.
func failureReason(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	// Toolchain / executable missing — distinct from a build failure
	// because the user can't act on it the same way (install Go, vs.
	// fix their source).
	case strings.Contains(msg, "not on path"),
		strings.Contains(msg, "executable not found"),
		strings.Contains(msg, "not yet vendored"):
		return "missing-toolchain"
	// Cancellation propagates through both context.Canceled and
	// govulncheck's own wrapping.
	case strings.Contains(msg, "context canceled"),
		strings.Contains(msg, "context deadline"),
		strings.Contains(msg, "cancel"):
		return "cancelled"
	// "no Go files in", "build constraints exclude all Go files", and
	// "no packages matching" all mean the target dir is not a Go
	// package — separate failure mode from a build that fails on
	// real Go code.
	case strings.Contains(msg, "no go files"),
		strings.Contains(msg, "no packages matching"),
		strings.Contains(msg, "build constraints exclude"):
		return "no-go-packages"
	// "missing go.sum entry" / "go: download" / "cannot find module"
	// — module-resolution failures distinct from a compile-stage error.
	case strings.Contains(msg, "missing go.sum"),
		strings.Contains(msg, "cannot find module"),
		strings.Contains(msg, "go.mod file not found"),
		strings.Contains(msg, "no required module"),
		strings.Contains(msg, "verifying module"):
		return "module-resolution-failed"
	// "go: parse" / "go.mod:" syntax errors.
	case strings.Contains(msg, "go.mod:") && strings.Contains(msg, "syntax"),
		strings.Contains(msg, "errors parsing go.mod"):
		return "invalid-go-mod"
	// Compile-stage errors: "build failed", "exit status 1/2",
	// "syntax error", "undefined:". All actionable by the user
	// fixing their source.
	case strings.Contains(msg, "build failed"),
		strings.Contains(msg, "exit status 1"),
		strings.Contains(msg, "exit status 2"),
		strings.Contains(msg, "syntax error"),
		strings.Contains(msg, "undefined:"),
		strings.Contains(msg, "imported and not used"):
		return "build-failed"
	// Generic fallback when we can't classify further; preserves the
	// historical default.
	case strings.Contains(msg, "not found"):
		return "missing-toolchain"
	default:
		return "runner-error"
	}
}
