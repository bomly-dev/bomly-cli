package jvmreach

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// Name is the analyzer's stable identifier (used in selectors and output).
const Name = "jvmreach"

// Analyzer is a Tier-3 (package-level) reachability analyzer for
// JVM-ecosystem packages. It groups Maven artifacts in the input
// graph by project root, runs the configured Runner once per
// project, and annotates each PackageVulnerability on JVM packages
// with a Reachability result.
//
// Tier-3 caveat: "unreachable" means "the application source does
// not import this artifact, neither directly nor through any
// dep-graph edge from a directly-imported neighbour". It does NOT
// mean "the vulnerability cannot be triggered" — reflection,
// ServiceLoader, Spring component scanning, OSGi, and JPMS dynamic
// loading are all invisible to a static scanner. See
// docs/REACHABILITY.md for the full caveat list.
type Analyzer struct {
	Runner       Runner
	Logger       *zap.Logger
	CacheDir     string
	CacheTTL     time.Duration
	DisableCache bool
}

// Descriptor returns the registration metadata for the jvmreach analyzer.
func (a Analyzer) Descriptor() model.AnalyzerDescriptor {
	return model.AnalyzerDescriptor{
		Name:                Name,
		Enabled:             true,
		Origin:              model.BundledOrigin,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemMaven, model.EcosystemScala},
		SupportedManagers: []model.PackageManager{
			model.PackageManagerMaven,
			model.PackageManagerGradle,
			model.PackageManagerSBT,
		},
		SupportedLanguages: []model.Language{
			model.LanguageJava,
			model.LanguageKotlin,
			model.LanguageScala,
			model.LanguageGroovy,
		},
		SupportedModes: []model.TargetMode{model.TargetModeFullGraph, model.TargetModeComponent},
		SupportedTiers: []model.ReachabilityTier{model.TierPackage},
	}
}

func (a Analyzer) Ready() bool { return true }

func (a Analyzer) Applicable(_ context.Context, req model.AnalyzeRequest) (bool, error) {
	if req.Graph == nil {
		return false, nil
	}
	for _, pkg := range req.Graph.Packages() {
		if pkg == nil || len(pkg.Vulnerabilities) == 0 {
			continue
		}
		if isJVMPackage(pkg) {
			return true, nil
		}
	}
	return false, nil
}

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
		logger.Info("jvmreach: no JVM project roots discovered; marking all JVM vulnerabilities as unknown")
		annotateAllUnknown(req.Graph, "no-project-root-discovered", time.Now())
		return resultFromGraph(req.Graph), nil
	}

	logger.Info("jvmreach: starting reachability analysis",
		zap.String("runner", runner.Name()),
		zap.String("runner_version", runner.Version()),
		zap.Int("project_roots", len(projectRoots)),
		zap.Bool("cache_enabled", !a.DisableCache),
	)
	logger.Debug("jvmreach: discovered project roots", zap.Strings("paths", projectRoots))

	cache := a.cache()
	stats := model.ReachabilityStats{}
	cacheHits, cacheMisses := 0, 0
	for _, root := range projectRoots {
		select {
		case <-ctx.Done():
			logger.Info("jvmreach: context cancelled; skipping project",
				zap.String("project_root", root))
			annotateProjectUnknown(req.Graph, root, "cancelled", time.Now())
			continue
		default:
		}

		projectStart := time.Now()
		runResult, fromCache, err := a.runWithCache(ctx, runner, cache, root, logger)
		if err != nil {
			logger.Warn("jvmreach: runner failed",
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
		logger.Info("jvmreach: completed project",
			zap.String("project_root", root),
			zap.String("runner", runner.Name()),
			zap.Bool("cache_hit", fromCache),
			zap.Int("source_files", runResult.SourceFiles),
			zap.Int("imported_artifacts", len(runResult.ImportedArtifacts)),
			zap.Int("reachable", applied.reachable),
			zap.Int("unreachable", applied.unreachable),
			zap.Duration("duration", time.Since(projectStart)),
		)
	}

	logger.Info("jvmreach: completed reachability analysis",
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

func (a Analyzer) runWithCache(
	ctx context.Context,
	runner Runner,
	cache *resultCache,
	projectDir string,
	logger *zap.Logger,
) (RunnerResult, bool, error) {
	if cache != nil {
		if cached, ok := cache.get(projectDir, runner.Name(), runner.Version()); ok {
			logger.Debug("jvmreach: cache hit",
				zap.String("project_root", projectDir),
				zap.String("runner", runner.Name()),
				zap.Int("imported_artifacts", len(cached.ImportedArtifacts)))
			return cached, true, nil
		}
		logger.Debug("jvmreach: cache miss",
			zap.String("project_root", projectDir),
			zap.String("runner", runner.Name()))
	}
	result, err := runner.Run(ctx, projectDir)
	if err != nil {
		return RunnerResult{}, false, err
	}
	if cache != nil {
		if err := cache.set(projectDir, runner.Name(), runner.Version(), result); err != nil {
			logger.Debug("jvmreach: cache write failed (non-fatal)",
				zap.String("project_root", projectDir),
				zap.Error(err))
		}
	}
	return result, false, nil
}

func (a Analyzer) cache() *resultCache {
	if a.DisableCache {
		return nil
	}
	return newResultCache(a.CacheDir, a.CacheTTL)
}

func resultFromGraph(g *model.Graph) model.AnalyzeResult {
	return model.AnalyzeResult{Graph: g, AnalyzerRuns: []string{Name}}
}

type applyOutcome struct{ reachable, unreachable, unknown int }

// applyRunnerResult annotates every JVM vulnerability whose owning
// package is attributable to projectRoot. A package is "reachable"
// iff its `groupId:artifactId` is in the transitive closure of the
// runner's imported-artifact set, expanded through Graph.Dependencies.
func applyRunnerResult(g *model.Graph, projectRoot string, runRes RunnerResult, now time.Time) applyOutcome {
	var outcome applyOutcome
	timestamp := now.UTC().Format(time.RFC3339)
	hopsByID := computeReachablePackageHops(g, runRes.ImportedArtifacts)
	dynamicImports := runRes.DynamicImportsDetected
	for _, pkg := range g.Packages() {
		if pkg == nil || !isJVMPackage(pkg) {
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
				Analyzer:               Name,
				AnalyzedAt:             timestamp,
				Tier:                   model.TierPackage,
				DynamicImportsDetected: dynamicImports,
			}
			if hops, ok := hopsByID[pkg.ID]; ok {
				r.Status = model.ReachabilityReachable
				h := hops
				r.Hops = &h
				r.Confidence = model.DeriveConfidence(&h, dynamicImports)
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

// computeReachablePackageHops returns a map from graph package ID to
// the shortest dep-graph distance from a directly-imported artifact.
// Hop 0 packages are directly imported by app source; hop N packages
// are reachable only via N transitive edges.
func computeReachablePackageHops(g *model.Graph, imports map[string]struct{}) map[string]int {
	hops := make(map[string]int)
	if g == nil || len(imports) == 0 {
		return hops
	}
	queue := make([]string, 0)
	for _, pkg := range g.Packages() {
		if pkg == nil || !isJVMPackage(pkg) {
			continue
		}
		if !isPackageImported(pkg, imports) {
			continue
		}
		if _, ok := hops[pkg.ID]; ok {
			continue
		}
		hops[pkg.ID] = 0
		queue = append(queue, pkg.ID)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		current := hops[id]
		deps, err := g.Dependencies(id)
		if err != nil {
			continue
		}
		for _, dep := range deps {
			if dep == nil {
				continue
			}
			if _, ok := hops[dep.ID]; ok {
				continue
			}
			hops[dep.ID] = current + 1
			queue = append(queue, dep.ID)
		}
	}
	return hops
}

// isPackageImported reports whether pkg's Maven coordinate (built
// from Org / Name) appears in the runner's import set.
func isPackageImported(pkg *model.Package, imports map[string]struct{}) bool {
	if pkg == nil || len(imports) == 0 {
		return false
	}
	coord := canonicalCoord(pkg.Org, baseArtifactName(pkg.Name))
	if coord == "" {
		return false
	}
	_, ok := imports[coord]
	return ok
}

// baseArtifactName strips any trailing ":classifier" suffix that the
// Maven detector appends to differentiate artifacts (e.g.
// "jackson-databind:tests"). The reachability map keys on bare
// artifact IDs.
func baseArtifactName(name string) string {
	if i := strings.Index(name, ":"); i >= 0 {
		return name[:i]
	}
	return name
}

func annotateProjectUnknown(g *model.Graph, projectRoot, reason string, now time.Time) int {
	timestamp := now.UTC().Format(time.RFC3339)
	count := 0
	for _, pkg := range g.Packages() {
		if pkg == nil || !isJVMPackage(pkg) {
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
		if pkg == nil || !isJVMPackage(pkg) {
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

func packageBelongsToProjectRoot(pkg *model.Package, projectRoot string) bool {
	if pkg == nil {
		return false
	}
	if len(pkg.Locations) == 0 {
		return true
	}
	for _, loc := range pkg.Locations {
		if loc.RealPath == "" {
			continue
		}
		if pathContainsRoot(loc.RealPath, projectRoot) {
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

func failureReason(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not implemented"), strings.Contains(msg, "not on path"), strings.Contains(msg, "not found"):
		return "missing-toolchain"
	case strings.Contains(msg, "not accessible"), strings.Contains(msg, "no recognised build manifest"):
		return "no-project-root"
	case strings.Contains(msg, "context"), strings.Contains(msg, "cancel"):
		return "cancelled"
	default:
		return "runner-error"
	}
}
