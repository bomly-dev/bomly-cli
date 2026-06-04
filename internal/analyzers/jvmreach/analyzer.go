package jvmreach

import (
	"context"
	"path/filepath"
	"sort"
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
	if req.Graph == nil || req.Registry == nil {
		return false, nil
	}
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil || !isJVMPackage(pkg) {
			continue
		}
		regPkg, ok := req.Registry.Get(dependencyPURL(pkg))
		if !ok || regPkg == nil || len(regPkg.Vulnerabilities) == 0 {
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
	return dep.PURL
}

// vulnerabilitiesForDep returns the registry slice for a dependency. The
// caller may mutate the returned slice in place; entries live on the
// shared backing array owned by the registry package.
func vulnerabilitiesForDep(req model.AnalyzeRequest, dep *model.Dependency) []model.Vulnerability {
	if req.Registry == nil || dep == nil {
		return nil
	}
	pkg, ok := req.Registry.Get(dependencyPURL(dep))
	if !ok || pkg == nil {
		return nil
	}
	return pkg.Vulnerabilities
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
	hierarchies := discoverModuleHierarchies(req)
	if len(hierarchies) == 0 {
		logger.Info("jvmreach: no JVM project roots discovered; marking all JVM vulnerabilities as unknown")
		annotateAllUnknown(req, "no-project-root-discovered", time.Now())
		return resultFromRequest(req), nil
	}

	logger.Info("jvmreach: starting reachability analysis",
		zap.String("runner", runner.Name()),
		zap.String("runner_version", runner.Version()),
		zap.Int("module_hierarchies", len(hierarchies)),
		zap.Bool("cache_enabled", !a.DisableCache),
	)
	logger.Debug("jvmreach: discovered module hierarchies", zap.Strings("paths", moduleHierarchyRoots(hierarchies)))

	cache := a.cache()
	stats := model.ReachabilityStats{}
	cacheHits, cacheMisses := 0, 0
	for _, hierarchy := range hierarchies {
		root := hierarchy.Root
		select {
		case <-ctx.Done():
			logger.Info("jvmreach: context cancelled; skipping project",
				zap.String("project_root", root))
			annotateProjectUnknown(req, root, "cancelled", time.Now())
			continue
		default:
		}

		projectStart := time.Now()
		closure, hits, misses := a.analyzeModuleHierarchy(ctx, runner, cache, hierarchy, logger)
		cacheHits += hits
		cacheMisses += misses
		var applied applyOutcome
		if closure.incomplete {
			added := annotateProjectUnknown(req, root, closure.reason, time.Now())
			applied.unknown += added
		} else {
			applied = applyImportedArtifactSeeds(req, root, closure.importedArtifacts, closure.dynamicImports, time.Now())
		}
		stats.Reachable += applied.reachable
		stats.Unreachable += applied.unreachable
		stats.Unknown += applied.unknown
		logger.Info("jvmreach: completed module hierarchy",
			zap.String("project_root", root),
			zap.String("runner", runner.Name()),
			zap.Int("modules", len(hierarchy.Modules)),
			zap.Int("cache_hits", hits),
			zap.Int("cache_misses", misses),
			zap.Int("imported_artifacts", len(closure.importedArtifacts)),
			zap.Int("reachable", applied.reachable),
			zap.Int("unreachable", applied.unreachable),
			zap.Duration("duration", time.Since(projectStart)),
		)
	}

	logger.Info("jvmreach: completed reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("module_hierarchies", len(hierarchies)),
		zap.Int("cache_hits", cacheHits),
		zap.Int("cache_misses", cacheMisses),
		zap.Int("reachable", stats.Reachable),
		zap.Int("unreachable", stats.Unreachable),
		zap.Int("unknown", stats.Unknown),
		zap.Duration("duration", time.Since(overallStart)),
	)

	out := resultFromRequest(req)
	out.AnalyzerStats = map[string]model.ReachabilityStats{Name: stats}
	return out, nil
}

type moduleClosure struct {
	importedArtifacts map[string]int
	dynamicImports    bool
	incomplete        bool
	reason            string
}

func moduleHierarchyRoots(hierarchies []moduleHierarchy) []string {
	roots := make([]string, 0, len(hierarchies))
	for _, hierarchy := range hierarchies {
		roots = append(roots, hierarchy.Root)
	}
	return roots
}

func (a Analyzer) analyzeModuleHierarchy(
	ctx context.Context,
	runner Runner,
	cache *resultCache,
	hierarchy moduleHierarchy,
	logger *zap.Logger,
) (moduleClosure, int, int) {
	results := make(map[string]RunnerResult, len(hierarchy.Modules))
	failures := make(map[string]error)
	hits, misses := 0, 0
	for _, module := range hierarchy.Modules {
		result, hit, err := a.runWithCache(ctx, runner, cache, module.Dir, logger)
		if err != nil {
			failures[module.Dir] = err
			logger.Warn("jvmreach: module runner failed",
				zap.String("hierarchy_root", hierarchy.Root),
				zap.String("module", module.Dir),
				zap.Error(err))
			continue
		}
		if hit {
			hits++
		} else {
			misses++
		}
		results[module.Dir] = result
	}
	if len(hierarchy.Modules) == 1 {
		module := hierarchy.Modules[0]
		if err := failures[module.Dir]; err != nil {
			return moduleClosure{incomplete: true, reason: failureReason(err)}, hits, misses
		}
		result := results[module.Dir]
		return moduleClosure{
			importedArtifacts: artifactSeedDepths(result.ImportedArtifacts, 0),
			dynamicImports:    result.DynamicImportsDetected,
		}, hits, misses
	}

	modulesByDir := make(map[string]jvmModule, len(hierarchy.Modules))
	for _, module := range hierarchy.Modules {
		modulesByDir[module.Dir] = module
	}
	edges := make(map[string][]string)
	incoming := make(map[string]int)
	for _, module := range hierarchy.Modules {
		targets := make(map[string]struct{})
		for imported := range results[module.Dir].RawImports {
			target, ok := resolveInternalModule(imported, hierarchy.Modules)
			if !ok || target.Dir == module.Dir {
				continue
			}
			targets[target.Dir] = struct{}{}
		}
		for target := range targets {
			edges[module.Dir] = append(edges[module.Dir], target)
			incoming[target]++
		}
		sort.Strings(edges[module.Dir])
	}
	var roots []string
	for _, module := range hierarchy.Modules {
		if results[module.Dir].hasResult() && module.Application {
			roots = append(roots, module.Dir)
		}
	}
	if len(roots) == 0 {
		for _, module := range hierarchy.Modules {
			if incoming[module.Dir] == 0 && results[module.Dir].hasResult() {
				roots = append(roots, module.Dir)
			}
		}
	}
	if len(roots) == 0 {
		for _, module := range hierarchy.Modules {
			if results[module.Dir].hasResult() {
				roots = append(roots, module.Dir)
			}
		}
	}
	sort.Strings(roots)
	closure := moduleClosure{importedArtifacts: make(map[string]int)}
	depths := make(map[string]int)
	queue := append([]string(nil), roots...)
	for _, root := range roots {
		depths[root] = 0
	}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		depth := depths[dir]
		result := results[dir]
		closure.dynamicImports = closure.dynamicImports || result.DynamicImportsDetected
		for artifact := range result.ImportedArtifacts {
			setMinimumArtifactDepth(closure.importedArtifacts, artifact, depth)
		}
		for _, targetDir := range edges[dir] {
			target := modulesByDir[targetDir]
			if target.Coord != "" {
				setMinimumArtifactDepth(closure.importedArtifacts, target.Coord, depth+1)
			}
			if _, failed := failures[targetDir]; failed {
				closure.incomplete = true
				closure.reason = "module-closure-incomplete"
				continue
			}
			if old, seen := depths[targetDir]; seen && old <= depth+1 {
				continue
			}
			depths[targetDir] = depth + 1
			queue = append(queue, targetDir)
		}
	}
	return closure, hits, misses
}

func resolveInternalModule(imported string, modules []jvmModule) (jvmModule, bool) {
	var best jvmModule
	bestLength := -1
	for _, module := range modules {
		for _, prefix := range module.Prefixes {
			if imported != prefix && !strings.HasPrefix(imported, prefix+".") {
				continue
			}
			if len(prefix) > bestLength {
				best, bestLength = module, len(prefix)
			}
		}
	}
	return best, bestLength >= 0
}

func artifactSeedDepths(imports map[string]struct{}, depth int) map[string]int {
	seeds := make(map[string]int, len(imports))
	for imported := range imports {
		seeds[imported] = depth
	}
	return seeds
}

func setMinimumArtifactDepth(depths map[string]int, key string, depth int) {
	if old, ok := depths[key]; !ok || depth < old {
		depths[key] = depth
	}
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

func resultFromRequest(req model.AnalyzeRequest) model.AnalyzeResult {
	return model.AnalyzeResult{Registry: req.Registry, AnalyzerRuns: []string{Name}}
}

type applyOutcome struct{ reachable, unreachable, unknown int }

// applyRunnerResult annotates every JVM vulnerability whose owning
// package is attributable to projectRoot. A package is "reachable"
// iff its `groupId:artifactId` is in the transitive closure of the
// runner's imported-artifact set, expanded through Graph.Dependencies.
func applyRunnerResult(req model.AnalyzeRequest, projectRoot string, runRes RunnerResult, now time.Time) applyOutcome {
	return applyImportedArtifactSeeds(req, projectRoot, artifactSeedDepths(runRes.ImportedArtifacts, 0), runRes.DynamicImportsDetected, now)
}

func applyImportedArtifactSeeds(req model.AnalyzeRequest, projectRoot string, imports map[string]int, dynamicImports bool, now time.Time) applyOutcome {
	var outcome applyOutcome
	if req.Graph == nil {
		return outcome
	}
	timestamp := now.UTC().Format(time.RFC3339)
	hopsByID := computeReachablePackageHopsFromSeeds(req.Graph, imports)
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil || !isJVMPackage(pkg) {
			continue
		}
		if !packageBelongsToProjectRoot(pkg, projectRoot) {
			continue
		}
		vulns := vulnerabilitiesForDep(req, pkg)
		for i := range vulns {
			vuln := &vulns[i]
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
	return computeReachablePackageHopsFromSeeds(g, artifactSeedDepths(imports, 0))
}

func computeReachablePackageHopsFromSeeds(g *model.Graph, imports map[string]int) map[string]int {
	hops := make(map[string]int)
	if g == nil || len(imports) == 0 {
		return hops
	}
	queue := make([]string, 0)
	for _, pkg := range g.Nodes() {
		if pkg == nil || !isJVMPackage(pkg) {
			continue
		}
		if !isPackageImported(pkg, imports) {
			continue
		}
		if _, ok := hops[pkg.ID]; ok {
			continue
		}
		hops[pkg.ID] = importedArtifactDepth(pkg, imports)
		queue = append(queue, pkg.ID)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		current := hops[id]
		deps, err := g.DirectDependencies(id)
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

func importedArtifactDepth(pkg *model.Dependency, imports map[string]int) int {
	return imports[canonicalCoord(pkg.Org, baseArtifactName(pkg.Name))]
}

// isPackageImported reports whether pkg's Maven coordinate (built
// from Org / Name) appears in the runner's import set.
func isPackageImported(pkg *model.Dependency, imports map[string]int) bool {
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

func annotateProjectUnknown(req model.AnalyzeRequest, projectRoot, reason string, now time.Time) int {
	if req.Graph == nil {
		return 0
	}
	timestamp := now.UTC().Format(time.RFC3339)
	count := 0
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil || !isJVMPackage(pkg) {
			continue
		}
		if !packageBelongsToProjectRoot(pkg, projectRoot) {
			continue
		}
		vulns := vulnerabilitiesForDep(req, pkg)
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
	if req.Graph == nil {
		return
	}
	timestamp := now.UTC().Format(time.RFC3339)
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil || !isJVMPackage(pkg) {
			continue
		}
		vulns := vulnerabilitiesForDep(req, pkg)
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

func packageBelongsToProjectRoot(pkg *model.Dependency, projectRoot string) bool {
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
