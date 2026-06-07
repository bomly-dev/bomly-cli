package jsreach

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
const Name = "jsreach"

// Analyzer is a Tier-3 (package-level) reachability analyzer for npm
// packages. It groups npm packages in the input graph by project root,
// runs the configured Runner once per project, and annotates each
// registry vulnerability on npm packages with a Reachability result.
//
// Tier-3 caveat: "unreachable" here means "the application source does
// not import this package, neither directly nor indirectly through app
// code". It does NOT mean "the vulnerability cannot be triggered".
// docs/REACHABILITY.md is the authoritative source on this distinction.
type Analyzer struct {
	// Runner is the underlying esbuild driver. Defaults to
	// NewRunner(Logger) when nil.
	Runner Runner
	Logger *zap.Logger
	// CacheDir overrides the default per-project result cache
	// location. Empty means "use the OS user cache directory under
	// bomly/analyzers/jsreach".
	CacheDir string
	// CacheTTL overrides the default 24h cache lifetime. Zero means
	// use the default.
	CacheTTL time.Duration
	// DisableCache turns off the on-disk result cache entirely.
	// Useful in CI smoke runs where freshness matters more than
	// speed.
	DisableCache bool
}

// Descriptor returns the registration metadata for the jsreach analyzer.
func (a Analyzer) Descriptor() model.AnalyzerDescriptor {
	return model.AnalyzerDescriptor{
		Name:                Name,
		SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:   []model.PackageManager{model.PackageManagerNPM, model.PackageManagerPNPM, model.PackageManagerYarn},
		SupportedLanguages:  []model.Language{model.LanguageJavaScript, model.LanguageTypeScript},
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
	if req.Graph == nil || req.Registry == nil {
		return false, nil
	}
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil || !isNPMPackage(pkg) {
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

// Analyze runs the configured Runner per discovered npm project root
// and writes Reachability onto every npm registry vulnerability in the
// graph. Errors degrade to Status=Unknown with a stable Reason — the
// engine relies on this to keep the pipeline running.
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
	hierarchies := discoverWorkspaceHierarchies(req)
	if len(hierarchies) == 0 {
		logger.Info("jsreach: no npm project roots discovered; marking all npm vulnerabilities as unknown")
		annotateAllUnknown(req, "no-project-root-discovered", time.Now())
		return resultFromRequest(req), nil
	}

	logger.Info("jsreach: starting reachability analysis",
		zap.String("runner", runner.Name()),
		zap.String("runner_version", runner.Version()),
		zap.Int("workspace_hierarchies", len(hierarchies)),
		zap.Bool("cache_enabled", !a.DisableCache),
	)
	logger.Debug("jsreach: discovered workspace hierarchies", zap.Strings("paths", workspaceHierarchyRoots(hierarchies)))

	cache := a.cache()
	stats := model.ReachabilityStats{}
	cacheHits, cacheMisses := 0, 0
	for _, hierarchy := range hierarchies {
		root := hierarchy.Root
		select {
		case <-ctx.Done():
			logger.Info("jsreach: context cancelled; skipping project",
				zap.String("project_root", root))
			annotateProjectUnknown(req, root, "cancelled", time.Now())
			continue
		default:
		}

		projectStart := time.Now()
		closure, hits, misses := a.analyzeWorkspaceHierarchy(ctx, runner, cache, hierarchy, logger)
		cacheHits += hits
		cacheMisses += misses
		var applied applyOutcome
		if closure.incomplete {
			added := annotateProjectUnknown(req, root, closure.reason, time.Now())
			applied.unknown += added
		} else {
			applied = applyImportedPackageSeeds(req, root, closure.importedPackages, closure.dynamicImports, time.Now())
		}
		stats.Reachable += applied.reachable
		stats.Unreachable += applied.unreachable
		stats.Unknown += applied.unknown
		logger.Info("jsreach: completed workspace hierarchy",
			zap.String("workspace_root", root),
			zap.String("runner", runner.Name()),
			zap.Int("members", len(hierarchy.Members)),
			zap.Int("cache_hits", hits),
			zap.Int("cache_misses", misses),
			zap.Int("imported_packages", len(closure.importedPackages)),
			zap.Int("reachable", applied.reachable),
			zap.Int("unreachable", applied.unreachable),
			zap.Int("unknown", applied.unknown),
			zap.Duration("duration", time.Since(projectStart)),
		)
	}

	logger.Info("jsreach: completed reachability analysis",
		zap.String("runner", runner.Name()),
		zap.Int("workspace_hierarchies", len(hierarchies)),
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

type workspaceClosure struct {
	importedPackages map[string]int
	dynamicImports   bool
	incomplete       bool
	reason           string
}

func workspaceHierarchyRoots(hierarchies []workspaceHierarchy) []string {
	roots := make([]string, 0, len(hierarchies))
	for _, hierarchy := range hierarchies {
		roots = append(roots, hierarchy.Root)
	}
	return roots
}

func (a Analyzer) analyzeWorkspaceHierarchy(
	ctx context.Context,
	runner Runner,
	cache *resultCache,
	hierarchy workspaceHierarchy,
	logger *zap.Logger,
) (workspaceClosure, int, int) {
	results := make(map[string]RunnerResult, len(hierarchy.Members))
	failures := make(map[string]error)
	hits, misses := 0, 0
	for _, member := range hierarchy.Members {
		result, hit, err := a.runWithCache(ctx, runner, cache, member.Dir, logger)
		if err != nil {
			failures[member.Dir] = err
			logger.Warn("jsreach: workspace member runner failed",
				zap.String("workspace_root", hierarchy.Root),
				zap.String("member", member.Dir),
				zap.Error(err))
			continue
		}
		if hit {
			hits++
		} else {
			misses++
		}
		results[member.Dir] = result
	}
	if len(hierarchy.Members) == 1 {
		member := hierarchy.Members[0]
		if err := failures[member.Dir]; err != nil {
			return workspaceClosure{incomplete: true, reason: failureReason(err)}, hits, misses
		}
		result := results[member.Dir]
		return workspaceClosure{
			importedPackages: packageSeedDepths(result.ImportedPackages, 0),
			dynamicImports:   result.DynamicImportsDetected,
		}, hits, misses
	}

	byName := make(map[string]workspaceMember, len(hierarchy.Members))
	for _, member := range hierarchy.Members {
		if member.Name != "" {
			byName[member.Name] = member
		}
	}
	edges := make(map[string][]string)
	incoming := make(map[string]int)
	for _, member := range hierarchy.Members {
		for imported := range results[member.Dir].ImportedPackages {
			target, ok := byName[imported]
			if !ok || target.Dir == member.Dir {
				continue
			}
			edges[member.Dir] = append(edges[member.Dir], target.Dir)
			incoming[target.Dir]++
		}
		sort.Strings(edges[member.Dir])
	}
	var roots []string
	if result, ok := results[hierarchy.Root]; ok && result.hasResult() {
		roots = append(roots, hierarchy.Root)
	} else {
		for _, member := range hierarchy.Members {
			if incoming[member.Dir] == 0 && results[member.Dir].hasResult() {
				roots = append(roots, member.Dir)
			}
		}
	}
	if len(roots) == 0 {
		for _, member := range hierarchy.Members {
			if results[member.Dir].hasResult() {
				roots = append(roots, member.Dir)
			}
		}
	}
	sort.Strings(roots)
	closure := workspaceClosure{importedPackages: make(map[string]int)}
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
		for imported := range result.ImportedPackages {
			if _, internal := byName[imported]; internal {
				continue
			}
			setMinimumDepth(closure.importedPackages, imported, depth)
		}
		for _, target := range edges[dir] {
			if _, failed := failures[target]; failed {
				closure.incomplete = true
				closure.reason = "workspace-closure-incomplete"
				continue
			}
			if old, seen := depths[target]; seen && old <= depth+1 {
				continue
			}
			depths[target] = depth + 1
			queue = append(queue, target)
		}
	}
	return closure, hits, misses
}

func packageSeedDepths(imports map[string]struct{}, depth int) map[string]int {
	seeds := make(map[string]int, len(imports))
	for imported := range imports {
		seeds[imported] = depth
	}
	return seeds
}

func setMinimumDepth(depths map[string]int, key string, depth int) {
	if old, ok := depths[key]; !ok || depth < old {
		depths[key] = depth
	}
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
			logger.Debug("jsreach: cache hit",
				zap.String("project_root", projectDir),
				zap.String("runner", runner.Name()),
				zap.Int("imported_packages", len(cached.ImportedPackages)))
			return cached, true, nil
		}
		logger.Debug("jsreach: cache miss",
			zap.String("project_root", projectDir),
			zap.String("runner", runner.Name()))
	}
	result, err := runner.Run(ctx, projectDir)
	if err != nil {
		return RunnerResult{}, false, err
	}
	if cache != nil {
		if err := cache.set(projectDir, runner.Name(), runner.Version(), result); err != nil {
			logger.Debug("jsreach: cache write failed (non-fatal)",
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

func resultFromRequest(req model.AnalyzeRequest) model.AnalyzeResult {
	return model.AnalyzeResult{Registry: req.Registry, AnalyzerRuns: []string{Name}}
}

// applyOutcome reports per-vuln Reachability outcomes for telemetry.
type applyOutcome struct {
	reachable, unreachable, unknown int
}

// applyRunnerResult annotates every npm vulnerability whose owning
// package is attributable to projectRoot. A package is "reachable" iff
// it is in the transitive closure of the runner's bare-specifier
// import set walked through the dep graph; otherwise it is marked
// Unreachable at TierPackage.
//
// The transitive closure is essential — esbuild stops at every bare
// specifier (PackagesExternal), so the runner's import set only
// captures packages directly imported from app source. A CVE in a
// transitive dep (e.g. body-parser pulled in by express) would be
// missed otherwise. The closure follows Graph.Dependencies edges, so
// it sees exactly the dep tree the npm detector resolved from the
// lockfile.
func applyRunnerResult(req model.AnalyzeRequest, projectRoot string, runRes RunnerResult, now time.Time) applyOutcome {
	return applyImportedPackageSeeds(req, projectRoot, packageSeedDepths(runRes.ImportedPackages, 0), runRes.DynamicImportsDetected, now)
}

func applyImportedPackageSeeds(req model.AnalyzeRequest, projectRoot string, imports map[string]int, dynamicImports bool, now time.Time) applyOutcome {
	var outcome applyOutcome
	if req.Graph == nil {
		return outcome
	}
	timestamp := now.UTC().Format(time.RFC3339)
	hopsByID := computeReachablePackageHopsFromSeeds(req.Graph, imports)
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		if !packageBelongsToProjectRoot(pkg, projectRoot) {
			continue
		}
		vulns := vulnerabilitiesForDep(req, pkg)
		for i := range vulns {
			vuln := &vulns[i]
			if vuln.Reachability != nil && vuln.Reachability.Analyzer == Name {
				continue // already annotated by an earlier project pass
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
// the shortest dep-graph distance from any directly-imported package.
// The seed set (hop 0) is every npm package whose name (or qualified
// scoped name) matches a bare specifier in imports; the expansion
// walks Graph.Dependencies edges breadth-first.
//
// The result is keyed by package ID rather than name because npm
// allows multiple versions of the same package to coexist (a top-
// level lodash@4 and a nested lodash@3 inside some dep), and the
// lockfile-derived graph captures that. Working in IDs keeps the
// attribution honest.
func computeReachablePackageHops(g *model.Graph, imports map[string]struct{}) map[string]int {
	return computeReachablePackageHopsFromSeeds(g, packageSeedDepths(imports, 0))
}

func computeReachablePackageHopsFromSeeds(g *model.Graph, imports map[string]int) map[string]int {
	hops := make(map[string]int)
	if g == nil || len(imports) == 0 {
		return hops
	}
	queue := make([]string, 0)
	// Seed: every npm package whose name matches the import set.
	for _, pkg := range g.Nodes() {
		if pkg == nil || !isNPMPackage(pkg) {
			continue
		}
		if !isPackageImported(pkg, imports) {
			continue
		}
		if _, ok := hops[pkg.ID]; ok {
			continue
		}
		hops[pkg.ID] = importedPackageDepth(pkg, imports)
		queue = append(queue, pkg.ID)
	}
	// BFS: every dep edge from a reachable package adds its target at
	// hop+1 if it has not been seen yet (shortest-distance wins).
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

func importedPackageDepth(pkg *model.Dependency, imports map[string]int) int {
	best := 0
	found := false
	for _, candidate := range []string{pkg.QualifiedName(), pkg.Name} {
		if depth, ok := imports[strings.TrimSpace(candidate)]; ok && (!found || depth < best) {
			best = depth
			found = true
		}
	}
	return best
}

// isPackageImported reports whether pkg's npm name (or qualified
// scoped name) appears in the runner's bare-specifier import set.
// Used as the seed predicate for the transitive walk.
func isPackageImported(pkg *model.Dependency, imports map[string]int) bool {
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

func annotateProjectUnknown(req model.AnalyzeRequest, projectRoot, reason string, now time.Time) int {
	if req.Graph == nil {
		return 0
	}
	timestamp := now.UTC().Format(time.RFC3339)
	count := 0
	for _, pkg := range req.Graph.Nodes() {
		if pkg == nil || !isNPMPackage(pkg) {
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
		if pkg == nil || !isNPMPackage(pkg) {
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

// packageBelongsToProjectRoot is a best-effort attribution. jsreach
// runs per-project, so any npm package physically located under
// projectRoot (or with no recorded location) is treated as belonging
// to it. In multi-project repos this may over-attribute; the second
// pass through applyRunnerResult skips already-annotated vulns to
// avoid double-counting.
func packageBelongsToProjectRoot(pkg *model.Dependency, projectRoot string) bool {
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
