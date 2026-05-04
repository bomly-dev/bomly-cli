package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/selector"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// auditEnrichResult holds the outcome of running auditors against a dependency graph.
type auditEnrichResult struct {
	Findings []model.Finding
}

func enrichResolvedGraphs(
	ctx commandContext,
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
		if selector.Contains(result.MatcherRuns, eolCheckerName) {
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
		if selector.Contains(result.MatcherRuns, eolCheckerName) {
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
func deduplicateFindings(findings []model.Finding) []model.Finding {
	type key struct{ pkgID, vulnID string }
	type entry struct {
		idx  int
		rank int
	}
	best := make(map[key]entry, len(findings))
	out := make([]model.Finding, 0, len(findings))

	for _, f := range findings {
		if f.ID == "" || f.Kind != model.FindingKindVulnerability {
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
	req := model.AuditRequest{
		Mode:          model.TargetModeComponent,
		Graph:         g,
		Target:        target,
		Ecosystem:     model.Ecosystem(target.Ecosystem),
		AuditorFilter: defaultAuditorFilter(ctx.config.Auditors),
		Stderr:        stderr,
	}
	result, err := engine.Audit(context.Background(), req)
	if err != nil {
		logger.Warn("audit: one or more auditors reported errors", zap.Error(err))
	}
	return auditEnrichResult{Findings: deduplicateFindings(result.Findings)}
}

func diffAuditSummary(baseFindings, headFindings []model.Finding) *output.DiffAudit {
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
