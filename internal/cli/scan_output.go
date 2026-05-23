package cli

import (
	"sort"

	"github.com/bomly-dev/bomly-cli/internal/engine"
	diffengine "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func diffAuditOutput(audit *diffengine.Audit) *output.DiffAudit {
	if audit == nil {
		return nil
	}
	combined := append(append([]sdk.Finding{}, audit.Introduced...), audit.Persisted...)
	return &output.DiffAudit{
		Introduced:   output.FindingsFromScan(audit.Introduced),
		Resolved:     output.FindingsFromScan(audit.Resolved),
		Persisted:    output.FindingsFromScan(audit.Persisted),
		AuditSummary: output.SummaryFromFindings(combined),
	}
}

func reportOptionsFromPipelineResults(enabled bool, results ...engine.PipelineResult) output.ReportOptions {
	if !enabled {
		return output.ReportOptions{}
	}
	runsSeen := make(map[string]struct{})
	stats := make(map[string]sdk.ReachabilityStats)
	for _, result := range results {
		for _, run := range result.AnalyzerRuns {
			if run == "" {
				continue
			}
			runsSeen[run] = struct{}{}
		}
		for name, value := range result.AnalyzerStats {
			current := stats[name]
			current.Reachable += value.Reachable
			current.Unreachable += value.Unreachable
			current.Unknown += value.Unknown
			current.NotApplicable += value.NotApplicable
			stats[name] = current
		}
	}
	runs := make([]string, 0, len(runsSeen))
	for run := range runsSeen {
		runs = append(runs, run)
	}
	sort.Strings(runs)
	return output.ReportOptions{
		ReachabilityEnabled: true,
		AnalyzerRuns:        runs,
		AnalyzerStats:       stats,
	}
}

func explainPackageRef(pkg *sdk.Package) output.PackageRef {
	ref := output.PackageFromGraphPackage(pkg)
	if pkg == nil {
		return ref
	}
	if legacyID := pkg.StableID(); legacyID != "" {
		ref.ID = legacyID
	}
	return ref
}

func explainPathsWithStableIDs(paths []output.DependencyPath) []output.DependencyPath {
	out := make([]output.DependencyPath, len(paths))
	for i, path := range paths {
		out[i] = path
		out[i].Packages = make([]output.PackageRef, len(path.Packages))
		for j, ref := range path.Packages {
			out[i].Packages[j] = explainPackageRefFromOutput(ref)
		}
		if len(out[i].Packages) > 0 {
			out[i].IntroducedVia = out[i].Packages[0].ID
		}
		if path.CycleTo != "" {
			for _, ref := range out[i].Packages {
				if ref.Purl == path.CycleTo || ref.ID == path.CycleTo {
					out[i].CycleTo = ref.ID
					break
				}
			}
		}
	}
	return out
}

func explainPackageRefFromOutput(ref output.PackageRef) output.PackageRef {
	if ref.Name != "" && ref.Version != "" {
		ref.ID = ref.Name + "@" + ref.Version
	}
	return ref
}
