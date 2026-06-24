package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	diffengine "github.com/bomly-dev/bomly-cli/internal/engine/diff"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/progress"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// newCommandProgress constructs a Progress sourcing its writer + TTY-detection
// from the CLI's commandStreams.
func newCommandProgress(streams commandStreams, label string) *progress.Progress {
	return progress.New(streams.notificationWriter(), streams.canRenderProgress(), label)
}

// warningProgressChildren converts pipeline warnings into ⚠ children using
// the warning source as Label and the message as Detail.
func warningProgressChildren(warnings []engine.PipelineWarning) []progress.Child {
	children := make([]progress.Child, 0, len(warnings))
	for _, w := range warnings {
		label := w.Source
		if label == "" {
			label = "unknown"
		}
		detail := strings.ReplaceAll(w.Message, "\n", " ")
		children = append(children, progress.Child{
			Icon:   progress.WarningMark,
			Label:  label,
			Detail: detail,
		})
	}
	return children
}

// subprojectProgressChildren returns one child per resolved subproject showing
// the relative path and ecosystem.
func subprojectProgressChildren(results []sdk.DetectionResult) []progress.Child {
	children := make([]progress.Child, 0, len(results))
	for _, r := range results {
		label := r.SubprojectInfo.RelativePath
		if label == "" || label == "." {
			label = progressTargetLabel(r.SubprojectInfo.ExecutionTarget)
			if label == "" || label == "." {
				label = "root"
			}
		}
		detail := string(r.SubprojectInfo.Ecosystem)
		if detail != "" {
			label += " (" + detail + ")"
		}
		children = append(children, progress.Child{Label: label})
	}
	return children
}

// plannedSubprojectChildren is the indexing-time variant of
// subprojectProgressChildren: it reads from the planned []sdk.Subproject so
// the "Indexed subprojects" step can be promoted right after Prepare returns,
// before the detection pipeline starts.
func plannedSubprojectChildren(subprojects []sdk.Subproject) []progress.Child {
	children := make([]progress.Child, 0, len(subprojects))
	for _, s := range subprojects {
		label := s.RelativePath
		if label == "" || label == "." {
			label = progressTargetLabel(s.ExecutionTarget)
			if label == "" || label == "." {
				label = "root"
			}
		}
		detail := string(s.Ecosystem)
		if detail == "" {
			detail = "unknown ecosystem"
		}
		children = append(children, progress.Child{Label: label, Detail: "[" + detail + "]"})
	}
	return children
}

// prepareCommandContextWithProgress runs the two pre-pipeline phases under
// dedicated progress steps:
//
//  1. Resolve execution target — clone repo, read SBOM file, or resolve a
//     container reference. Shown only when there's real work to do (skipped
//     for local filesystem targets where it's instant).
//  2. Index subprojects — registry build, plugin load, subproject planning.
//     Always shown, always completes (with the planned subproject tree)
//     before the detection pipeline begins.
//
// Both steps complete strictly in order so the user never sees indexing still
// spinning while detection has already started.
func prepareCommandContextWithProgress(ctx context.Context, options *opts.Options, prog *progress.Progress, logger *zap.Logger) (opts.Options, error) {
	if active, done, show := inputResolutionLabels(*options); show {
		inputStep := prog.StartWithDoneLabel("input", active, done)
		executionTarget, cleanup, err := options.ResolveExecutionTarget(logger)
		if err != nil {
			inputStep.Fail(active + " failed")
			return opts.Options{}, err
		}
		inputStep.Complete(done, nil)

		indexStep := prog.StartWithDoneLabel("indexing", "Indexing subprojects", "Indexed subprojects")
		commandCtx, err := options.PrepareForExecutionTarget(ctx, logger, executionTarget, cleanup)
		if err != nil {
			indexStep.Fail("Indexing subprojects failed")
			return opts.Options{}, err
		}
		indexStep.Complete("Indexed subprojects", plannedSubprojectChildren(commandCtx.Subprojects()))
		return commandCtx, nil
	}

	// Local filesystem path: no remote work to do. Open the indexing step
	// directly so the user still gets a live spinner for Prepare.
	indexStep := prog.StartWithDoneLabel("indexing", "Indexing subprojects", "Indexed subprojects")
	commandCtx, err := options.Prepare(ctx, logger)
	if err != nil {
		indexStep.Fail("Indexing subprojects failed")
		return opts.Options{}, err
	}
	indexStep.Complete("Indexed subprojects", plannedSubprojectChildren(commandCtx.Subprojects()))
	return commandCtx, nil
}

// combinedSubprojectChildren merges base+head subprojects into a single
// deduplicated child list. Used by diff progress to render one "Indexed
// subprojects" tree spanning both refs. Subprojects are deduplicated by
// relative path + ecosystem so identical sets across refs don't duplicate.
func combinedSubprojectChildren(base, head []sdk.Subproject) []progress.Child {
	seen := make(map[string]struct{})
	all := append(append([]sdk.Subproject(nil), base...), head...)
	deduped := make([]sdk.Subproject, 0, len(all))
	for _, s := range all {
		key := s.RelativePath + "|" + string(s.Ecosystem)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, s)
	}
	return plannedSubprojectChildren(deduped)
}

// inputResolutionLabels chooses the progress labels for the pre-indexing step
// based on what the resolved config asks us to fetch. Returns (active label,
// done label, true) when a step should be shown, or ("", "", false) when the
// target is local/instant and no step is needed.
func inputResolutionLabels(cfg opts.Options) (string, string, bool) {
	resolved := cfg.GetConfig()
	switch {
	case resolved.SBOM:
		return "Reading SBOM", "Read SBOM", true
	case resolved.URL != "":
		return "Cloning repository", "Cloned repository", true
	case resolved.Container != "":
		return "Resolving container reference", "Resolved container reference", true
	default:
		// Local filesystem — resolution is instant; skip the step.
		return "", "", false
	}
}

func progressTargetLabel(target sdk.ExecutionTarget) string {
	if label := gitProgressTargetLabel(target); label != "" {
		return label
	}
	switch target.Kind {
	case sdk.ExecutionTargetContainerImage:
		return strings.TrimSpace(target.Location)
	case sdk.ExecutionTargetFilesystem:
		location := strings.TrimSpace(target.Location)
		if location != "" {
			return filepath.Base(location)
		}
	}
	return filepath.Base(target.Location)
}

func gitProgressTargetLabel(target sdk.ExecutionTarget) string {
	ref := strings.TrimSpace(target.Ref)
	repo := strings.TrimSpace(target.RepositoryURL)
	if target.Kind != sdk.ExecutionTargetGitRepository && repo == "" && ref == "" {
		return ""
	}
	switch {
	case repo != "" && ref != "":
		return repo + " @ " + ref
	case ref != "":
		return ref
	case repo != "":
		return repo
	default:
		return ""
	}
}

// detectorProgressChildren groups results by detector name, sums the total
// package count per detector, and returns children with ✔ icon.
func detectorProgressChildren(results []sdk.DetectionResult) []progress.Child {
	type detectorInfo struct {
		name     string
		packages int
	}
	index := make(map[string]*detectorInfo)
	order := make([]string, 0)
	for _, r := range results {
		key := r.DetectorName
		info, exists := index[key]
		if !exists {
			info = &detectorInfo{name: r.DetectorName}
			index[key] = info
			order = append(order, key)
		}
		if r.Graphs != nil {
			for _, entry := range r.Graphs.Entries {
				if entry.Graph != nil {
					info.packages += entry.Graph.Size()
				}
			}
		}
	}
	children := make([]progress.Child, 0, len(order))
	for _, key := range order {
		info := index[key]
		children = append(children, progress.Child{
			Icon:   progress.CheckMark,
			Label:  humanizeDetectorName(info.name),
			Detail: fmt.Sprintf("[%d packages]", info.packages),
		})
	}
	return children
}

// auditProgressChildren groups findings by source and returns children with ✔ icon.
func auditProgressChildren(auditorRuns []string, auditorFindings map[string]int, warnings []engine.PipelineWarning) []progress.Child {
	children := make([]progress.Child, 0, len(auditorRuns)+len(warnings))
	for _, name := range auditorRuns {
		children = append(children, progress.Child{
			Icon:   progress.CheckMark,
			Label:  humanizeAuditorSource(name),
			Detail: fmt.Sprintf("[%d findings]", auditorFindings[name]),
		})
	}
	children = append(children, warningProgressChildren(warnings)...)
	return children
}

// analyzerProgressChildren returns ✔ children for each successful reachability
// analyzer run and ⚠ children for each warning.
func analyzerProgressChildren(analyzerRuns []string, analyzerStats map[string]sdk.ReachabilityStats, warnings []engine.PipelineWarning) []progress.Child {
	children := make([]progress.Child, 0, len(analyzerRuns)+len(warnings))
	for _, name := range analyzerRuns {
		children = append(children, progress.Child{
			Icon:   progress.CheckMark,
			Label:  humanizeAnalyzerSource(name),
			Detail: analyzerProgressDetail(analyzerStats[name]),
		})
	}
	children = append(children, warningProgressChildren(warnings)...)
	return children
}

func analyzerProgressDetail(stats sdk.ReachabilityStats) string {
	parts := make([]string, 0, 4)
	if stats.Reachable > 0 {
		parts = append(parts, fmt.Sprintf("%d reachable", stats.Reachable))
	}
	if stats.Unreachable > 0 {
		parts = append(parts, fmt.Sprintf("%d unreachable", stats.Unreachable))
	}
	if stats.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", stats.Unknown))
	}
	if stats.NotApplicable > 0 {
		parts = append(parts, fmt.Sprintf("%d not applicable", stats.NotApplicable))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// diffPolicyOutcomeProgressChild summarizes the diff findings that gate the
// run, using the same blocking semantics as `bomly diff --audit` (introduced
// plus persisted — see auditBlockingFindings).
func diffPolicyOutcomeProgressChild(audit *diffengine.Audit) progress.Child {
	if audit == nil {
		return progress.Child{
			Icon:   progress.CheckMark,
			Label:  "Policy Outcome",
			Detail: "[no audit delta]",
		}
	}
	blocking := auditBlockingFindings(audit)
	failing := output.FailingFindingCount(blocking)
	warnings := len(blocking) - failing
	child := progress.Child{
		Icon:  progress.CheckMark,
		Label: "Policy Outcome",
	}
	switch {
	case failing > 0:
		child.Icon = progress.CrossMark
		child.Detail = fmt.Sprintf("[%d failing, %d warnings]", failing, warnings)
	case warnings > 0:
		child.Icon = progress.WarningMark
		child.Detail = fmt.Sprintf("[passed, %d warnings]", warnings)
	default:
		child.Detail = "[passed, no findings]"
	}
	return child
}

// matchProgressChildren returns ✔ children for each successful matcher run
// and ⚠ children for each warning.
func matchProgressChildren(stats []sdk.MatcherStats, warnings []engine.PipelineWarning) []progress.Child {
	children := make([]progress.Child, 0, len(stats)+len(warnings))
	for _, stat := range stats {
		children = append(children, progress.Child{
			Icon:   progress.CheckMark,
			Label:  matcherStatsLabel(stat),
			Detail: matcherProgressDetail(stat),
		})
	}
	children = append(children, warningProgressChildren(warnings)...)
	return children
}

func matcherProgressDetail(stats sdk.MatcherStats) string {
	parts := make([]string, 0, 4)
	if stats.MatchedPackages > 0 {
		parts = append(parts, fmt.Sprintf("%d matched packages", stats.MatchedPackages))
	}
	if stats.UnmatchedPackages > 0 {
		parts = append(parts, fmt.Sprintf("%d unmatched packages", stats.UnmatchedPackages))
	}
	if stats.Licenses > 0 {
		parts = append(parts, fmt.Sprintf("%d licenses", stats.Licenses))
	}
	if stats.Vulnerabilities > 0 {
		parts = append(parts, fmt.Sprintf("%d vulnerabilities", stats.Vulnerabilities))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func matcherStatsLabel(stats sdk.MatcherStats) string {
	if strings.TrimSpace(stats.DisplayName) != "" {
		return strings.TrimSpace(stats.DisplayName)
	}
	if strings.TrimSpace(stats.Name) == "" {
		return ""
	}
	return titleWords(strings.ReplaceAll(strings.TrimSpace(stats.Name), "-", " "))
}

// humanizeDetectorName converts a detector name like "maven-detector" to "Maven Detector".
func humanizeDetectorName(name string) string {
	name = strings.TrimSuffix(name, "-detector")
	parts := strings.Split(name, "-")
	for i, part := range parts {
		if isAcronym(part) {
			parts[i] = strings.ToUpper(part)
		} else if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ") + " Detector"
}

func humanizeAnalyzerSource(name string) string {
	return titleWords(strings.ReplaceAll(strings.TrimSpace(name), "-", " "))
}

// humanizeAuditorSource converts an auditor source name to a display name.
func humanizeAuditorSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "Auditor"
	}
	if strings.Contains(strings.ToLower(source), "auditor") {
		return source
	}
	switch strings.ToLower(source) {
	case "vulnerability":
		return "Vulnerability Auditor"
	case "license":
		return "License Auditor"
	case "package":
		return "Package Auditor"
	case "grype":
		return "Grype Auditor"
	case "osv":
		return "OSV Auditor"
	default:
		if isAcronym(source) {
			return strings.ToUpper(source) + " Auditor"
		}
		label := titleWords(strings.ReplaceAll(source, "-", " "))
		if label != "" {
			return label + " Auditor"
		}
		return "Auditor"
	}
}

func isAcronym(s string) bool {
	switch strings.ToLower(s) {
	case "npm", "pnpm", "osv", "sbom", "uv":
		return true
	default:
		return false
	}
}

func titleWords(value string) string {
	parts := strings.Fields(value)
	for i, part := range parts {
		if isAcronym(part) {
			parts[i] = strings.ToUpper(part)
			continue
		}
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, " ")
}
