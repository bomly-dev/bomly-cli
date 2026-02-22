package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bomly/bomly-cli/internal/explain"
	"github.com/bomly/bomly-cli/internal/model"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/scan"
	"github.com/bomly/bomly-cli/internal/viewmodel"
	"github.com/spf13/cobra"
)

type whyTreeNode struct {
	key            string
	label          string
	children       map[string]*whyTreeNode
	childOrder     []string
	annotations    []string
	annotationSeen map[string]struct{}
}

func newExplainCmd(options *globalOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "explain <package>",
		Short: "Explain why a dependency exists",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return invalidInputf("explain expects exactly one package argument")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			started := time.Now()
			current := options.current()
			logger := commandLogger(cmd, options, "explain")
			streams := newCommandStreams(cmd, current.Quiet, current.Verbosity)
			progress := newCommandProgress(streams, "Resolving dependencies")
			restoreStdout := streams.captureStdoutToDebugLog(logger)
			defer func() {
				if progress != nil {
					progress.Fail("Explain aborted")
				}
				restoreStdout()
			}()
			ctx, err := options.newCommandContext(logger)
			if err != nil {
				return err
			}
			defer func() { _ = ctx.close() }()
			if ctx.format == output.FormatSARIF && !ctx.config.Audit {
				return invalidInputf("--format sarif requires --audit")
			}
			resolution, err := resolveGraphs(ctx, logger, streams.notificationWriter())
			if err != nil {
				return err
			}
			resolved := resolution.Results
			subprojectChildren := subprojectProgressChildren(resolved)
			subprojectChildren = append(subprojectChildren, warningProgressChildren(resolution.DetectorWarnings)...)
			progress.CompleteStep("Indexed subprojects", subprojectChildren)
			progress.CompleteStep("Detected Dependencies", detectorProgressChildren(resolved))
			progress.Advance("Finding dependency paths")
			auditWarnings := make([]scan.PipelineWarning, 0)

			targets := make([]viewmodel.ExplainTargetResponse, 0, len(resolved))
			focusedResults := make([]scan.ResolveGraphResult, 0, len(resolved))
			allFindings := make([]scan.Finding, 0)
			anyVulnerabilityData := false
			for _, result := range resolved {
				depsGraph, graphErr := result.ConsolidatedGraph()
				if graphErr != nil {
					return resolutionFailure(graphErr)
				}
				if ctx.config.Enrich {
					depsGraph = enrichGraph(ctx, logger, depsGraph, result.SubprojectInfo, streams.notificationWriter())
				}
				if scan.GraphHasVulnerabilityData(depsGraph) {
					anyVulnerabilityData = true
				}
				dependency, paths, findErr := explain.FindWhy(depsGraph, args[0])
				if findErr != nil {
					if errors.Is(findErr, explain.ErrDependencyNotFound) {
						continue
					}
					return resolutionFailure(findErr)
				}
				findings := []scan.Finding(nil)
				if ctx.config.Audit {
					targetPkg, ok := depsGraph.Package(dependency.ID)
					if ok {
						findings = auditComponent(ctx, logger, depsGraph, targetPkg, streams.notificationWriter()).Findings
						allFindings = append(allFindings, findings...)
					}
				}
				targets = append(targets, viewmodel.ExplainTargetResponse{
					Project:      ctx.projectDescriptorForSubproject(result.SubprojectInfo),
					Detector:     result.DetectorName,
					Dependency:   dependency,
					Paths:        paths,
					Findings:     viewmodel.FindingsFromScan(findings),
					AuditSummary: viewmodel.SummaryFromFindings(findings),
				})
				focusedGraph, focusErr := explainGraphFromPaths(depsGraph, paths)
				if focusErr != nil {
					return resolutionFailure(focusErr)
				}
				focusedResults = append(focusedResults, scan.ResolveGraphResult{
					SubprojectInfo: result.SubprojectInfo,
					DetectorName:   result.DetectorName,
					DetectorType:   result.DetectorType,
					Graphs:         scan.SingleGraphContainer(focusedGraph, explainManifestMetadata(result)),
				})
			}
			if len(targets) == 0 {
				return resolutionFailure(fmt.Errorf("%w: %s", explain.ErrDependencyNotFound, args[0]))
			}
			if ctx.config.Audit && !anyVulnerabilityData {
				auditWarnings = append(auditWarnings, auditDataAvailabilityWarnings(nil)...)
			}
			if ctx.config.Audit {
				progress.CompleteStep("Evaluated policy", auditProgressChildren([]string{severityPolicyAuditorName}, map[string]int{severityPolicyAuditorName: len(allFindings)}, auditWarnings))
			}

			payload := viewmodel.BuildExplainResponse(ctx.projectDescriptor(), args[0], targets, started)
			if ctx.format == output.FormatSARIF {
				progress.Success("Resolved Graph")
				return output.WriteSARIF(streams.reportWriter(), allFindings, "bomly", cmd.Root().Version)
			}
			if ctx.config.Interactive {
				consolidated, err := scan.ConsolidateGraphs(focusedResults)
				if err != nil {
					return resolutionFailure(err)
				}
				graphValue, err := consolidated.Graphs.ConsolidatedGraph()
				if err != nil {
					return resolutionFailure(err)
				}
				progress.Success("Resolved Graph")
				return runInteractiveModel(cmd.InOrStdin(), streams.interactiveWriter(), newScanNavigatorModel("Bomly Interactive Explain", payload.Project, consolidated, graphValue, allFindings))
			}

			writer, closeWriter, err := ctx.writer(streams.reportWriter())
			if err != nil {
				return err
			}
			defer func() { _ = closeWriter() }()
			progress.Success("Resolved Graph")
			if ctx.format == output.FormatText {
				progress.SeparateReport()
			}

			err = output.Write(writer, ctx.format, payload, output.Renderers{
				Text: func(w io.Writer) error {
					for i, target := range payload.Targets {
						if i > 0 {
							if _, err := fmt.Fprintln(w); err != nil {
								return err
							}
						}
						if err := renderExplainTextReport(w, target); err != nil {
							return err
						}
					}
					return nil
				},
			})
			if err == nil && ctx.config.Audit && len(allFindings) > 0 {
				return policyViolationFindings(len(allFindings))
			}
			return err
		},
	}
	return cmd
}

func whyTreeLines(paths []explain.Path) []string {
	return whyTreeLinesForTarget(paths, "")
}

func whyTreeLinesForTarget(paths []explain.Path, targetID string) []string {
	root := &whyTreeNode{children: make(map[string]*whyTreeNode)}
	for _, path := range paths {
		current := root
		for _, node := range path.Packages {
			current = current.child(node)
		}
		current.addAnnotation(whyPathAnnotation(path))
	}

	lines := make([]string, 0)
	for _, id := range root.childOrder {
		lines = appendWhyTreeLines(lines, root.children[id], "", true, true, targetID)
	}
	return lines
}

func appendWhyTreeLines(lines []string, node *whyTreeNode, prefix string, isLast bool, root bool, targetID string) []string {
	line := node.label
	if targetID != "" && node.key == targetID {
		line = ansiStyled(line, ansiBold, ansiCyan) + " " + ansiStyled("[analyzed]", ansiDim)
	}
	if len(node.annotations) > 0 {
		line = fmt.Sprintf("%s (%s)", line, strings.Join(node.annotations, "; "))
	}
	if root {
		lines = append(lines, line)
	} else {
		connector := "|- "
		if isLast {
			connector = "\\- "
		}
		lines = append(lines, prefix+connector+line)
	}

	childPrefix := prefix
	if !root {
		if isLast {
			childPrefix += "   "
		} else {
			childPrefix += "|  "
		}
	}
	for i, key := range node.childOrder {
		child := node.children[key]
		lines = appendWhyTreeLines(lines, child, childPrefix, i == len(node.childOrder)-1, false, targetID)
	}
	return lines
}

func (n *whyTreeNode) child(ref output.PackageRef) *whyTreeNode {
	key := ref.ID
	if key == "" {
		key = explainPackageDisplayName(ref)
	}
	if child, ok := n.children[key]; ok {
		return child
	}
	child := &whyTreeNode{
		key:            key,
		label:          explainPackageDisplayName(ref),
		children:       make(map[string]*whyTreeNode),
		annotationSeen: make(map[string]struct{}),
	}
	n.children[key] = child
	n.childOrder = append(n.childOrder, key)
	return child
}

func (n *whyTreeNode) addAnnotation(annotation string) {
	if annotation == "" {
		return
	}
	if _, ok := n.annotationSeen[annotation]; ok {
		return
	}
	n.annotationSeen[annotation] = struct{}{}
	n.annotations = append(n.annotations, annotation)
}

func whyPathAnnotation(path explain.Path) string {
	parts := []string{path.Relationship}
	if path.Cyclic {
		parts = append(parts, "cycle to "+path.CycleTo)
	}
	return strings.Join(parts, ", ")
}

func explainPackageDisplayName(ref output.PackageRef) string {
	name := strings.TrimSpace(ref.Name)
	if name == "" {
		name = strings.TrimSpace(ref.ID)
	}
	if ref.Version != "" && !strings.HasSuffix(name, "@"+ref.Version) {
		name += "@" + ref.Version
	}
	if name == "" {
		return "-"
	}
	return name
}

func explainGraphFromPaths(source *model.Graph, paths []explain.Path) (*model.Graph, error) {
	focused := model.New()
	if source == nil {
		return focused, nil
	}
	for _, path := range paths {
		for i, ref := range path.Packages {
			pkg, ok := source.Package(ref.ID)
			if !ok || pkg == nil {
				continue
			}
			if _, exists := focused.Package(pkg.ID); !exists {
				if err := focused.AddPackage(pkg.Clone()); err != nil {
					return nil, err
				}
			}
			if i == 0 {
				continue
			}
			parentRef := path.Packages[i-1]
			parent, ok := source.Package(parentRef.ID)
			if !ok || parent == nil {
				continue
			}
			if _, exists := focused.Package(parent.ID); !exists {
				if err := focused.AddPackage(parent.Clone()); err != nil {
					return nil, err
				}
			}
			if err := focused.AddDependency(parent.ID, pkg.ID); err != nil && !errors.Is(err, model.ErrCycleDetected) {
				return nil, err
			}
		}
	}
	return focused, nil
}

func explainManifestMetadata(result scan.ResolveGraphResult) scan.ManifestMetadata {
	if result.Graphs != nil && len(result.Graphs.Entries) > 0 {
		return result.Graphs.Entries[0].Manifest
	}
	return scan.ManifestMetadata{
		Path: result.SubprojectInfo.ExecutionTarget.Location,
		Kind: result.SubprojectInfo.PackageManager.Name(),
	}
}

func renderExplainTextReport(w io.Writer, target viewmodel.ExplainTargetResponse) error {
	divider := ansiStyled(strings.Repeat("=", 72), ansiDim)
	section := ansiStyled(strings.Repeat("-", 72), ansiDim)

	if _, err := fmt.Fprintln(w, divider); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ansiStyled("Dependency Explanation", ansiBold, ansiCyan)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, section); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Component:", ansiDim), explainPackageDisplayName(target.Dependency)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Project:  ", ansiDim), valueOrDash(target.Project.Name)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Detector: ", ansiDim), valueOrDash(target.Detector)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s %d\n", ansiStyled("Path count:", ansiDim), len(target.Paths)); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, ansiStyled("Dependency Paths", ansiBold)); err != nil {
		return err
	}
	for _, line := range whyTreeLinesForTarget(target.Paths, target.Dependency.ID) {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}

	if len(target.Findings) > 0 || len(target.Dependency.Licenses) > 0 || len(target.Dependency.Vulnerabilities) > 0 {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, ansiStyled("Impact Assessment", ansiBold)); err != nil {
			return err
		}
	}

	if len(target.Dependency.Vulnerabilities) > 0 {
		if _, err := fmt.Fprintf(w, "%s %d matched\n", ansiStyled("Vulnerability enrichment:", ansiDim), len(target.Dependency.Vulnerabilities)); err != nil {
			return err
		}
		for _, vulnerability := range target.Dependency.Vulnerabilities {
			if _, err := fmt.Fprintf(w, "- %s %s (%s)\n", explainSeverityLabel(vulnerability.Severity), vulnerability.ID, valueOrDash(vulnerability.Source)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Title:   ", ansiDim), valueOrDash(vulnerability.Title)); err != nil {
				return err
			}
		}
	}

	if len(target.Findings) > 0 {
		if len(target.Dependency.Vulnerabilities) > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s %s\n", ansiStyled("Policy findings:", ansiDim), formatExplainAuditSummary(target.AuditSummary)); err != nil {
			return err
		}
		for _, finding := range target.Findings {
			if _, err := fmt.Fprintf(w, "- %s %s\n", explainSeverityLabel(finding.Severity), finding.ID); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Title:   ", ansiDim), valueOrDash(finding.Title)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Source:  ", ansiDim), valueOrDash(finding.Source)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s %s\n", ansiStyled("Package: ", ansiDim), explainPackageDisplayName(finding.Package)); err != nil {
				return err
			}
			if len(finding.Reasons) > 0 {
				if _, err := fmt.Fprintln(w, "  "+ansiStyled("Details: ", ansiDim)+finding.Reasons[0]); err != nil {
					return err
				}
				for _, reason := range finding.Reasons[1:] {
					if _, err := fmt.Fprintln(w, "           "+reason); err != nil {
						return err
					}
				}
			}
		}
	}

	if len(target.Dependency.Licenses) > 0 {
		if len(target.Findings) > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s %d detected\n", ansiStyled("Licenses:", ansiDim), len(target.Dependency.Licenses)); err != nil {
			return err
		}
		for idx, license := range target.Dependency.Licenses {
			label := license.Identifier()
			if license.Type != "" {
				label += " [" + license.Type + "]"
			}
			if _, err := fmt.Fprintf(w, "- License %d: %s\n", idx+1, valueOrDash(label)); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s applicable to %s\n", ansiStyled("Scope:   ", ansiDim), explainPackageDisplayName(target.Dependency)); err != nil {
				return err
			}
		}
	}

	if _, err := fmt.Fprintln(w, divider); err != nil {
		return err
	}
	return nil
}

func formatExplainAuditSummary(summary *viewmodel.AuditSummary) string {
	if summary == nil || summary.Total == 0 {
		return "no active findings"
	}
	parts := make([]string, 0, 4)
	if summary.Critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", summary.Critical))
	}
	if summary.High > 0 {
		parts = append(parts, fmt.Sprintf("%d high", summary.High))
	}
	if summary.Medium > 0 {
		parts = append(parts, fmt.Sprintf("%d medium", summary.Medium))
	}
	if summary.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d low", summary.Low))
	}
	if len(parts) == 0 && summary.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", summary.Unknown))
	}
	return fmt.Sprintf("%d total (%s)", summary.Total, strings.Join(parts, ", "))
}

func explainSeverityLabel(severity string) string {
	label := strings.ToUpper(valueOrDash(severity))
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return ansiStyled("["+label+"]", ansiRed, ansiBold)
	case "high":
		return ansiStyled("["+label+"]", ansiRed)
	case "medium":
		return ansiStyled("["+label+"]", ansiYellow, ansiBold)
	case "low":
		return ansiStyled("["+label+"]", ansiCyan)
	default:
		return ansiStyled("["+label+"]", ansiDim)
	}
}
