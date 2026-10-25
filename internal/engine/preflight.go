package engine

import (
	"fmt"
	"slices"
	"strings"

	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	"github.com/bomly-dev/bomly-sdk/plugin"
)

// Preflight evaluates the requirements a component descriptor declares
// (plugin.Requirements, the SDK's vocabulary) against what the host can vouch
// for at the stage the component runs in, before its Ready, Applicable or
// action method is called. It never reorders the fixed pipeline and never
// looks a provider up by name: a requirement names data, and the only
// question asked is whether that data exists at that point. A component that
// declares nothing is legacy and passes untouched. ADR-0051 records the rules.

// PipelineStage names one stage of the fixed pipeline.
type PipelineStage string

// The stages, in the order the pipeline runs them.
const (
	StageDetect  PipelineStage = "detect"
	StageMatch   PipelineStage = "match"
	StageAnalyze PipelineStage = "analyze"
	StageAudit   PipelineStage = "audit"
)

// stageKinds maps each stage to the component kind that runs in it.
var stageKinds = map[PipelineStage]plugin.PluginKind{
	StageDetect:  plugin.PluginKindDetector,
	StageMatch:   plugin.PluginKindMatcher,
	StageAnalyze: plugin.PluginKindAnalyzer,
	StageAudit:   plugin.PluginKindAuditor,
}

// hostRequirements is the vocabulary this host knows how to evaluate. A
// token outside it -- unknown to the SDK, or known to a newer SDK than this
// evaluator was written for -- is never available, so it always comes back
// unsatisfied.
var hostRequirements = []plugin.Requirement{
	plugin.RequirementSourceTree,
	plugin.RequirementDependencyGraph,
	plugin.RequirementVulnerabilityRecords,
}

// Evaluates reports whether this host can vouch for requirement at all. A
// token it cannot evaluate is never satisfied, whatever the target.
func Evaluates(requirement plugin.Requirement) bool {
	return slices.Contains(hostRequirements, requirement)
}

// PreflightIssue is one declared requirement the host cannot vouch for at
// the stage the component runs in.
type PreflightIssue struct {
	Kind        plugin.PluginKind
	Component   string
	Stage       PipelineStage
	Requirement plugin.Requirement
	// Explicit reports whether the user's selection is why the component is
	// in the plan; see selectedExplicitly.
	Explicit bool
	// Satisfy says what is missing and what would supply it.
	Satisfy string
}

// String renders the issue as one actionable sentence.
func (i PreflightIssue) String() string {
	return fmt.Sprintf("%s %s requires %s: %s", i.Kind, i.Component, i.Requirement, i.Satisfy)
}

// PreflightError reports explicitly selected components the plan can never
// run. It is returned before any stage starts.
type PreflightError struct {
	Issues []PreflightIssue
}

// Error lists every issue, so one run reports all of them.
func (e *PreflightError) Error() string {
	return "selected components cannot run: " + joinIssues(e.Issues)
}

func joinIssues(issues []PreflightIssue) string {
	reasons := make([]string, 0, len(issues))
	for _, issue := range issues {
		reasons = append(reasons, issue.String())
	}
	return strings.Join(reasons, "; ")
}

// preflightCandidate is one component a stage would run.
type preflightCandidate struct {
	kind     plugin.PluginKind
	name     string
	requires plugin.Requirements
	explicit bool
}

// preflightFacts is what the host knows about the run when it plans a
// stage.
type preflightFacts struct {
	stage PipelineStage
	// planning is set before any stage has run. Requirements that depend on
	// what an earlier stage produces are then taken as producible; the stage
	// checks them again against the data it actually receives.
	planning             bool
	target               targetShape
	matchStage           bool
	dependencyNodes      bool
	vulnerabilityRecords bool
}

// targetShape says whether the execution target is a source tree and, when
// it is not, what it is instead.
type targetShape struct {
	sourceTree  bool
	description string
}

// describeTarget classifies the request's target. A filesystem path or a Git
// checkout is a source tree unless discovery planned it as an SBOM document;
// a container image, and a target whose kind is not recorded, is not.
func describeTarget(req PipelineRequest) targetShape {
	for _, sub := range req.Subprojects {
		if sub.PrimaryPackageManager() == model.PackageManagerSBOM {
			return targetShape{description: "an SBOM document"}
		}
	}
	switch req.ExecutionTarget.Kind {
	case plugin.ExecutionTargetFilesystem, plugin.ExecutionTargetGitRepository:
		return targetShape{sourceTree: true}
	case plugin.ExecutionTargetContainerImage:
		return targetShape{description: "a container image"}
	default:
		return targetShape{description: "an input of unrecorded kind"}
	}
}

// available returns the requirements the host can vouch for under facts.
func (f preflightFacts) available() []plugin.Requirement {
	var out []plugin.Requirement
	if f.target.sourceTree {
		out = append(out, plugin.RequirementSourceTree)
	}
	// Detection is the stage that produces the graph.
	if f.stage != StageDetect && (f.planning || f.dependencyNodes) {
		out = append(out, plugin.RequirementDependencyGraph)
	}
	// Matchers supply vulnerability records, so they exist only for the
	// stages after matching. Which matcher supplies them is not asked: the
	// registry either carries a record or it does not.
	if (f.stage == StageAnalyze || f.stage == StageAudit) && (f.planning || f.vulnerabilityRecords) {
		out = append(out, plugin.RequirementVulnerabilityRecords)
	}
	return out
}

// issues returns one issue per requirement candidate declares that facts
// cannot vouch for.
func (f preflightFacts) issues(candidate preflightCandidate) []PreflightIssue {
	unmet := candidate.requires.Unsatisfied(f.available())
	if len(unmet) == 0 {
		return nil
	}
	issues := make([]PreflightIssue, 0, len(unmet))
	for _, requirement := range unmet {
		issues = append(issues, PreflightIssue{
			Kind:        candidate.kind,
			Component:   candidate.name,
			Stage:       f.stage,
			Requirement: requirement,
			Explicit:    candidate.explicit,
			Satisfy:     f.satisfy(requirement),
		})
	}
	return issues
}

// satisfy explains why requirement is unmet and what would meet it.
func (f preflightFacts) satisfy(requirement plugin.Requirement) string {
	if !Evaluates(requirement) {
		return "this version of Bomly does not know this requirement; upgrade Bomly, or use a component version that does not declare it"
	}
	switch requirement {
	case plugin.RequirementSourceTree:
		return fmt.Sprintf("the target is %s, not a source tree; scan a directory with --path or a Git repository with --url", f.target.description)
	case plugin.RequirementDependencyGraph:
		if f.stage == StageDetect {
			return "detection is the stage that produces the dependency graph, so a detector cannot require one"
		}
		return "detection found no dependencies in the target"
	default: // plugin.RequirementVulnerabilityRecords
		switch {
		case f.stage == StageDetect || f.stage == StageMatch:
			return "matchers supply vulnerability records, so only an analyzer or an auditor can require them"
		case !f.matchStage:
			return "no matcher ran; add --enrich so a vulnerability matcher can supply them"
		default:
			return "no package carries a vulnerability record after enrichment"
		}
	}
}

// plannedStages returns the stages req runs, in pipeline order.
func plannedStages(req PipelineRequest) []PipelineStage {
	stages := []PipelineStage{StageDetect}
	if req.EnrichEnabled || req.MatchEnabled {
		stages = append(stages, StageMatch)
	}
	if req.AnalyzeReachabilityEnabled {
		stages = append(stages, StageAnalyze)
	}
	if req.AuditEnabled {
		stages = append(stages, StageAudit)
	}
	return stages
}

// preflightPlan fails the run, before any stage starts, when an explicitly
// selected component declares a requirement the plan can never satisfy: a
// source tree the target is not, a token this host does not know, or data
// no earlier stage produces. A default-selected component is left to the
// stage, which skips it with a diagnostic.
func (p *Pipeline) preflightPlan(req PipelineRequest) error {
	target := describeTarget(req)
	var issues []PreflightIssue
	for _, stage := range plannedStages(req) {
		facts := preflightFacts{stage: stage, planning: true, target: target, matchStage: req.EnrichEnabled || req.MatchEnabled}
		for _, candidate := range p.stageCandidates(stage, req) {
			if candidate.explicit {
				issues = append(issues, facts.issues(candidate)...)
			}
		}
	}
	if len(issues) == 0 {
		return nil
	}
	for _, issue := range issues {
		p.Logger.Warn("pipeline: selected component cannot run",
			zap.String("kind", string(issue.Kind)),
			zap.String("component", issue.Component),
			zap.String("stage", string(issue.Stage)),
			zap.String("requirement", string(issue.Requirement)),
			zap.String("reason", issue.Satisfy))
	}
	return &PreflightError{Issues: issues}
}

// preflightStage evaluates the components stage would run against the data
// the stage actually receives. It returns the pipeline the stage runs on --
// p itself when nothing is held back, otherwise a view whose registry leaves
// the held-back components out -- and one issue per unmet requirement.
// Components that pass still go through Ready and Applicable as before.
func (p *Pipeline) preflightStage(stage PipelineStage, req PipelineRequest, graph *model.Graph, registry *model.PackageRegistry) (*Pipeline, []PreflightIssue) {
	facts := preflightFacts{
		stage:                stage,
		target:               describeTarget(req),
		matchStage:           req.EnrichEnabled || req.MatchEnabled,
		dependencyNodes:      hasDependencyNode(graph),
		vulnerabilityRecords: hasVulnerabilityRecord(registry),
	}
	candidates := p.stageCandidates(stage, req)
	var issues []PreflightIssue
	var skipped []string
	declared := 0
	for _, candidate := range candidates {
		if len(candidate.requires) > 0 {
			declared++
		}
		found := facts.issues(candidate)
		if len(found) == 0 {
			continue
		}
		issues = append(issues, found...)
		skipped = append(skipped, candidate.name)
		for _, issue := range found {
			p.Logger.Warn("pipeline: component skipped by preflight",
				zap.String("kind", string(issue.Kind)),
				zap.String("component", issue.Component),
				zap.String("stage", string(issue.Stage)),
				zap.String("requirement", string(issue.Requirement)),
				zap.Bool("explicit", issue.Explicit),
				zap.String("reason", issue.Satisfy))
		}
	}
	p.Logger.Debug("pipeline: preflight evaluated",
		zap.String("stage", string(stage)),
		zap.Int("components", len(candidates)),
		zap.Int("declaring_requirements", declared),
		zap.Strings("skipped", skipped))
	if len(skipped) == 0 {
		return p, nil
	}
	view := &Registry{Registry: p.Registry.Without(stageKinds[stage], skipped)}
	return &Pipeline{Registry: view, Logger: p.Logger, engine: NewEngine(view)}, issues
}

// stageCandidates lists the components stage would run for req, through the
// same registry selection the stage itself uses, so preflight sees exactly
// the plan the filters, defaults and detector chains produce.
func (p *Pipeline) stageCandidates(stage PipelineStage, req PipelineRequest) []preflightCandidate {
	reg := p.Registry
	kind := stageKinds[stage]
	var candidates []preflightCandidate
	add := func(name string, requires plugin.Requirements, include, exclude []string, includes func(string) bool) {
		explicit := selectedExplicitly(include, exclude, includes, name, reg.DefaultEnabled(kind, name))
		candidates = append(candidates, preflightCandidate{kind: kind, name: name, requires: requires, explicit: explicit})
	}
	switch stage {
	case StageDetect:
		filter := req.DetectorFilter
		seen := make(map[string]struct{})
		for _, sub := range req.Subprojects {
			planned := reg.PlannedDetectors(plugin.DetectionRequest{
				DetectorFilter: filter,
				Ecosystem:      sub.Ecosystem,
				PackageManager: sub.PrimaryPackageManager(),
			}, sub.PlannedDetectors)
			for _, detector := range planned {
				descriptor := detector.Descriptor()
				if _, ok := seen[descriptor.Name]; ok {
					continue
				}
				seen[descriptor.Name] = struct{}{}
				add(descriptor.Name, descriptor.Requires, filter.Include, filter.Exclude, filter.Includes)
			}
		}
	case StageMatch:
		filter := req.MatcherFilter
		for _, matcher := range reg.Matchers(plugin.MatchRequest{MatcherFilter: filter}) {
			descriptor := matcher.Descriptor()
			add(descriptor.Name, descriptor.Requires, filter.Include, filter.Exclude, filter.Includes)
		}
	case StageAnalyze:
		filter := req.AnalyzerFilter
		for _, analyzer := range reg.Analyzers(plugin.AnalyzeRequest{AnalyzerFilter: filter}) {
			descriptor := analyzer.Descriptor()
			add(descriptor.Name, descriptor.Requires, filter.Include, filter.Exclude, filter.Includes)
		}
	case StageAudit:
		filter := req.AuditorFilter
		for _, auditor := range reg.Auditors(plugin.AuditRequest{AuditorFilter: filter}) {
			descriptor := auditor.Descriptor()
			add(descriptor.Name, descriptor.Requires, filter.Include, filter.Exclude, filter.Includes)
		}
	}
	return candidates
}

// selectedExplicitly reports whether the user's selection is why a component
// is in the plan: it is named in a plain selector list, or it is off by
// default and a "+name" selector added it. The operator form resolves to an
// exclude-only filter, so a default-off component that survives one was
// added by name. A default-on component is implicit even when "+name"
// repeats it, because it would have run anyway.
func selectedExplicitly(include, exclude []string, includes func(string) bool, name string, defaultEnabled bool) bool {
	if len(include) > 0 {
		return includes(name)
	}
	return len(exclude) > 0 && !defaultEnabled
}

func hasDependencyNode(graph *model.Graph) bool {
	if graph == nil {
		return false
	}
	found := false
	graph.WalkNodes(func(node model.GraphNode) bool {
		_, found = node.(*model.DependencyNode)
		return !found
	})
	return found
}

func hasVulnerabilityRecord(registry *model.PackageRegistry) bool {
	if registry == nil {
		return false
	}
	for _, pkg := range registry.All() {
		if pkg != nil && len(pkg.Vulnerabilities) > 0 {
			return true
		}
	}
	return false
}

// preflightWarnings renders stage issues on the stage's warning channel, the
// one a default-verbosity run shows.
func preflightWarnings(issues []PreflightIssue) []PipelineWarning {
	if len(issues) == 0 {
		return nil
	}
	warnings := make([]PipelineWarning, 0, len(issues))
	for _, issue := range issues {
		warnings = append(warnings, PipelineWarning{Source: issue.Component, Message: preflightSkipMessage(issue)})
	}
	return warnings
}

// detectorPreflightWarnings renders detector issues as typed detector
// warnings. A held-back detector means its subproject was resolved by a
// later link of its chain or not at all, so the warning degrades coverage.
func detectorPreflightWarnings(issues []PreflightIssue) []plugin.DetectorWarning {
	if len(issues) == 0 {
		return nil
	}
	warnings := make([]plugin.DetectorWarning, 0, len(issues))
	for _, issue := range issues {
		warnings = append(warnings, plugin.DetectorWarning{
			Type:    plugin.DetectorWarningResolutionFailure,
			Source:  issue.Component,
			Message: preflightSkipMessage(issue),
		})
	}
	return warnings
}

func preflightSkipMessage(issue PreflightIssue) string {
	return fmt.Sprintf("skipped: requires %s; %s", issue.Requirement, issue.Satisfy)
}

// preflightSummary joins issues into one clause for an error that a held-back
// component may explain.
func preflightSummary(issues []PreflightIssue) string {
	return "preflight held back " + joinIssues(issues)
}
