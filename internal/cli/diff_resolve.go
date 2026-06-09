package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/git"
	"github.com/bomly-dev/bomly-cli/internal/progress"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func resolveGitDiffGraphs(ctx context.Context, options *opts.Options, prog *progress.Progress, logger *zap.Logger, baseRef, headRef string) (diffResolvedTarget, diffResolvedTarget, string, []engine.PipelineWarning, error) {
	repoRoot, repoCleanup, projectIdentifier, err := resolveDiffRepo(options, prog, logger)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	if repoCleanup != nil {
		defer func() { _ = repoCleanup() }()
	}
	if err := git.VerifyRef(repoRoot, baseRef); err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, exit.InvalidInputError("verify --base %q: %v", baseRef, err)
	}
	if err := git.VerifyRef(repoRoot, headRef); err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, exit.InvalidInputError("verify --head %q: %v", headRef, err)
	}

	// Single indexing step covering both refs' Prepare phases.
	indexStep := prog.StartWithDoneLabel("indexing", "Indexing subprojects", "Indexed subprojects")

	baseTarget, err := resolveDiffResultsForRef(ctx, options, logger, repoRoot, baseRef)
	if err != nil {
		indexStep.Fail("Indexing subprojects failed")
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headTarget, err := resolveDiffResultsForRef(ctx, options, logger, repoRoot, headRef)
	if err != nil {
		indexStep.Fail("Indexing subprojects failed")
		_ = baseTarget.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}

	indexStep.Complete("Indexed subprojects", combinedSubprojectChildren(baseTarget.Context.Subprojects(), headTarget.Context.Subprojects()))

	return baseTarget, headTarget, projectIdentifier, collectPipelineWarnings(baseTarget.Warnings, headTarget.Warnings), nil
}

// resolveDiffRepo finds (or clones) the git repository to diff. When --url is
// set it surfaces a dedicated "Cloning repository" progress step around the
// clone; for local repos no step is needed (resolution is instant).
func resolveDiffRepo(options *opts.Options, prog *progress.Progress, logger *zap.Logger) (string, func() error, string, error) {
	current := options.GetConfig()
	if current.URL != "" {
		step := prog.StartWithDoneLabel("input", "Cloning repository", "Cloned repository")
		repoRoot, err := git.CloneTemp(logger, current.URL, "")
		if err != nil {
			step.Fail("Cloning repository failed")
			return "", nil, "", exit.InvalidInputError("clone --url %q: %v", current.URL, err)
		}
		step.Complete("Cloned repository", nil)
		return repoRoot, func() error { return os.RemoveAll(repoRoot) }, current.URL, nil
	}

	selectedPath, err := options.ResolveProjectPath()
	if err != nil {
		return "", nil, "", err
	}
	repoRoot, err := git.FindRepoRoot(selectedPath)
	if err != nil {
		return "", nil, "", exit.InvalidInputError("resolve local git repository: %v", err)
	}
	return repoRoot, nil, repoRoot, nil
}

func resolveDiffResultsForRef(ctx context.Context, options *opts.Options, logger *zap.Logger, repoRoot, ref string) (diffResolvedTarget, error) {
	materializedPath, err := git.MaterializeLocalRef(logger, repoRoot, ref)
	if err != nil {
		return diffResolvedTarget{}, exit.ResolutionFailureError(err)
	}
	cleanup := func() error {
		return os.RemoveAll(materializedPath)
	}
	executionTarget := sdk.ExecutionTarget{
		Kind:          sdk.ExecutionTargetGitRepository,
		Location:      materializedPath,
		RepositoryURL: strings.TrimSpace(options.GetConfig().URL),
		Ref:           ref,
	}
	commandCtx, err := options.PrepareForExecutionTarget(ctx, logger, executionTarget, cleanup)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: commandCtx}, nil
}

func resolveContainerDiffGraphs(ctx context.Context, options *opts.Options, prog *progress.Progress, logger *zap.Logger, baseRef, headRef string) (diffResolvedTarget, diffResolvedTarget, string, []engine.PipelineWarning, error) {
	current := options.GetConfig()
	refStep := prog.StartWithDoneLabel("input", "Resolving container references", "Resolved container references")
	baseTarget, err := resolveContainerDiffTarget(current.Container, baseRef)
	if err != nil {
		refStep.Fail("Resolving container references failed")
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, exit.InvalidInputError("resolve --base %q: %v", baseRef, err)
	}
	headTarget, err := resolveContainerDiffTarget(current.Container, headRef)
	if err != nil {
		refStep.Fail("Resolving container references failed")
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, exit.InvalidInputError("resolve --head %q: %v", headRef, err)
	}
	refStep.Complete("Resolved container references", nil)

	indexStep := prog.StartWithDoneLabel("indexing", "Indexing subprojects", "Indexed subprojects")
	baseResolved, err := resolveDiffResultsForExecutionTarget(ctx, options, logger, executionTargetForResolved(baseTarget))
	if err != nil {
		indexStep.Fail("Indexing subprojects failed")
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headResolved, err := resolveDiffResultsForExecutionTarget(ctx, options, logger, executionTargetForResolved(headTarget))
	if err != nil {
		indexStep.Fail("Indexing subprojects failed")
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	indexStep.Complete("Indexed subprojects", combinedSubprojectChildren(baseResolved.Context.Subprojects(), headResolved.Context.Subprojects()))

	return baseResolved, headResolved, current.Container, collectPipelineWarnings(baseResolved.Warnings, headResolved.Warnings), nil
}

// executionTargetForResolved returns a filesystem target when the resolved location
// is a local path, otherwise a container image target.
func executionTargetForResolved(location string) sdk.ExecutionTarget {
	if localPathExists(location) {
		return sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: location}
	}
	return sdk.ExecutionTarget{Kind: sdk.ExecutionTargetContainerImage, Location: location}
}

func resolveDiffResultsForExecutionTarget(ctx context.Context, options *opts.Options, logger *zap.Logger, executionTarget sdk.ExecutionTarget) (diffResolvedTarget, error) {
	commandCtx, err := options.PrepareForExecutionTarget(ctx, logger, executionTarget, nil)
	if err != nil {
		return diffResolvedTarget{}, err
	}

	return diffResolvedTarget{Context: commandCtx}, nil
}

func collectPipelineWarnings(groups ...[]engine.PipelineWarning) []engine.PipelineWarning {
	var all []engine.PipelineWarning
	for _, g := range groups {
		all = append(all, g...)
	}
	return all
}

func resolveContainerDiffTarget(container, selector string) (string, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return "", fmt.Errorf("image selector is empty")
	}
	if looksLikeContainerReference(selector) {
		return selector, nil
	}
	if localPathExists(selector) {
		absPath, absErr := system.Abs(selector)
		if absErr != nil {
			return "", absErr
		}
		return absPath, nil
	}
	container = strings.TrimSpace(container)
	if container == "" {
		return "", fmt.Errorf("--container is empty")
	}
	if strings.HasPrefix(selector, "sha256:") {
		return container + "@" + selector, nil
	}
	return container + ":" + selector, nil
}

func localPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func looksLikeContainerReference(value string) bool {
	switch {
	case strings.Contains(value, "@sha256:"):
		return true
	case strings.Contains(value, "/"):
		return true
	case strings.Count(value, ":") > 1:
		return true
	default:
		return false
	}
}

// resolveSBOMDiffGraphs resolves dependency graph results for two SBOM files
// and returns them along with a human-readable comparison label.
func resolveSBOMDiffGraphs(ctx context.Context, options *opts.Options, prog *progress.Progress, logger *zap.Logger, basePath, headPath string) (diffResolvedTarget, diffResolvedTarget, string, []engine.PipelineWarning, error) {
	// For SBOM diff, reading the SBOM and "indexing" are the same operation —
	// the SBOM file is itself the subproject. Use a single combined step.
	step := prog.StartWithDoneLabel("indexing", "Reading SBOM files", "Read SBOM files")
	baseResolved, err := resolveDiffResultsForSBOMFile(ctx, options, logger, basePath)
	if err != nil {
		step.Fail("Reading SBOM files failed")
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve base SBOM %q: %w", basePath, err)
	}
	headResolved, err := resolveDiffResultsForSBOMFile(ctx, options, logger, headPath)
	if err != nil {
		step.Fail("Reading SBOM files failed")
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve head SBOM %q: %w", headPath, err)
	}
	step.Complete("Read SBOM files", combinedSubprojectChildren(baseResolved.Context.Subprojects(), headResolved.Context.Subprojects()))

	label := fmt.Sprintf("%s vs %s", filepath.Base(basePath), filepath.Base(headPath))
	return baseResolved, headResolved, label, nil, nil
}

// resolveDiffResultsForSBOMFile builds one prepared runtime and graph resolution for an explicit SBOM file.
func resolveDiffResultsForSBOMFile(ctx context.Context, options *opts.Options, logger *zap.Logger, sbomPath string) (diffResolvedTarget, error) {
	absPath, err := system.ResolveExistingFile(sbomPath)
	if err != nil {
		return diffResolvedTarget{}, exit.InvalidInputError("resolve SBOM file %q: %v", sbomPath, err)
	}
	executionTarget := sdk.ExecutionTarget{
		Kind:     sdk.ExecutionTargetFilesystem,
		Location: absPath,
	}
	commandCtx, err := options.PrepareForExecutionTarget(ctx, logger, executionTarget, nil)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: commandCtx}, nil
}
