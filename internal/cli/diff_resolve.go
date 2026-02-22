package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/git"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func resolveGitDiffGraphs(options *globalOptions, logger *zap.Logger, baseRef, headRef string, stderr io.Writer) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	repoRoot, repoCleanup, projectIdentifier, err := resolveDiffRepo(options, logger)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	if repoCleanup != nil {
		defer func() { _ = repoCleanup() }()
	}
	if err := git.VerifyRef(repoRoot, baseRef); err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("verify --base %q: %v", baseRef, err)
	}
	if err := git.VerifyRef(repoRoot, headRef); err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("verify --head %q: %v", headRef, err)
	}

	baseTarget, err := resolveDiffResultsForRef(options, logger, repoRoot, baseRef, stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headTarget, err := resolveDiffResultsForRef(options, logger, repoRoot, headRef, stderr)
	if err != nil {
		_ = baseTarget.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}

	return baseTarget, headTarget, projectIdentifier, collectPipelineWarnings(baseTarget.Warnings, headTarget.Warnings), nil
}

func resolveDiffRepo(options *globalOptions, logger *zap.Logger) (string, func() error, string, error) {
	if options.URL != "" {
		repoRoot, err := git.CloneTemp(logger, options.URL, "")
		if err != nil {
			return "", nil, "", invalidInputf("clone --url %q: %v", options.URL, err)
		}
		return repoRoot, func() error { return os.RemoveAll(repoRoot) }, options.URL, nil
	}

	selectedPath, err := options.resolveProjectPath()
	if err != nil {
		return "", nil, "", err
	}
	repoRoot, err := git.FindRepoRoot(selectedPath)
	if err != nil {
		return "", nil, "", invalidInputf("resolve local git repository: %v", err)
	}
	return repoRoot, nil, repoRoot, nil
}

func resolveDiffResultsForRef(options *globalOptions, logger *zap.Logger, repoRoot, ref string, stderr io.Writer) (diffResolvedTarget, error) {
	materializedPath, err := git.MaterializeLocalRef(logger, repoRoot, ref)
	if err != nil {
		return diffResolvedTarget{}, resolutionFailure(err)
	}
	cleanup := func() error {
		return os.RemoveAll(materializedPath)
	}
	executionTarget := model.ExecutionTarget{
		Kind:     model.ExecutionTargetGitRepository,
		Location: materializedPath,
		Ref:      ref,
	}
	ctx, err := options.newCommandContextForExecutionTarget(logger, executionTarget, cleanup)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	resolution, err := resolveGraphs(ctx, logger, stderr)
	if err != nil {
		_ = ctx.close()
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: ctx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}

func resolveContainerDiffGraphs(options *globalOptions, logger *zap.Logger, baseRef, headRef string, stderr io.Writer) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	baseTarget, err := resolveContainerDiffTarget(options.Container, baseRef)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("resolve --base %q: %v", baseRef, err)
	}
	headTarget, err := resolveContainerDiffTarget(options.Container, headRef)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, invalidInputf("resolve --head %q: %v", headRef, err)
	}

	baseResolved, err := resolveDiffResultsForExecutionTarget(options, logger, executionTargetForResolved(baseTarget), stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headResolved, err := resolveDiffResultsForExecutionTarget(options, logger, executionTargetForResolved(headTarget), stderr)
	if err != nil {
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}

	return baseResolved, headResolved, options.Container, collectPipelineWarnings(baseResolved.Warnings, headResolved.Warnings), nil
}

// executionTargetForResolved returns a filesystem target when the resolved location
// is a local path, otherwise a container image target.
func executionTargetForResolved(location string) model.ExecutionTarget {
	if localPathExists(location) {
		return model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: location}
	}
	return model.ExecutionTarget{Kind: model.ExecutionTargetContainerImage, Location: location}
}

func resolveDiffResultsForExecutionTarget(options *globalOptions, logger *zap.Logger, executionTarget model.ExecutionTarget, stderr io.Writer) (diffResolvedTarget, error) {
	ctx, err := options.newCommandContextForExecutionTarget(logger, executionTarget, nil)
	if err != nil {
		return diffResolvedTarget{}, err
	}

	resolution, err := resolveGraphs(ctx, logger, stderr)
	if err != nil {
		_ = ctx.close()
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: ctx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}

func collectPipelineWarnings(groups ...[]scan.PipelineWarning) []scan.PipelineWarning {
	var all []scan.PipelineWarning
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
func resolveSBOMDiffGraphs(
	options *globalOptions,
	logger *zap.Logger,
	basePath, headPath string,
	stderr io.Writer,
) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	baseResolved, err := resolveDiffResultsForSBOMFile(options, logger, basePath, stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve base SBOM %q: %w", basePath, err)
	}
	headResolved, err := resolveDiffResultsForSBOMFile(options, logger, headPath, stderr)
	if err != nil {
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve head SBOM %q: %w", headPath, err)
	}
	label := fmt.Sprintf("%s vs %s", filepath.Base(basePath), filepath.Base(headPath))
	return baseResolved, headResolved, label, nil, nil
}

// resolveDiffResultsForSBOMFile builds one prepared runtime and graph resolution for an explicit SBOM file.
func resolveDiffResultsForSBOMFile(
	options *globalOptions,
	logger *zap.Logger,
	sbomPath string,
	stderr io.Writer,
) (diffResolvedTarget, error) {
	absPath, err := resolveExactFileTarget(sbomPath)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	executionTarget := model.ExecutionTarget{
		Kind:     model.ExecutionTargetFilesystem,
		Location: absPath,
	}
	ctx, err := options.newCommandContextForExecutionTarget(logger, executionTarget, nil)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	resolution, err := resolveGraphs(ctx, logger, stderr)
	if err != nil {
		_ = ctx.close()
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: ctx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}
