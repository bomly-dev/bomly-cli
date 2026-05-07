package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/cli/opts"
	"github.com/bomly-dev/bomly-cli/internal/cli/resolve"
	"github.com/bomly-dev/bomly-cli/internal/git"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func resolveGitDiffGraphs(ctx context.Context, options *opts.Options, logger *zap.Logger, baseRef, headRef string, stderr io.Writer) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	repoRoot, repoCleanup, projectIdentifier, err := resolveDiffRepo(options, logger)
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

	baseTarget, err := resolveDiffResultsForRef(ctx, options, logger, repoRoot, baseRef, stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headTarget, err := resolveDiffResultsForRef(ctx, options, logger, repoRoot, headRef, stderr)
	if err != nil {
		_ = baseTarget.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}

	return baseTarget, headTarget, projectIdentifier, collectPipelineWarnings(baseTarget.Warnings, headTarget.Warnings), nil
}

func resolveDiffRepo(options *opts.Options, logger *zap.Logger) (string, func() error, string, error) {
	current := options.GetConfig()
	if current.URL != "" {
		repoRoot, err := git.CloneTemp(logger, current.URL, "")
		if err != nil {
			return "", nil, "", exit.InvalidInputError("clone --url %q: %v", current.URL, err)
		}
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

func resolveDiffResultsForRef(ctx context.Context, options *opts.Options, logger *zap.Logger, repoRoot, ref string, stderr io.Writer) (diffResolvedTarget, error) {
	materializedPath, err := git.MaterializeLocalRef(logger, repoRoot, ref)
	if err != nil {
		return diffResolvedTarget{}, exit.ResolutionFailureError(err)
	}
	cleanup := func() error {
		return os.RemoveAll(materializedPath)
	}
	executionTarget := sdk.ExecutionTarget{
		Kind:     sdk.ExecutionTargetGitRepository,
		Location: materializedPath,
		Ref:      ref,
	}
	commandCtx, err := options.PrepareForExecutionTarget(ctx, logger, executionTarget, cleanup)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	resolution, err := resolve.ResolveGraphs(commandCtx, logger, stderr)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: commandCtx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}

func resolveContainerDiffGraphs(ctx context.Context, options *opts.Options, logger *zap.Logger, baseRef, headRef string, stderr io.Writer) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	current := options.GetConfig()
	baseTarget, err := resolveContainerDiffTarget(current.Container, baseRef)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, exit.InvalidInputError("resolve --base %q: %v", baseRef, err)
	}
	headTarget, err := resolveContainerDiffTarget(current.Container, headRef)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, exit.InvalidInputError("resolve --head %q: %v", headRef, err)
	}

	baseResolved, err := resolveDiffResultsForExecutionTarget(ctx, options, logger, executionTargetForResolved(baseTarget), stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}
	headResolved, err := resolveDiffResultsForExecutionTarget(ctx, options, logger, executionTargetForResolved(headTarget), stderr)
	if err != nil {
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, err
	}

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

func resolveDiffResultsForExecutionTarget(ctx context.Context, options *opts.Options, logger *zap.Logger, executionTarget sdk.ExecutionTarget, stderr io.Writer) (diffResolvedTarget, error) {
	commandCtx, err := options.PrepareForExecutionTarget(ctx, logger, executionTarget, nil)
	if err != nil {
		return diffResolvedTarget{}, err
	}

	resolution, err := resolve.ResolveGraphs(commandCtx, logger, stderr)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: commandCtx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
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
	ctx context.Context,
	options *opts.Options,
	logger *zap.Logger,
	basePath, headPath string,
	stderr io.Writer,
) (diffResolvedTarget, diffResolvedTarget, string, []scan.PipelineWarning, error) {
	baseResolved, err := resolveDiffResultsForSBOMFile(ctx, options, logger, basePath, stderr)
	if err != nil {
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve base SBOM %q: %w", basePath, err)
	}
	headResolved, err := resolveDiffResultsForSBOMFile(ctx, options, logger, headPath, stderr)
	if err != nil {
		_ = baseResolved.close()
		return diffResolvedTarget{}, diffResolvedTarget{}, "", nil, fmt.Errorf("resolve head SBOM %q: %w", headPath, err)
	}
	label := fmt.Sprintf("%s vs %s", filepath.Base(basePath), filepath.Base(headPath))
	return baseResolved, headResolved, label, nil, nil
}

// resolveDiffResultsForSBOMFile builds one prepared runtime and graph resolution for an explicit SBOM file.
func resolveDiffResultsForSBOMFile(
	ctx context.Context,
	options *opts.Options,
	logger *zap.Logger,
	sbomPath string,
	stderr io.Writer,
) (diffResolvedTarget, error) {
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
	resolution, err := resolve.ResolveGraphs(commandCtx, logger, stderr)
	if err != nil {
		return diffResolvedTarget{}, err
	}
	return diffResolvedTarget{Context: commandCtx, Results: resolution.Results, Warnings: resolution.DetectorWarnings}, nil
}
