package opts

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/baseline"
	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/internal/git"
	"github.com/bomly-dev/bomly-cli/internal/output"
	"github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// Options encapsulates the context for executing a CLI command,
// including configuration, registry, execution target, filters, output format, and cleanup logic.
type Options struct {
	ResolvedConfig         config.Resolved
	registry               *engine.Registry
	executionTarget        sdk.ExecutionTarget
	subprojects            []sdk.Subproject
	detectorFilter         sdk.DetectorFilter
	auditorFilter          sdk.AuditorFilter
	matcherFilter          sdk.MatcherFilter
	analyzerFilter         sdk.AnalyzerFilter
	ecosystemFilter        sdk.EcosystemFilter
	httpProvider           *sdk.HTTPClientProvider
	Format                 output.Format
	outputPath             string
	verbose                bool
	cleanup                func() error
	findingPolicyResolvers []sdk.FindingPolicyResolver
	baselineEvaluation     *engine.BaselineEvaluation
}

type optionsKey struct{}

func NewOptions() *Options {
	return &Options{}
}

// ToContext returns a context that carries Bomly command options.
func ToContext(ctx context.Context, options *Options) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, optionsKey{}, options)
}

// FromContext returns the Bomly command context stored on ctx.
func FromContext(ctx context.Context) (*Options, bool) {
	if ctx == nil {
		return nil, false
	}
	options, ok := ctx.Value(optionsKey{}).(*Options)
	return options, ok && options != nil
}

func (o *Options) GetConfig() config.Resolved {
	if o == nil {
		cfg := config.Resolved{}
		config.ApplyDefaults(&cfg)
		return cfg
	}
	return o.ResolvedConfig
}

func (o *Options) SetConfig(cfg config.Resolved) {
	o.ResolvedConfig = cfg
}

// Registry returns the filtered scan registry prepared for command execution.
func (o *Options) Registry() *engine.Registry {
	return o.registry
}

// ExecutionTarget returns the target prepared for command execution.
func (o *Options) ExecutionTarget() sdk.ExecutionTarget {
	return o.executionTarget
}

// Subprojects returns the subprojects prepared for command execution.
func (o *Options) Subprojects() []sdk.Subproject {
	return append([]sdk.Subproject(nil), o.subprojects...)
}

// DetectorFilter returns the detector filter prepared for command execution.
func (o *Options) DetectorFilter() sdk.DetectorFilter {
	return o.detectorFilter
}

// AuditorFilter returns the auditor filter prepared for command execution.
func (o *Options) AuditorFilter() sdk.AuditorFilter {
	return o.auditorFilter
}

// MatcherFilter returns the matcher filter prepared for command execution.
func (o *Options) MatcherFilter() sdk.MatcherFilter {
	return o.matcherFilter
}

// AnalyzerFilter returns the analyzer filter prepared for command execution.
func (o *Options) AnalyzerFilter() sdk.AnalyzerFilter {
	return o.analyzerFilter
}

// PipelineRequest builds the scan pipeline request for this prepared command context.
func (o *Options) PipelineRequest(scope sdk.Scope, stderr io.Writer) engine.PipelineRequest {
	failOn, _ := sdk.ParseFailOnList(o.ResolvedConfig.FailOn)
	typosquatThreshold, _ := strconv.ParseFloat(strings.TrimSpace(o.ResolvedConfig.TyposquatThreshold), 64)
	return engine.PipelineRequest{
		ProjectPath:                o.executionTarget.Location,
		ExecutionTarget:            o.executionTarget,
		Subprojects:                o.Subprojects(),
		EnrichEnabled:              o.ResolvedConfig.Enrich,
		AuditEnabled:               o.ResolvedConfig.Audit,
		AnalyzeReachabilityEnabled: o.ResolvedConfig.Analyze,
		ScopeFilter:                scope,
		AuditorFilter:              o.auditorFilter,
		MatcherFilter:              o.matcherFilter,
		AnalyzerFilter:             o.analyzerFilter,
		DetectorFilter:             o.detectorFilter,
		FailOn:                     failOn,
		AllowVulnerabilityIDs:      append([]string(nil), o.ResolvedConfig.AllowVulnerabilityIDs...),
		AllowLicenses:              append([]string(nil), o.ResolvedConfig.AllowLicenses...),
		DenyLicenses:               append([]string(nil), o.ResolvedConfig.DenyLicenses...),
		LicenseExemptPackages:      append([]string(nil), o.ResolvedConfig.LicenseExemptPackages...),
		DenyPackages:               append([]string(nil), o.ResolvedConfig.DenyPackages...),
		DenyGroups:                 append([]string(nil), o.ResolvedConfig.DenyGroups...),
		ProtectedPackages:          append([]string(nil), o.ResolvedConfig.ProtectedPackages...),
		TyposquatThreshold:         typosquatThreshold,
		TyposquatMode:              strings.TrimSpace(o.ResolvedConfig.TyposquatMode),
		WarnOnly:                   o.ResolvedConfig.WarnOnly,
		FindingPolicyResolvers:     append([]sdk.FindingPolicyResolver(nil), o.findingPolicyResolvers...),
		BaselineEvaluation:         cloneBaselineEvaluation(o.baselineEvaluation),
		InstallFirst:               o.ResolvedConfig.InstallFirst,
		InstallArgs:                append([]string(nil), o.ResolvedConfig.InstallArgs...),
		Stderr:                     stderr,
		Verbose:                    o.Verbose(),
	}
}

// Verbose reports whether verbose command output is enabled.
func (o *Options) Verbose() bool {
	return o.verbose
}

func (o *Options) Bind(root *cobra.Command) error {
	return bindFlagOptions(root, &o.ResolvedConfig)
}

func (o *Options) ResolveConfig(cmd *cobra.Command) error {
	flagValues := o.ResolvedConfig
	resolved := o.ResolvedConfig
	config.ApplyDefaults(&resolved)

	configPaths, err := o.configLoadPaths()
	if err != nil {
		return err
	}
	for _, path := range configPaths {
		fileCfg, err := config.LoadFile(path)
		if err != nil {
			return exit.InvalidInputError("load config %q: %v", path, err)
		}
		if fileCfg == nil {
			continue
		}
		config.ApplyFileConfig(&resolved, *fileCfg)
		resolved.LoadedFiles = append(resolved.LoadedFiles, path)
	}

	config.ApplyEnvOverrides(&resolved)
	applyFlagOverrides(&resolved, flagValues, cmd)
	// MaxDepth carries a non-zero default, so config.Validate cannot tell an
	// explicit --max-depth from the default value. Gate the flag combination
	// here where flag explicitness is still observable.
	if flagChanged(cmd, "max-depth") && !resolved.Recursive {
		return exit.InvalidInputError("--max-depth requires --recursive")
	}
	if err := config.Validate(resolved); err != nil {
		return exit.InvalidInputError("%v", err)
	}
	o.ResolvedConfig = resolved
	return nil
}

func (o *Options) Prepare(ctx context.Context, logger *zap.Logger) (Options, error) {
	executionTarget, _, cleanup, err := o.resolveExecutionTarget(logger)
	if err != nil {
		return Options{}, err
	}
	return o.PrepareForExecutionTarget(ctx, logger, executionTarget, cleanup)
}

// ResolveExecutionTarget resolves where the scan should run: it clones a
// remote repository, materializes an SBOM file, or resolves a local path.
// The returned cleanup must be deferred by the caller. CLI commands call
// this directly when they want to surface a dedicated "Cloning repository"
// (or similar) progress step around just this phase, before calling
// PrepareForExecutionTarget for the subproject-indexing phase.
func (o *Options) ResolveExecutionTarget(logger *zap.Logger) (sdk.ExecutionTarget, func() error, error) {
	target, _, cleanup, err := o.resolveExecutionTarget(logger)
	return target, cleanup, err
}

func (o *Options) PrepareForExecutionTarget(ctx context.Context, logger *zap.Logger, executionTarget sdk.ExecutionTarget, cleanup func() error) (Options, error) {
	resolved := o.ResolvedConfig

	format, err := o.OutputFormat()
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, exit.InvalidInputError("parse format: %v", err)
	}

	if _, err := sdk.ParseFailOnList(resolved.FailOn); err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, exit.InvalidInputError("%v", err)
	}

	httpProvider, err := sdk.NewHTTPClientProvider(httpClientConfigFromResolved(resolved))
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, exit.InvalidInputError("configure HTTP client: %v", err)
	}

	registryConfigs := RegistryConfigsFromResolved(resolved)
	registryConfigs.HTTPClientProvider = httpProvider
	scanRegistry := engine.NewRegistry(registryConfigs, *logger)
	scanRegistry.Build()

	if err := o.registerInstalledPluginDescriptors(ctx, scanRegistry); err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, err
	}

	ecosystemFilter, err := resolveEcosystemFilter(resolved.Ecosystems)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, err
	}

	detectorFilter, err := resolveDetectorFilter(resolved.Detectors, scanRegistry)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, err
	}

	matcherFilter, err := resolveMatcherFilter(resolved.Matchers, scanRegistry)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, err
	}

	auditorFilter, err := ResolveAuditorFilter(resolved.Auditors, scanRegistry)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, err
	}

	analyzerFilter, err := ResolveAnalyzerFilter(resolved.Analyzers, scanRegistry)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, err
	}

	if len(resolved.InstallArgs) > 0 {
		selectedDetectors := selectedDetectorNames(detectorFilter, scanRegistry)
		if len(selectedDetectors) != 1 {
			if cleanup != nil {
				_ = cleanup()
			}
			return Options{}, exit.InvalidInputError("--install-arg requires exactly one selected detector, got %d (%s)", len(selectedDetectors), strings.Join(selectedDetectors, ", "))
		}
	}

	forcedPackageManager := sdk.PackageManagerUnknown
	if resolved.SBOM {
		forcedPackageManager = sdk.PackageManagerSBOM
	}

	filteredRegistry := scanRegistry.Filter(engine.RegistryFilter{
		DetectorFilter:  detectorFilter,
		AuditorFilter:   auditorFilter,
		MatcherFilter:   matcherFilter,
		AnalyzerFilter:  analyzerFilter,
		EcosystemFilter: ecosystemFilter,
	})

	subprojects, err := PlanSubprojects(filteredRegistry, Request{
		Registry:             scanRegistry,
		ExecutionTarget:      executionTarget,
		ForcedPackageManager: forcedPackageManager,
		DetectorFilter:       detectorFilter,
		EcosystemFilter:      ecosystemFilter,
		Recursive:            resolved.Recursive,
		MaxDepth:             resolved.MaxDepth,
		ExcludeGlobs:         append([]string(nil), resolved.ExcludePaths...),
		Logger:               logger,
	})
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, err
	}

	var baselineResult baseline.LoadResult
	if resolved.Audit {
		baselineResult, err = baseline.ResolversForTarget(resolved.Baseline, executionTarget, logger)
		if err != nil {
			if cleanup != nil {
				_ = cleanup()
			}
			return Options{}, exit.InvalidInputError("%v", err)
		}
	}

	return Options{
		registry:               filteredRegistry,
		executionTarget:        executionTarget,
		subprojects:            subprojects,
		detectorFilter:         detectorFilter,
		auditorFilter:          auditorFilter,
		matcherFilter:          matcherFilter,
		analyzerFilter:         analyzerFilter,
		ecosystemFilter:        ecosystemFilter,
		httpProvider:           httpProvider,
		ResolvedConfig:         resolved,
		Format:                 format,
		verbose:                resolved.Verbosity > 0,
		cleanup:                cleanup,
		findingPolicyResolvers: baselineResult.Resolvers,
		baselineEvaluation:     baselineEvaluationFromLoadResult(baselineResult),
	}, nil
}

func baselineEvaluationFromLoadResult(result baseline.LoadResult) *engine.BaselineEvaluation {
	if result.Path == "" {
		return nil
	}
	return &engine.BaselineEvaluation{
		Path:      result.Path,
		Entries:   result.Entries,
		Automatic: result.Automatic,
	}
}

func cloneBaselineEvaluation(evaluation *engine.BaselineEvaluation) *engine.BaselineEvaluation {
	if evaluation == nil {
		return nil
	}
	clone := *evaluation
	return &clone
}

func (o *Options) ResolveProjectPath() (string, error) {
	resolvedConfig := o.ResolvedConfig
	if resolvedConfig.Path != "" {
		absPath, err := system.Abs(resolvedConfig.Path)
		if err != nil {
			return "", exit.InvalidInputError("resolve path %q: %v", resolvedConfig.Path, err)
		}
		return absPath, nil
	}
	cwd, err := system.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	return cwd, nil
}

func (o *Options) OutputFormat() (output.Format, error) {
	cfg := o.ResolvedConfig
	if cfg.Interactive {
		return output.FormatText, nil
	}
	if strings.TrimSpace(cfg.Format) == "" {
		return output.FormatText, nil
	}
	return output.ParseFormat(strings.ToLower(strings.TrimSpace(cfg.Format)))
}

func (o *Options) PluginLaunchContext(ctx context.Context) context.Context {
	current := o.GetConfig()
	httpProvider := o.httpProvider
	if httpProvider == nil {
		httpProvider, _ = sdk.NewHTTPClientProvider(httpClientConfigFromResolved(current))
	}
	return plugin.WithLaunchOptions(ctx, plugin.LaunchOptions{
		ConfigPath:         current.Config,
		Verbosity:          current.Verbosity,
		HTTPProxy:          current.HTTPProxy,
		HTTPNoProxy:        current.HTTPNoProxy,
		HTTPProxyType:      current.HTTPProxyType,
		HTTPProxyHost:      current.HTTPProxyHost,
		HTTPProxyPort:      current.HTTPProxyPort,
		HTTPProxyUsername:  current.HTTPProxyUsername,
		HTTPProxyPassword:  current.HTTPProxyPassword,
		HTTPCACertFile:     current.HTTPCACertFile,
		HTTPClientProvider: httpProvider,
		PluginConfigs:      current.Plugins,
	})
}

func httpClientConfigFromResolved(current config.Resolved) sdk.HTTPClientConfig {
	return sdk.HTTPClientConfig{
		ProxyURL:      current.HTTPProxy,
		NoProxy:       current.HTTPNoProxy,
		ProxyType:     current.HTTPProxyType,
		ProxyHost:     current.HTTPProxyHost,
		ProxyPort:     current.HTTPProxyPort,
		ProxyUsername: current.HTTPProxyUsername,
		ProxyPassword: current.HTTPProxyPassword,
		CACertFile:    current.HTTPCACertFile,
	}
}

// ProjectDescriptor returns a descriptor for the main project being analyzed,
// summarizing its name, path, ecosystem, and package manager.
func (o *Options) ProjectDescriptor() output.ProjectDescriptor {
	ecosystem := sdk.EcosystemOther
	packageManager := sdk.PackageManagerMultiple
	if len(o.subprojects) == 1 {
		ecosystem = o.subprojects[0].Ecosystem
		packageManager = o.subprojects[0].PrimaryPackageManager()
	}
	location := displayTargetLocation(o.executionTarget)
	return output.ProjectDescriptor{
		Name:           displayTargetName(o.executionTarget),
		Path:           location,
		TargetType:     displayTargetType(o.executionTarget),
		TargetRef:      o.executionTarget.Ref,
		Ecosystem:      ecosystem,
		PackageManager: packageManager,
	}
}

// ProjectDescriptorForSubproject returns a descriptor for a given subproject,
// summarizing its name, path, ecosystem, and package manager.
// If the subproject's relative path is ".", it uses the main execution target's name instead.
func (o *Options) ProjectDescriptorForSubproject(subproject sdk.Subproject) output.ProjectDescriptor {
	name := filepath.Base(subproject.ExecutionTarget.Location)
	if subproject.RelativePath == "." {
		name = displayTargetName(o.executionTarget)
	}
	return output.ProjectDescriptor{
		Name:           name,
		Path:           displayTargetLocation(subproject.ExecutionTarget),
		TargetType:     displayTargetType(subproject.ExecutionTarget),
		TargetRef:      subproject.ExecutionTarget.Ref,
		Ecosystem:      subproject.Ecosystem,
		PackageManager: subproject.PrimaryPackageManager(),
	}
}

func displayTargetLocation(target sdk.ExecutionTarget) string {
	if target.Kind == sdk.ExecutionTargetGitRepository && strings.TrimSpace(target.RepositoryURL) != "" {
		return strings.TrimSpace(target.RepositoryURL)
	}
	return target.Location
}

func displayTargetName(target sdk.ExecutionTarget) string {
	location := displayTargetLocation(target)
	if strings.TrimSpace(location) == "" {
		return ""
	}
	if target.Kind == sdk.ExecutionTargetContainerImage {
		return location
	}
	// Git repositories and filesystem paths both name themselves after the
	// last path segment — the repo or directory name. The full URL stays
	// available as the descriptor's Path.
	trimmed := strings.TrimSuffix(strings.TrimRight(location, `/\`), ".git")
	if idx := strings.LastIndexAny(trimmed, `/\`); idx >= 0 && idx < len(trimmed)-1 {
		return trimmed[idx+1:]
	}
	return filepath.Base(trimmed)
}

func displayTargetType(target sdk.ExecutionTarget) string {
	switch target.Kind {
	case sdk.ExecutionTargetGitRepository:
		return "git repository"
	case sdk.ExecutionTargetContainerImage:
		return "container image"
	case sdk.ExecutionTargetFilesystem:
		return "filesystem"
	default:
		return string(target.Kind)
	}
}

// Writer returns an io.Writer for the command's output, which writes to
// the specified output path if provided, or to the given stdout otherwise.
func (o *Options) Writer(stdout io.Writer) (io.Writer, func() error, error) {
	if o.outputPath == "" {
		return stdout, func() error { return nil }, nil
	}
	file, err := os.Create(o.outputPath)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return file, file.Close, nil
}

// Close performs any necessary cleanup for the command options.
func (o *Options) Close() error {
	if o.cleanup == nil {
		return nil
	}
	return o.cleanup()
}

func (o *Options) configLoadPaths() ([]string, error) {
	paths := make([]string, 0, 3)

	homePath, err := config.UserConfigPath()
	if err != nil {
		return nil, err
	}
	if homePath != "" {
		paths = append(paths, homePath)
	}

	projectPath, err := o.projectConfigPathForLoading()
	if err != nil {
		return nil, err
	}
	if projectPath != "" && projectPath != homePath {
		paths = append(paths, projectPath)
	}

	if strings.TrimSpace(o.ResolvedConfig.Config) != "" {
		explicitPath, err := system.Abs(o.ResolvedConfig.Config)
		if err != nil {
			return nil, exit.InvalidInputError("resolve config path %q: %v", o.ResolvedConfig.Config, err)
		}
		if explicitPath != homePath && explicitPath != projectPath {
			paths = append(paths, explicitPath)
		}
	}

	return paths, nil
}

func (o *Options) projectConfigPathForLoading() (string, error) {
	if strings.TrimSpace(o.ResolvedConfig.URL) != "" || strings.TrimSpace(o.ResolvedConfig.Image) != "" {
		return "", nil
	}

	projectRoot := strings.TrimSpace(o.ResolvedConfig.Path)
	if projectRoot == "" {
		cwd, err := system.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve cwd for config discovery: %w", err)
		}
		projectRoot = cwd
	}

	absPath, err := system.Abs(projectRoot)
	if err != nil {
		return "", exit.InvalidInputError("resolve project config path %q: %v", projectRoot, err)
	}
	info, err := os.Stat(absPath)
	if err == nil && !info.IsDir() {
		absPath = filepath.Dir(absPath)
	}
	return filepath.Join(absPath, ".bomly", "config.yaml"), nil
}

func (o *Options) resolveExecutionTarget(logger *zap.Logger) (sdk.ExecutionTarget, string, func() error, error) {
	resolved := o.ResolvedConfig
	if resolved.SBOM {
		if resolved.Image != "" || resolved.URL != "" || resolved.Ref != "" {
			return sdk.ExecutionTarget{}, "", nil, exit.InvalidInputError("--sbom cannot be combined with --image, --url, or --ref")
		}
		sbomPath, err := system.ResolveExistingFile(resolved.Path)
		if err != nil {
			return sdk.ExecutionTarget{}, "", nil, exit.InvalidInputError("resolve --path for --sbom: %v", err)
		}
		return sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: sbomPath}, sbomPath, nil, nil
	}
	targetCount := 0
	if resolved.Path != "" {
		targetCount++
	}
	if resolved.URL != "" {
		targetCount++
	}
	if resolved.Image != "" {
		targetCount++
	}
	if targetCount > 1 {
		return sdk.ExecutionTarget{}, "", nil, exit.InvalidInputError("--path, --url, and --image cannot be used together")
	}
	if resolved.URL != "" {
		projectPath, err := git.CloneTemp(logger, resolved.URL, resolved.Ref)
		if err != nil {
			return sdk.ExecutionTarget{}, "", nil, exit.InvalidInputError("clone --url %q: %v", resolved.URL, err)
		}
		cleanup := func() error {
			return os.RemoveAll(projectPath)
		}
		return sdk.ExecutionTarget{
			Kind:          sdk.ExecutionTargetGitRepository,
			Location:      projectPath,
			RepositoryURL: resolved.URL,
			Ref:           resolved.Ref,
		}, projectPath, cleanup, nil
	}
	if resolved.Image != "" {
		if resolved.Ref != "" {
			return sdk.ExecutionTarget{}, "", nil, exit.InvalidInputError("--ref can only be used with --url")
		}
		return sdk.ExecutionTarget{
			Kind:     sdk.ExecutionTargetContainerImage,
			Location: strings.TrimSpace(resolved.Image),
		}, resolved.Image, nil, nil
	}
	projectPath, err := o.ResolveProjectPath()
	if err != nil {
		return sdk.ExecutionTarget{}, "", nil, err
	}
	return sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectPath}, projectPath, nil, nil
}

func (o *Options) registerInstalledPluginDescriptors(ctx context.Context, reg *engine.Registry) error {
	if reg == nil {
		return nil
	}
	launchCtx := o.PluginLaunchContext(ctx)
	return plugin.RegisterRuntimePlugins(launchCtx, reg, "")
}
