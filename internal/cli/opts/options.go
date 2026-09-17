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
	"github.com/bomly-dev/bomly-sdk/system"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/httpkit"
	"github.com/bomly-dev/bomly-sdk/model"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Options encapsulates the context for executing a CLI command,
// including configuration, registry, execution target, filters, output format, and cleanup logic.
type Options struct {
	ResolvedConfig         config.Resolved
	registry               *engine.Registry
	executionTarget        sdkplugin.ExecutionTarget
	subprojects            []sdkplugin.Subproject
	detectorFilter         sdkplugin.DetectorFilter
	auditorFilter          sdkplugin.AuditorFilter
	matcherFilter          sdkplugin.MatcherFilter
	analyzerFilter         sdkplugin.AnalyzerFilter
	ecosystemFilter        model.EcosystemFilter
	httpProvider           *httpkit.ClientProvider
	Format                 output.Format
	outputPath             string
	verbose                bool
	cleanup                func() error
	findingPolicyResolvers []model.FindingPolicyResolver
	baselineEvaluation     *engine.BaselineEvaluation
	pluginPool             *plugin.ClientPool
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
func (o *Options) ExecutionTarget() sdkplugin.ExecutionTarget {
	return o.executionTarget
}

// Subprojects returns the subprojects prepared for command execution.
func (o *Options) Subprojects() []sdkplugin.Subproject {
	return append([]sdkplugin.Subproject(nil), o.subprojects...)
}

// DetectorFilter returns the detector filter prepared for command execution.
func (o *Options) DetectorFilter() sdkplugin.DetectorFilter {
	return o.detectorFilter
}

// AuditorFilter returns the auditor filter prepared for command execution.
func (o *Options) AuditorFilter() sdkplugin.AuditorFilter {
	return o.auditorFilter
}

// MatcherFilter returns the matcher filter prepared for command execution.
func (o *Options) MatcherFilter() sdkplugin.MatcherFilter {
	return o.matcherFilter
}

// AnalyzerFilter returns the analyzer filter prepared for command execution.
func (o *Options) AnalyzerFilter() sdkplugin.AnalyzerFilter {
	return o.analyzerFilter
}

// PipelineRequest builds the scan pipeline request for this prepared command context.
func (o *Options) PipelineRequest(scope model.Scope, stderr io.Writer) engine.PipelineRequest {
	failOn, _ := model.ParseFailOnList(o.ResolvedConfig.FailOn)
	typosquatThreshold, _ := strconv.ParseFloat(strings.TrimSpace(o.ResolvedConfig.TyposquatThreshold), 64)
	if !o.Verbose() {
		stderr = nil
	}
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
		FindingPolicyResolvers:     append([]model.FindingPolicyResolver(nil), o.findingPolicyResolvers...),
		BaselineEvaluation:         cloneBaselineEvaluation(o.baselineEvaluation),
		InstallFirst:               o.ResolvedConfig.InstallFirst,
		InstallArgs:                append([]string(nil), o.ResolvedConfig.InstallArgs...),
		Stderr:                     stderr,
		Verbose:                    o.Verbose(),
	}
}

// Verbose reports whether debug-level subprocess output is enabled.
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

	envValues := config.Resolved{}
	config.ApplyEnvOverrides(&envValues)
	explicitConfig := envValues.Config
	if flagChanged(cmd, "config") {
		explicitConfig = flagValues.Config
	}

	configPaths, err := o.configLoadPaths(explicitConfig)
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
	executionTarget, _, cleanup, err := o.resolveExecutionTarget(ctx, logger)
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
func (o *Options) ResolveExecutionTarget(ctx context.Context, logger *zap.Logger) (sdkplugin.ExecutionTarget, func() error, error) {
	target, _, cleanup, err := o.resolveExecutionTarget(ctx, logger)
	return target, cleanup, err
}

func (o *Options) PrepareForExecutionTarget(ctx context.Context, logger *zap.Logger, executionTarget sdkplugin.ExecutionTarget, cleanup func() error) (Options, error) {
	resolved := o.ResolvedConfig

	format, err := o.OutputFormat()
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, exit.InvalidInputError("parse format: %v", err)
	}

	if _, err := model.ParseFailOnList(resolved.FailOn); err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return Options{}, exit.InvalidInputError("%v", err)
	}
	httpProvider, err := httpkit.NewClientProvider(httpClientConfigFromResolved(resolved))
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

	forcedPackageManager := model.PackageManagerUnknown
	if resolved.SBOM {
		forcedPackageManager = model.PackageManagerSBOM
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

	// The plugin subprocess pool joins the command cleanup chain alongside
	// temp-dir cleanup (e.g. git clone dirs): Close() shuts down any pooled
	// plugin subprocesses started while the command ran.
	pool := o.pluginPool
	cleanupWithPool := func() error {
		if pool != nil {
			pool.Shutdown()
		}
		if cleanup != nil {
			return cleanup()
		}
		return nil
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
		verbose:                resolved.Verbosity >= 2,
		cleanup:                cleanupWithPool,
		findingPolicyResolvers: baselineResult.Resolvers,
		baselineEvaluation:     baselineEvaluationFromLoadResult(baselineResult),
		pluginPool:             pool,
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

// DetachPluginPool clears the memoized plugin subprocess pool so this Options
// value lazily creates its own on first use. Long-lived servers that clone a
// base Options per request must call this on the clone: pooled subprocesses
// are bound to the launching request's context, so a pool shared across
// requests would have its processes killed by request cancellation and its
// single-restart allowance exhausted by subsequent requests.
func (o *Options) DetachPluginPool() {
	o.pluginPool = nil
}

func (o *Options) PluginLaunchContext(ctx context.Context) context.Context {
	current := o.GetConfig()
	httpProvider := o.httpProvider
	if httpProvider == nil {
		httpProvider, _ = httpkit.NewClientProvider(httpClientConfigFromResolved(current))
	}
	if o.pluginPool == nil {
		o.pluginPool = plugin.NewClientPool()
	}
	return plugin.WithLaunchOptions(ctx, plugin.LaunchOptions{
		Pool:               o.pluginPool,
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

func httpClientConfigFromResolved(current config.Resolved) httpkit.ClientConfig {
	return httpkit.ClientConfig{
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
	ecosystem := model.EcosystemOther
	packageManager := model.PackageManagerMultiple
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
func (o *Options) ProjectDescriptorForSubproject(subproject sdkplugin.Subproject) output.ProjectDescriptor {
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

func displayTargetLocation(target sdkplugin.ExecutionTarget) string {
	if target.Kind == sdkplugin.ExecutionTargetGitRepository && strings.TrimSpace(target.RepositoryURL) != "" {
		return strings.TrimSpace(target.RepositoryURL)
	}
	return target.Location
}

func displayTargetName(target sdkplugin.ExecutionTarget) string {
	location := displayTargetLocation(target)
	if strings.TrimSpace(location) == "" {
		return ""
	}
	if target.Kind == sdkplugin.ExecutionTargetContainerImage {
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

func displayTargetType(target sdkplugin.ExecutionTarget) string {
	switch target.Kind {
	case sdkplugin.ExecutionTargetGitRepository:
		return "git repository"
	case sdkplugin.ExecutionTargetContainerImage:
		return "container image"
	case sdkplugin.ExecutionTargetFilesystem:
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

func (o *Options) configLoadPaths(explicitConfig string) ([]string, error) {
	paths := make([]string, 0, 2)

	homePath, err := config.UserConfigPath()
	if err != nil {
		return nil, err
	}
	if homePath != "" {
		paths = append(paths, homePath)
	}

	if strings.TrimSpace(explicitConfig) != "" {
		explicitPath, err := system.Abs(explicitConfig)
		if err != nil {
			return nil, exit.InvalidInputError("resolve config path %q: %v", explicitConfig, err)
		}
		info, err := os.Stat(explicitPath)
		if err != nil {
			return nil, exit.InvalidInputError("resolve config path %q: %v", explicitConfig, err)
		}
		if !info.Mode().IsRegular() {
			return nil, exit.InvalidInputError("config path %q must be a regular file", explicitConfig)
		}
		if explicitPath != homePath {
			paths = append(paths, explicitPath)
		}
	}

	return paths, nil
}

func (o *Options) resolveExecutionTarget(ctx context.Context, logger *zap.Logger) (sdkplugin.ExecutionTarget, string, func() error, error) {
	resolved := o.ResolvedConfig
	if resolved.SBOM {
		if resolved.Image != "" || resolved.URL != "" || resolved.Ref != "" {
			return sdkplugin.ExecutionTarget{}, "", nil, exit.InvalidInputError("--sbom cannot be combined with --image, --url, or --ref")
		}
		sbomPath, err := system.ResolveExistingFile(resolved.Path)
		if err != nil {
			return sdkplugin.ExecutionTarget{}, "", nil, exit.InvalidInputError("resolve --path for --sbom: %v", err)
		}
		return sdkplugin.ExecutionTarget{Kind: sdkplugin.ExecutionTargetFilesystem, Location: sbomPath}, sbomPath, nil, nil
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
		return sdkplugin.ExecutionTarget{}, "", nil, exit.InvalidInputError("--path, --url, and --image cannot be used together")
	}
	if resolved.URL != "" {
		projectPath, err := git.CloneTemp(ctx, logger, resolved.URL, resolved.Ref)
		if err != nil {
			return sdkplugin.ExecutionTarget{}, "", nil, exit.InvalidInputError("clone --url %q: %v", resolved.URL, err)
		}
		cleanup := func() error {
			return os.RemoveAll(projectPath)
		}
		return sdkplugin.ExecutionTarget{
			Kind:          sdkplugin.ExecutionTargetGitRepository,
			Location:      projectPath,
			RepositoryURL: resolved.URL,
			Ref:           resolved.Ref,
		}, projectPath, cleanup, nil
	}
	if resolved.Image != "" {
		if resolved.Ref != "" {
			return sdkplugin.ExecutionTarget{}, "", nil, exit.InvalidInputError("--ref can only be used with --url")
		}
		return sdkplugin.ExecutionTarget{
			Kind:     sdkplugin.ExecutionTargetContainerImage,
			Location: strings.TrimSpace(resolved.Image),
		}, resolved.Image, nil, nil
	}
	projectPath, err := o.ResolveProjectPath()
	if err != nil {
		return sdkplugin.ExecutionTarget{}, "", nil, err
	}
	return sdkplugin.ExecutionTarget{Kind: sdkplugin.ExecutionTargetFilesystem, Location: projectPath}, projectPath, nil, nil
}

func (o *Options) registerInstalledPluginDescriptors(ctx context.Context, reg *engine.Registry) error {
	if reg == nil {
		return nil
	}
	launchCtx := o.PluginLaunchContext(ctx)
	return plugin.RegisterRuntimePlugins(launchCtx, reg, "")
}
