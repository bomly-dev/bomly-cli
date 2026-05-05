package cli

import (
	"cmp"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/git"
	"github.com/bomly-dev/bomly-cli/internal/output"
	managedplugin "github.com/bomly-dev/bomly-cli/internal/plugin"
	"github.com/bomly-dev/bomly-cli/internal/registry"
	"github.com/bomly-dev/bomly-cli/internal/scan"
	scanruntime "github.com/bomly-dev/bomly-cli/internal/scan/runtime"
	"github.com/bomly-dev/bomly-cli/internal/system"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

type globalOptions struct {
	Path         string
	Container    string
	URL          string
	Ref          string
	SBOM         bool
	Enrich       bool
	Audit        bool
	FailOn       string
	Format       string
	Interactive  bool
	Ecosystems   string
	Detectors    string
	Auditors     string
	Matchers     string
	InstallFirst bool
	InstallArgs  []string
	Config       string
	Quiet        bool
	Verbosity    int
	OsvAPIBase   string
	OsvCacheDir  string
	OsvCacheTTL  string
	KEVCacheDir  string
	KEVCacheTTL  string
	EOLAPIBase   string
	EOLCacheDir  string
	EOLCacheTTL  string
	resolved     *resolvedConfig
}

type commandContext struct {
	runtime         *scanruntime.Runtime
	executionTarget model.ExecutionTarget
	subprojects     []model.Subproject
	detectorFilter  model.DetectorFilter
	auditorFilter   model.AuditorFilter
	matcherFilter   model.MatcherFilter
	config          resolvedConfig
	format          output.Format
	outputPath      string
	verbose         bool
	cleanup         func() error
}

func (o *globalOptions) bind(root *cobra.Command) error {
	flags := root.PersistentFlags()
	flags.StringVar(&o.Path, "path", "", "Execution target path")
	flags.StringVar(&o.Container, "container", "", "Container image reference to scan with Syft")
	flags.StringVar(&o.URL, "url", "", "Git repository URL to clone and scan")
	flags.StringVar(&o.Ref, "ref", "", "Git reference to scan when using --url")
	flags.BoolVar(&o.SBOM, "sbom", false, "Treat the selected filesystem target as an SBOM file")
	flags.BoolVar(&o.Enrich, "enrich", false, "Enrich packages with external license and vulnerability data")
	flags.BoolVar(&o.Audit, "audit", false, "Evaluate policy and create findings from package vulnerability data")
	flags.StringVar(&o.FailOn, "fail-on", "", "Minimum severity that should create findings in audit mode: any, low, medium, high, critical")
	flags.StringVarP(&o.Format, "format", "f", "", "Output format: text, json, sarif")
	flags.BoolVar(&o.Interactive, "interactive", false, "Open an interactive terminal UI")
	flags.StringVar(&o.Ecosystems, "ecosystems", "", "Ecosystems to use; supports +name/-name to add/remove from all")
	flags.StringVar(&o.Detectors, "detectors", "", "Detector selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVar(&o.Auditors, "auditors", "", "Auditor selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.StringVar(&o.Matchers, "matchers", "", "Matcher selectors. Use names or aliases. Prefix with '+' to append defaults or '-' to remove from defaults")
	flags.BoolVar(&o.InstallFirst, "install-first", false, "Run detector-specific dependency installation before resolving graphs")
	flags.StringArrayVar(&o.InstallArgs, "install-arg", nil, "Additional detector-specific install argument; may be repeated")
	flags.StringVar(&o.Config, "config", "", "YAML config file path")
	flags.BoolVarP(&o.Quiet, "quiet", "q", false, "Suppress non-error stderr output")
	flags.CountVarP(&o.Verbosity, "verbose", "v", "Increase verbosity (-v = info, -vv = debug)")
	return bindDynamicFlagOptions(root)
}

func (o *globalOptions) newCommandContext(logger *zap.Logger) (commandContext, error) {
	executionTarget, _, cleanup, err := o.resolveExecutionTarget(logger)
	if err != nil {
		return commandContext{}, err
	}
	return o.newCommandContextForExecutionTarget(logger, executionTarget, cleanup)
}

func (o *globalOptions) newCommandContextForExecutionTarget(logger *zap.Logger, executionTarget model.ExecutionTarget, cleanup func() error) (commandContext, error) {
	current := o.current()
	ecosystemFilter, err := resolveEcosystemFilter(current.Ecosystems)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return commandContext{}, err
	}
	scanRegistry := scan.NewRegistry(registryBuilderConfig(current), *logger)
	scanRegistry.Build()
	if err := o.registerInstalledPluginMetadata(scanRegistry, current); err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return commandContext{}, err
	}
	detectorFilter, err := resolveDetectorFilter(current.Detectors, scanRegistry)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return commandContext{}, err
	}
	auditorFilter, err := resolveAuditorFilter(current.Auditors, scanRegistry)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return commandContext{}, err
	}
	matcherFilter, err := resolveMatcherFilter(current.Matchers, scanRegistry)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return commandContext{}, err
	}
	forcedPackageManager := model.PackageManagerUnknown
	if current.SBOM {
		forcedPackageManager = model.PackageManagerSBOM
	}
	if len(current.InstallArgs) > 0 {
		selectedDetectors := selectedDetectorNames(detectorFilter, scanRegistry)
		if len(selectedDetectors) != 1 {
			if cleanup != nil {
				_ = cleanup()
			}
			return commandContext{}, invalidInputf("--install-arg requires exactly one selected detector, got %d (%s)", len(selectedDetectors), strings.Join(selectedDetectors, ", "))
		}
	}
	preparedRuntime, err := scanruntime.Prepare(scanruntime.Request{
		Registry:             scanRegistry,
		ExecutionTarget:      executionTarget,
		ForcedPackageManager: forcedPackageManager,
		DetectorFilter:       detectorFilter,
		AuditorFilter:        auditorFilter,
		MatcherFilter:        matcherFilter,
		EcosystemFilter:      ecosystemFilter,
		PluginPolicy:         o.pluginExecutionPolicy(current),
	})
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return commandContext{}, invalidInputf("%v", err)
	}
	format, err := parseOutputMode(current)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return commandContext{}, invalidInputf("parse format: %v", err)
	}
	return commandContext{
		runtime:         preparedRuntime,
		executionTarget: executionTarget,
		subprojects:     preparedRuntime.Subprojects,
		detectorFilter:  detectorFilter,
		auditorFilter:   auditorFilter,
		matcherFilter:   matcherFilter,
		config:          current,
		format:          format,
		verbose:         current.Verbosity > 0,
		cleanup:         cleanup,
	}, nil
}

func (o *globalOptions) newCommandContextForResolvedResults(results []model.DetectionResult) (commandContext, error) {
	if len(results) == 0 {
		return commandContext{}, fmt.Errorf("build command context from resolved results: no results")
	}

	current := o.current()
	format, err := parseOutputMode(current)
	if err != nil {
		return commandContext{}, invalidInputf("parse format: %v", err)
	}

	scanRegistry := scan.NewRegistry(registryBuilderConfig(current), *zap.NewNop())
	scanRegistry.Build()
	if err := o.registerInstalledPluginMetadata(scanRegistry, current); err != nil {
		return commandContext{}, err
	}
	detectorFilter, err := resolveDetectorFilter(current.Detectors, scanRegistry)
	if err != nil {
		return commandContext{}, err
	}
	matcherFilter, err := resolveMatcherFilter(current.Matchers, scanRegistry)
	if err != nil {
		return commandContext{}, err
	}

	subprojects := make([]model.Subproject, 0, len(results))
	for _, result := range results {
		subprojects = append(subprojects, result.SubprojectInfo)
	}

	return commandContext{
		executionTarget: rootExecutionTargetForResults(results),
		subprojects:     subprojects,
		detectorFilter:  detectorFilter,
		matcherFilter:   matcherFilter,
		config:          current,
		format:          format,
		verbose:         current.Verbosity > 0,
	}, nil
}

func rootExecutionTargetForResults(results []model.DetectionResult) model.ExecutionTarget {
	if len(results) == 0 {
		return model.ExecutionTarget{}
	}
	if results[0].RootExecutionTarget.Kind != "" {
		return results[0].RootExecutionTarget
	}
	return results[0].SubprojectInfo.ExecutionTarget
}

func (ctx commandContext) close() error {
	if ctx.cleanup == nil {
		return nil
	}
	return ctx.cleanup()
}

func (o *globalOptions) resolveExecutionTarget(logger *zap.Logger) (model.ExecutionTarget, string, func() error, error) {
	current := o.current()
	if current.SBOM {
		if current.Container != "" || current.URL != "" || current.Ref != "" {
			return model.ExecutionTarget{}, "", nil, invalidInputf("--sbom cannot be combined with --container, --url, or --ref")
		}
		sbomPath, err := resolveExactFileTarget(current.Path)
		if err != nil {
			return model.ExecutionTarget{}, "", nil, err
		}
		return model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: sbomPath}, sbomPath, nil, nil
	}
	targetCount := 0
	if current.Path != "" {
		targetCount++
	}
	if current.URL != "" {
		targetCount++
	}
	if current.Container != "" {
		targetCount++
	}
	if targetCount > 1 {
		return model.ExecutionTarget{}, "", nil, invalidInputf("--path, --url, and --container cannot be used together")
	}
	if current.URL != "" {
		projectPath, err := git.CloneTemp(logger, current.URL, current.Ref)
		if err != nil {
			return model.ExecutionTarget{}, "", nil, invalidInputf("clone --url %q: %v", current.URL, err)
		}
		cleanup := func() error {
			return os.RemoveAll(projectPath)
		}
		return model.ExecutionTarget{
			Kind:          model.ExecutionTargetGitRepository,
			Location:      projectPath,
			RepositoryURL: current.URL,
			Ref:           current.Ref,
		}, projectPath, cleanup, nil
	}
	if current.Container != "" {
		if current.Ref != "" {
			return model.ExecutionTarget{}, "", nil, invalidInputf("--ref can only be used with --url")
		}
		return model.ExecutionTarget{
			Kind:     model.ExecutionTargetContainerImage,
			Location: strings.TrimSpace(current.Container),
		}, current.Container, nil, nil
	}
	projectPath, err := o.resolveProjectPath()
	if err != nil {
		return model.ExecutionTarget{}, "", nil, err
	}
	return model.ExecutionTarget{Kind: model.ExecutionTargetFilesystem, Location: projectPath}, projectPath, nil, nil
}

func (o *globalOptions) resolveProjectPath() (string, error) {
	current := o.current()
	if current.Path != "" {
		absPath, err := system.Abs(current.Path)
		if err != nil {
			return "", invalidInputf("resolve path %q: %v", current.Path, err)
		}
		return absPath, nil
	}
	cwd, err := system.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	return cwd, nil
}

func (o *globalOptions) pluginExecutionPolicy(current resolvedConfig) managedplugin.ExecutionPolicy {
	cwd := current.Path
	if strings.TrimSpace(cwd) == "" {
		if resolved, err := system.Getwd(); err == nil {
			cwd = resolved
		}
	}
	return managedplugin.ExecutionPolicy{
		CoreVersion: "",
		ConfigPath:  current.Config,
		CWD:         cwd,
		Verbosity:   current.Verbosity,
	}
}

func (o *globalOptions) registerInstalledPluginMetadata(reg *scan.Registry, current resolvedConfig) error {
	if reg == nil {
		return nil
	}
	policy := o.pluginExecutionPolicy(current)
	return managedplugin.RegisterRuntimePlugins(reg, "", policy)
}

func (o *globalOptions) resolveSubprojects(executionTarget model.ExecutionTarget) ([]model.Subproject, error) {
	current := o.current()
	ecosystemFilter, err := resolveEcosystemFilter(current.Ecosystems)
	if err != nil {
		return nil, err
	}

	forcedPackageManager := model.PackageManagerUnknown
	if current.SBOM {
		forcedPackageManager = model.PackageManagerSBOM
	}
	scanRegistry := scan.NewRegistry(registryBuilderConfig(current), *zap.NewNop())
	scanRegistry.Build()
	if err := o.registerInstalledPluginMetadata(scanRegistry, current); err != nil {
		return nil, err
	}
	detectorFilter, err := resolveDetectorFilter(current.Detectors, scanRegistry)
	if err != nil {
		return nil, err
	}
	auditorFilter, err := resolveAuditorFilter(current.Auditors, scanRegistry)
	if err != nil {
		return nil, err
	}
	matcherFilter, err := resolveMatcherFilter(current.Matchers, scanRegistry)
	if err != nil {
		return nil, err
	}

	runtime, err := scanruntime.Prepare(scanruntime.Request{
		Registry:             scanRegistry,
		ExecutionTarget:      executionTarget,
		ForcedPackageManager: forcedPackageManager,
		DetectorFilter:       detectorFilter,
		AuditorFilter:        auditorFilter,
		MatcherFilter:        matcherFilter,
		EcosystemFilter:      ecosystemFilter,
		PluginPolicy:         o.pluginExecutionPolicy(current),
	})
	if err != nil {
		return nil, invalidInputf("%v", err)
	}
	return runtime.Subprojects, nil
}

func (o *globalOptions) discoverSubprojects(executionTarget model.ExecutionTarget, ecosystemFilter model.EcosystemFilter) ([]model.Subproject, error) {
	_ = ecosystemFilter
	if executionTarget.Kind == model.ExecutionTargetContainerImage {
		return []model.Subproject{{
			ExecutionTarget: executionTarget,
			RelativePath:    ".",
		}}, nil
	}

	isFileTarget, err := executionTargetIsSingleFile(executionTarget)
	if err != nil {
		return nil, invalidInputf("discover subprojects: %v", err)
	}
	if isFileTarget {
		return indexedSubprojectsForPath(executionTarget, executionTarget.Location)
	}

	subprojects, err := discoverSubprojects(executionTarget)
	if err != nil {
		return nil, err
	}
	return subprojects, nil
}

func (ctx commandContext) projectDescriptor() output.ProjectDescriptor {
	ecosystem := "multiple"
	packageManager := "multiple"
	if len(ctx.subprojects) == 1 {
		ecosystem = string(ctx.subprojects[0].Ecosystem)
		packageManager = ctx.subprojects[0].PrimaryPackageManager().Name()
	}
	return output.ProjectDescriptor{
		Name:           filepath.Base(ctx.executionTarget.Location),
		Path:           ctx.executionTarget.Location,
		Ecosystem:      ecosystem,
		PackageManager: packageManager,
	}
}

func (ctx commandContext) projectDescriptorForSubproject(subproject model.Subproject) output.ProjectDescriptor {
	name := filepath.Base(subproject.ExecutionTarget.Location)
	if subproject.RelativePath == "." {
		name = filepath.Base(ctx.executionTarget.Location)
	}
	return output.ProjectDescriptor{
		Name:           name,
		Path:           subproject.ExecutionTarget.Location,
		Ecosystem:      string(subproject.Ecosystem),
		PackageManager: subproject.PrimaryPackageManager().Name(),
	}
}

func (ctx commandContext) resolveGraphRequests(mode model.TargetMode, query model.DependencyQuery, stderr io.Writer) []model.DetectionRequest {
	requests := make([]model.DetectionRequest, 0, len(ctx.subprojects))
	for _, subproject := range ctx.subprojects {
		requests = append(requests, model.DetectionRequest{
			ProjectPath:     subproject.ExecutionTarget.Location,
			ExecutionTarget: subproject.ExecutionTarget,
			Subproject:      subproject,
			Ecosystem:       subproject.Ecosystem,
			PackageManager:  subproject.PrimaryPackageManager(),
			DetectorFilter:  ctx.detectorFilter,
			Mode:            mode,
			Query:           query,
			InstallFirst:    ctx.config.InstallFirst,
			InstallArgs:     append([]string(nil), ctx.config.InstallArgs...),
			Stderr:          stderr,
			Verbose:         ctx.verbose,
		})
	}
	return requests
}

func parseOutputMode(cfg resolvedConfig) (output.Format, error) {
	if cfg.Interactive {
		return output.FormatText, nil
	}
	if strings.TrimSpace(cfg.Format) == "" {
		return output.FormatText, nil
	}
	return output.ParseFormat(strings.ToLower(strings.TrimSpace(cfg.Format)))
}

func resolveExactFileTarget(pathValue string) (string, error) {
	selectedPath := strings.TrimSpace(pathValue)
	if selectedPath == "" {
		cwd, err := system.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve cwd: %w", err)
		}
		selectedPath = cwd
	}
	absPath, err := system.Abs(selectedPath)
	if err != nil {
		return "", invalidInputf("resolve path %q: %v", selectedPath, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", invalidInputf("sbom file %q does not exist", selectedPath)
		}
		return "", invalidInputf("stat sbom file %q: %v", selectedPath, err)
	}
	if info.IsDir() {
		return "", invalidInputf("sbom path %q must be a file", selectedPath)
	}
	return absPath, nil
}

func (ctx commandContext) writer(stdout io.Writer) (io.Writer, func() error, error) {
	if ctx.outputPath == "" {
		return stdout, func() error { return nil }, nil
	}
	file, err := os.Create(ctx.outputPath)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return file, file.Close, nil
}

func parseCSV(value string) []string {
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		normalized := strings.ToLower(strings.TrimSpace(part))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		items = append(items, normalized)
	}
	return items
}

func discoverSubprojects(executionTarget model.ExecutionTarget) ([]model.Subproject, error) {
	seen := make(map[string]model.Subproject)
	if err := detectAndStoreSubprojects(executionTarget, executionTarget.Location, seen); err != nil {
		return nil, invalidInputf("discover subprojects: %v", err)
	}

	subprojects := make([]model.Subproject, 0, len(seen))
	for _, subproject := range seen {
		subprojects = append(subprojects, subproject)
	}
	sort.Slice(subprojects, func(i, j int) bool {
		if diff := cmp.Compare(subprojects[i].RelativePath, subprojects[j].RelativePath); diff != 0 {
			return diff < 0
		}
		return cmp.Compare(subprojects[i].PrimaryPackageManager().Name(), subprojects[j].PrimaryPackageManager().Name()) < 0
	})
	return subprojects, nil
}

func indexedSubprojectsForPath(executionTarget model.ExecutionTarget, candidatePath string) ([]model.Subproject, error) {
	indexedManagers, err := registry.IndexDetectors(candidatePath)
	if err != nil {
		return nil, invalidInputf("discover subprojects: %v", err)
	}
	return buildSubprojectsForIndexedManagers(executionTarget, candidatePath, indexedManagers)
}

func detectAndStoreSubprojects(executionTarget model.ExecutionTarget, candidatePath string, seen map[string]model.Subproject) error {
	indexedManagers, err := registry.IndexDetectors(candidatePath)
	if err != nil {
		return err
	}
	subprojects, err := buildSubprojectsForIndexedManagers(executionTarget, candidatePath, indexedManagers)
	if err != nil {
		return err
	}
	for _, subproject := range subprojects {
		key := subproject.RelativePath + "::" + subproject.PrimaryPackageManager().Name()
		seen[key] = subproject
	}
	return nil
}

func buildSubprojectsForIndexedManagers(executionTarget model.ExecutionTarget, candidatePath string, indexedManagers []registry.IndexedDetectors) ([]model.Subproject, error) {
	relPath, err := filepath.Rel(executionTarget.Location, candidatePath)
	if err != nil {
		return nil, err
	}
	if relPath == "" {
		relPath = "."
	}
	subprojects := make([]model.Subproject, 0, len(indexedManagers))
	for _, indexed := range indexedManagers {
		subprojectTarget := executionTarget
		subprojectTarget.Location = candidatePath
		subprojectTarget.Kind = model.ExecutionTargetFilesystem
		subprojects = append(subprojects, model.Subproject{
			ExecutionTarget:         subprojectTarget,
			RelativePath:            filepath.ToSlash(relPath),
			PrimaryDetector:         indexed.PrimaryDetector,
			DetectedPackageManagers: append([]model.PackageManager(nil), indexed.PackageManagers...),
			Ecosystem:               indexed.PackageManagers[0].Ecosystem(),
		})
	}
	return subprojects, nil
}

func executionTargetIsSingleFile(executionTarget model.ExecutionTarget) (bool, error) {
	if executionTarget.Kind != model.ExecutionTargetFilesystem {
		return false, nil
	}
	info, err := os.Stat(executionTarget.Location)
	if err != nil {
		return false, err
	}
	return !info.IsDir(), nil
}
