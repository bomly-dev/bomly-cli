package registry

import (
	"sort"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/auditors/policy"
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cargo"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cocoapods"
	"github.com/bomly-dev/bomly-cli/internal/detectors/composer"
	"github.com/bomly-dev/bomly-cli/internal/detectors/githubactions"
	"github.com/bomly-dev/bomly-cli/internal/detectors/gomod"
	"github.com/bomly-dev/bomly-cli/internal/detectors/gradle"
	"github.com/bomly-dev/bomly-cli/internal/detectors/maven"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-cli/internal/detectors/nuget"
	"github.com/bomly-dev/bomly-cli/internal/detectors/pub"
	"github.com/bomly-dev/bomly-cli/internal/detectors/python"
	"github.com/bomly-dev/bomly-cli/internal/detectors/ruby"
	sbomdetector "github.com/bomly-dev/bomly-cli/internal/detectors/sbom"
	"github.com/bomly-dev/bomly-cli/internal/detectors/syft"
	"github.com/bomly-dev/bomly-cli/internal/matchers/clearlydefined"
	"github.com/bomly-dev/bomly-cli/internal/matchers/depsdev"
	"github.com/bomly-dev/bomly-cli/internal/matchers/eol"
	"github.com/bomly-dev/bomly-cli/internal/matchers/grype"
	osvmatcher "github.com/bomly-dev/bomly-cli/internal/matchers/osv"
	model "github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// RegistryConfigs holds built-in registry wiring options resolved by the CLI layer.
type RegistryConfigs struct {
	FailOn      string
	OsvAPIBase  string
	OsvCacheDir string
	OsvCacheTTL string
	KEVCacheDir string
	KEVCacheTTL string
	EOLAPIBase  string
	EOLCacheDir string
	EOLCacheTTL string
}

// RegistryFilter narrows a registry down to the runtime-relevant selections.
type RegistryFilter struct {
	DetectorFilter  model.DetectorFilter
	AuditorFilter   model.AuditorFilter
	MatcherFilter   model.MatcherFilter
	EcosystemFilter model.EcosystemFilter
}

// DetectorDiscoveryPlan describes how one detector participates in runtime planning.
type DetectorDiscoveryPlan struct {
	SupportedEcosystems []model.Ecosystem
	SupportedManagers   []model.PackageManager
	EvidencePatterns    []string
	TargetKinds         []model.ExecutionTargetKind
}

// Clone returns a deep copy of the discovery plan.
func (p DetectorDiscoveryPlan) Clone() DetectorDiscoveryPlan {
	return DetectorDiscoveryPlan{
		SupportedEcosystems: append([]model.Ecosystem(nil), p.SupportedEcosystems...),
		SupportedManagers:   append([]model.PackageManager(nil), p.SupportedManagers...),
		EvidencePatterns:    append([]string(nil), p.EvidencePatterns...),
		TargetKinds:         append([]model.ExecutionTargetKind(nil), p.TargetKinds...),
	}
}

// Registry holds registered detectors, auditors, matchers, and discovery plans.
type Registry struct {
	logger         *zap.Logger
	configs        RegistryConfigs
	detectors      []model.Detector
	auditors       []model.Auditor
	matchers       []model.Matcher
	discoveryPlans map[string]DetectorDiscoveryPlan
}

// NewRegistry creates an empty registry.
func NewRegistry(configs RegistryConfigs, logger zap.Logger) *Registry {
	return &Registry{
		logger:         &logger,
		configs:        configs,
		discoveryPlans: make(map[string]DetectorDiscoveryPlan),
	}
}

// Build registers detectors, auditors, and matchers.
func (r *Registry) Build() {
	r.logger.Debug("Building scan registry")
	r.registerDetectors()
	r.registerMatchers()
	r.registerAuditors()
	r.registerDiscoveryPlans()
}

func (r *Registry) registerDetectors() {
	for _, detector := range builtInDetectors(orderedBuiltInDetectors(r.logger)) {
		r.RegisterDetector(detector)
	}
}

// RegisterDetector adds a detector to the registry.
func (r *Registry) RegisterDetector(detector model.Detector) {
	if detector == nil {
		return
	}
	r.detectors = append(r.detectors, detector)
}

func (r *Registry) registerMatchers() {
	r.registerGrypeMatcher()
	r.registerOSVMatcher()
	r.registerDepsDevMatcher()
	r.registerClearlyDefinedMatcher()
	r.registerEOLMatcher()
}

func (r *Registry) registerGrypeMatcher() {
	for _, matcher := range builtInMatchers([]model.Matcher{grype.Matcher{Logger: r.logger}}) {
		r.RegisterMatcher(matcher)
	}
}

func (r *Registry) registerOSVMatcher() {
	osvCfg := osvmatcher.DefaultConfig()
	osvCfg.Logger = r.logger
	if r.configs.OsvAPIBase != "" {
		osvCfg.APIBase = r.configs.OsvAPIBase
	}
	if r.configs.OsvCacheDir != "" {
		osvCfg.CacheDir = r.configs.OsvCacheDir
	}
	if r.configs.OsvCacheTTL != "" {
		if d, err := time.ParseDuration(r.configs.OsvCacheTTL); err == nil {
			osvCfg.CacheTTL = d
		} else {
			r.logger.Warn("osv: invalid cache_ttl; using default", zap.String("value", r.configs.OsvCacheTTL), zap.Error(err))
		}
	}
	if r.configs.KEVCacheDir != "" {
		osvCfg.KEVCacheDir = r.configs.KEVCacheDir
	}
	if r.configs.KEVCacheTTL != "" {
		if d, err := time.ParseDuration(r.configs.KEVCacheTTL); err == nil {
			osvCfg.KEVCacheTTL = d
		} else {
			r.logger.Warn("osv: invalid kev_cache_ttl; using default", zap.String("value", r.configs.KEVCacheTTL), zap.Error(err))
		}
	}

	osvMatcher, err := osvmatcher.New(osvCfg)
	if err != nil {
		r.logger.Warn("osv matcher unavailable", zap.Error(err))
	} else {
		for _, matcher := range builtInMatchers([]model.Matcher{osvMatcher}) {
			r.RegisterMatcher(matcher)
		}
	}
}

func (r *Registry) registerEOLMatcher() {
	eolCfg := eol.DefaultConfig()
	eolCfg.Logger = r.logger
	if r.configs.EOLAPIBase != "" {
		eolCfg.APIBase = r.configs.EOLAPIBase
	}
	if r.configs.EOLCacheDir != "" {
		eolCfg.CacheDir = r.configs.EOLCacheDir
	}
	if r.configs.EOLCacheTTL != "" {
		if d, err := time.ParseDuration(r.configs.EOLCacheTTL); err == nil {
			eolCfg.CacheTTL = d
		} else {
			r.logger.Warn("eol: invalid cache_ttl; using default", zap.String("value", r.configs.EOLCacheTTL), zap.Error(err))
		}
	}
	eolChecker, err := eol.New(eolCfg)
	if err != nil {
		r.logger.Warn("endoflife.date checker unavailable", zap.Error(err))
	} else {
		for _, matcher := range builtInMatchers([]model.Matcher{eolChecker}) {
			r.RegisterMatcher(matcher)
		}
		r.logger.Debug("endoflife.date matcher configured",
			zap.String("api_base", eolCfg.APIBase),
			zap.String("cache_dir", eolCfg.CacheDir),
			zap.Duration("cache_ttl", eolCfg.CacheTTL),
		)
	}
}

func (r *Registry) registerDepsDevMatcher() {
	depsDevCfg := depsdev.DefaultConfig()
	depsDevCfg.Logger = r.logger
	depsDevChecker, err := depsdev.New(depsDevCfg)
	if err != nil {
		r.logger.Warn("deps.dev license checker unavailable", zap.Error(err))
	} else {
		for _, matcher := range builtInMatchers([]model.Matcher{depsDevChecker}) {
			r.RegisterMatcher(matcher)
		}
		r.logger.Debug("deps.dev matcher configured")
	}
}

func (r *Registry) registerClearlyDefinedMatcher() {
	clearlyDefinedCfg := clearlydefined.DefaultConfig()
	clearlyDefinedCfg.Logger = r.logger
	clearlyDefinedChecker, err := clearlydefined.New(clearlyDefinedCfg)
	if err != nil {
		r.logger.Warn("ClearlyDefined license checker unavailable", zap.Error(err))
	} else {
		for _, matcher := range builtInMatchers([]model.Matcher{clearlyDefinedChecker}) {
			r.RegisterMatcher(matcher)
		}
		r.logger.Debug("ClearlyDefined matcher configured")
	}
}

// RegisterMatcher adds a matcher to the registry.
func (r *Registry) RegisterMatcher(matcher model.Matcher) {
	if matcher == nil {
		return
	}
	r.matchers = append(r.matchers, matcher)
}

func (r *Registry) registerAuditors() {
	for _, auditor := range builtInAuditors([]model.Auditor{policy.Auditor{FailOn: r.configs.FailOn}}) {
		r.RegisterAuditor(auditor)
	}
}

// RegisterAuditor adds an auditor to the registry.
func (r *Registry) RegisterAuditor(auditor model.Auditor) {
	if auditor == nil {
		return
	}
	r.auditors = append(r.auditors, auditor)
}

func (r *Registry) registerDiscoveryPlans() {
	r.RegisterDetectorDiscoveryPlan(detectors.NameSyft, DetectorDiscoveryPlan{
		SupportedEcosystems: SupportedEcosystemsForDetector(detectors.NameSyft),
		SupportedManagers:   SupportedPackageManagersForDetector(detectors.NameSyft),
		TargetKinds:         []model.ExecutionTargetKind{model.ExecutionTargetContainerImage},
	})
}

// RegisterDetectorDiscoveryPlan records planning metadata for automatic detector discovery.
func (r *Registry) RegisterDetectorDiscoveryPlan(detectorName string, plan DetectorDiscoveryPlan) {
	if r == nil || detectorName == "" {
		return
	}
	if r.discoveryPlans == nil {
		r.discoveryPlans = make(map[string]DetectorDiscoveryPlan)
	}
	r.discoveryPlans[detectorName] = plan
}

// DetectorDescriptors returns registered detector descriptors in registration order.
func (r *Registry) DetectorDescriptors() []model.DetectorDescriptor {
	descriptors := make([]model.DetectorDescriptor, 0, len(r.detectors))
	for _, detector := range r.detectors {
		descriptors = append(descriptors, detector.Descriptor())
	}
	return descriptors
}

// AuditorDescriptors returns registered auditor descriptors sorted by name.
func (r *Registry) AuditorDescriptors() []model.AuditorDescriptor {
	descriptors := make([]model.AuditorDescriptor, 0, len(r.auditors))
	for _, auditor := range r.auditors {
		descriptors = append(descriptors, auditor.Descriptor())
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}

// MatcherDescriptors returns registered matcher descriptors sorted by name.
func (r *Registry) MatcherDescriptors() []model.MatcherDescriptor {
	descriptors := make([]model.MatcherDescriptor, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		descriptors = append(descriptors, matcher.Descriptor())
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}

// Detectors returns matching detectors in registration order.
func (r *Registry) Detectors(req model.DetectionRequest) []model.Detector {
	matches := make([]model.Detector, 0, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !detectorSelected(req.DetectorFilter, descriptor) {
			continue
		}
		if req.Ecosystem != model.EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != model.PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		matches = append(matches, detector)
	}
	return matches
}

// PlannedDetectors returns detectors matching the requested names in the provided order.
func (r *Registry) PlannedDetectors(req model.DetectionRequest, names []string) []model.Detector {
	if len(names) == 0 {
		return r.Detectors(req)
	}

	available := make(map[string]model.Detector, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !detectorSelected(req.DetectorFilter, descriptor) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		available[descriptor.Name] = detector
	}

	matches := make([]model.Detector, 0, len(names))
	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		detector, ok := available[name]
		if !ok {
			continue
		}
		seen[name] = struct{}{}
		matches = append(matches, detector)
	}
	return matches
}

// Auditors returns matching auditors sorted by priority descending then name.
func (r *Registry) Auditors(req model.AuditRequest) []model.Auditor {
	matches := make([]model.Auditor, 0, len(r.auditors))
	for _, auditor := range r.auditors {
		descriptor := auditor.Descriptor()
		if !auditorSelected(req.AuditorFilter, descriptor) {
			continue
		}
		if !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		matches = append(matches, auditor)
	}
	return matches
}

// Matchers returns matching matchers sorted by priority descending then name.
func (r *Registry) Matchers(req model.MatchRequest) []model.Matcher {
	matches := make([]model.Matcher, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		descriptor := matcher.Descriptor()
		if !matcherSelected(req.MatcherFilter, descriptor) {
			continue
		}
		if req.Ecosystem != model.EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != model.PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
			continue
		}
		matches = append(matches, matcher)
	}
	return matches
}

// DiscoveryPlans returns planning metadata keyed by detector name.
func (r *Registry) DiscoveryPlans() map[string]DetectorDiscoveryPlan {
	if r == nil || len(r.discoveryPlans) == 0 {
		return nil
	}
	out := make(map[string]DetectorDiscoveryPlan, len(r.discoveryPlans))
	for name, plan := range r.discoveryPlans {
		out[name] = plan.Clone()
	}
	return out
}

// Filter returns a copy of the registry filtered by the supplied detector, auditor,
// matcher, and ecosystem selections.
func (r *Registry) Filter(filter RegistryFilter) *Registry {
	filtered := NewRegistry(r.configs, *r.logger)

	allowedDetectors := make(map[string]struct{}, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !detectorSelected(filter.DetectorFilter, descriptor) {
			continue
		}
		supportedEcosystems := descriptor.SupportedEcosystems
		if plan, ok := r.discoveryPlans[descriptor.Name]; ok {
			supportedEcosystems = mergeEcosystems(supportedEcosystems, plan.SupportedEcosystems)
		}
		if !descriptorAllowsEcosystem(supportedEcosystems, filter.EcosystemFilter) {
			continue
		}
		filtered.detectors = append(filtered.detectors, detector)
		allowedDetectors[descriptor.Name] = struct{}{}
	}

	for _, auditor := range r.auditors {
		descriptor := auditor.Descriptor()
		if !auditorSelected(filter.AuditorFilter, descriptor) {
			continue
		}
		if !descriptorAllowsEcosystem(descriptor.SupportedEcosystems, filter.EcosystemFilter) {
			continue
		}
		filtered.auditors = append(filtered.auditors, auditor)
	}

	for _, matcher := range r.matchers {
		descriptor := matcher.Descriptor()
		if !matcherSelected(filter.MatcherFilter, descriptor) {
			continue
		}
		if !descriptorAllowsEcosystem(descriptor.SupportedEcosystems, filter.EcosystemFilter) {
			continue
		}
		filtered.matchers = append(filtered.matchers, matcher)
	}

	for name, plan := range r.discoveryPlans {
		if _, ok := allowedDetectors[name]; !ok {
			continue
		}
		if !descriptorAllowsEcosystem(plan.SupportedEcosystems, filter.EcosystemFilter) {
			continue
		}
		filtered.discoveryPlans[name] = plan.Clone()
	}

	return filtered
}

func supportsEcosystem(supported []model.Ecosystem, ecosystem model.Ecosystem) bool {
	if len(supported) == 0 {
		return true
	}
	for _, candidate := range supported {
		if candidate == ecosystem {
			return true
		}
	}
	return false
}

func supportsPackageManager(supported []model.PackageManager, manager model.PackageManager) bool {
	if len(supported) == 0 {
		return true
	}
	for _, candidate := range supported {
		if candidate == manager {
			return true
		}
	}
	return false
}

func supportsMode(supported []model.TargetMode, mode model.TargetMode) bool {
	for _, candidate := range supported {
		if candidate == mode {
			return true
		}
	}
	return false
}

func detectorSelected(filter model.DetectorFilter, descriptor model.DetectorDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return descriptor.Enabled
}

func auditorSelected(filter model.AuditorFilter, descriptor model.AuditorDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return descriptor.Enabled
}

func matcherSelected(filter model.MatcherFilter, descriptor model.MatcherDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return descriptor.Enabled
}

func descriptorAllowsEcosystem(supported []model.Ecosystem, ecosystemFilter model.EcosystemFilter) bool {
	include := make(map[model.Ecosystem]struct{}, len(ecosystemFilter.Include))
	for _, ecosystem := range ecosystemFilter.Include {
		include[ecosystem] = struct{}{}
	}
	exclude := make(map[model.Ecosystem]struct{}, len(ecosystemFilter.Exclude))
	for _, ecosystem := range ecosystemFilter.Exclude {
		exclude[ecosystem] = struct{}{}
	}

	if len(exclude) > 0 && len(supported) > 0 {
		allExcluded := true
		for _, ecosystem := range supported {
			if _, ok := exclude[ecosystem]; !ok {
				allExcluded = false
				break
			}
		}
		if allExcluded {
			return false
		}
	}

	if len(include) == 0 {
		return true
	}
	if len(supported) == 0 {
		return true
	}
	for _, ecosystem := range supported {
		if _, ok := include[ecosystem]; ok {
			return true
		}
	}
	return false
}

func mergeEcosystems(left, right []model.Ecosystem) []model.Ecosystem {
	if len(left) == 0 {
		return append([]model.Ecosystem(nil), right...)
	}
	if len(right) == 0 {
		return append([]model.Ecosystem(nil), left...)
	}

	merged := append([]model.Ecosystem(nil), left...)
	seen := make(map[model.Ecosystem]struct{}, len(left)+len(right))
	for _, ecosystem := range left {
		seen[ecosystem] = struct{}{}
	}
	for _, ecosystem := range right {
		if _, ok := seen[ecosystem]; ok {
			continue
		}
		seen[ecosystem] = struct{}{}
		merged = append(merged, ecosystem)
	}
	return merged
}

func orderedBuiltInDetectors(logger *zap.Logger) []model.Detector {
	detectorsByName := builtInDetectorsByName(logger)
	ordered := make([]model.Detector, 0, len(detectorsByName))
	seen := make(map[string]struct{}, len(detectorsByName))

	for _, manager := range SupportedPackageManagers() {
		for _, detectorName := range DetectorNamesForPackageManager(manager) {
			if detectorName == "" {
				continue
			}
			if _, ok := seen[detectorName]; ok {
				continue
			}
			detector, ok := detectorsByName[detectorName]
			if !ok || detector == nil {
				continue
			}
			seen[detectorName] = struct{}{}
			ordered = append(ordered, detector)
		}
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		return componentPriority(ordered[i].Descriptor().ComponentType) < componentPriority(ordered[j].Descriptor().ComponentType)
	})

	return ordered
}

func componentPriority(componentType model.ComponentType) int {
	switch componentType {
	case model.NativeComponent:
		return 0
	case model.LockfileParserComponent:
		return 1
	case model.ThirdPartyComponent:
		return 2
	case model.PluginComponent:
		return 3
	default:
		return 4
	}
}

func builtInDetectorsByName(logger *zap.Logger) map[string]model.Detector {
	syftFallback := syft.Detector{Logger: logger}
	syftPrimary := syft.Detector{
		Logger:              logger,
		SupportedManagers:   SupportedPackageManagersForDetector(detectors.NameSyft),
		SupportedEcosystems: SupportedEcosystemsForDetector(detectors.NameSyft),
	}
	sbomDetector := sbomdetector.Detector{Logger: logger}
	npmNativeDetector := npm.NativeDetector{Logger: logger, Fallback: syftFallback}
	pnpmNativeDetector := pnpm.NativeDetector{Logger: logger, Fallback: syftFallback}
	yarnNativeDetector := yarn.NativeDetector{Logger: logger, Fallback: syftFallback}
	npmDetector := npm.LockfileDetector{Logger: logger, Fallback: npmNativeDetector}
	pnpmDetector := pnpm.LockfileDetector{Logger: logger, Fallback: pnpmNativeDetector}
	yarnDetector := yarn.LockfileDetector{Logger: logger, Fallback: yarnNativeDetector}
	gradleDetector := gradle.Detector{Logger: logger, Fallback: syftFallback}
	mavenDetector := maven.Detector{Logger: logger, Fallback: syftFallback}
	goDetector := gomod.Detector{Logger: logger, Fallback: syftFallback}
	composerDetector := composer.Detector{Logger: logger, Fallback: syftFallback}
	bundlerDetector := ruby.Detector{Logger: logger, Fallback: syftFallback}
	githubActionsDetector := githubactions.Detector{}
	pipDetector := python.PipDetector{Logger: logger, Fallback: syftFallback}
	pipenvDetector := python.PipenvDetector{Logger: logger, Fallback: syftFallback}
	poetryDetector := python.PoetryDetector{Logger: logger, Fallback: syftFallback}
	uvDetector := python.UVDetector{Logger: logger, Fallback: syftFallback}
	nugetDetector := nuget.Detector{Logger: logger, Fallback: syftFallback}
	cargoDetector := cargo.Detector{Logger: logger, Fallback: syftFallback}
	pubDetector := pub.Detector{Logger: logger, Fallback: syftFallback}
	cocoaPodsDetector := cocoapods.Detector{Logger: logger, Fallback: syftFallback}

	return map[string]model.Detector{
		sbomDetector.Descriptor().Name:          sbomDetector,
		npmDetector.Descriptor().Name:           npmDetector,
		pnpmDetector.Descriptor().Name:          pnpmDetector,
		yarnDetector.Descriptor().Name:          yarnDetector,
		gradleDetector.Descriptor().Name:        gradleDetector,
		mavenDetector.Descriptor().Name:         mavenDetector,
		goDetector.Descriptor().Name:            goDetector,
		composerDetector.Descriptor().Name:      composerDetector,
		bundlerDetector.Descriptor().Name:       bundlerDetector,
		githubActionsDetector.Descriptor().Name: githubActionsDetector,
		pipDetector.Descriptor().Name:           pipDetector,
		pipenvDetector.Descriptor().Name:        pipenvDetector,
		poetryDetector.Descriptor().Name:        poetryDetector,
		uvDetector.Descriptor().Name:            uvDetector,
		nugetDetector.Descriptor().Name:         nugetDetector,
		cargoDetector.Descriptor().Name:         cargoDetector,
		pubDetector.Descriptor().Name:           pubDetector,
		cocoaPodsDetector.Descriptor().Name:     cocoaPodsDetector,
		syftPrimary.Descriptor().Name:           syftPrimary,
	}
}

func builtInDetectors(detectors []model.Detector) []model.Detector {
	out := make([]model.Detector, 0, len(detectors))
	for _, detector := range detectors {
		if detector == nil {
			continue
		}
		out = append(out, detector)
	}
	return out
}

func builtInMatchers(matchers []model.Matcher) []model.Matcher {
	out := make([]model.Matcher, 0, len(matchers))
	for _, matcher := range matchers {
		if matcher == nil {
			continue
		}
		out = append(out, matcher)
	}
	return out
}

func builtInAuditors(auditors []model.Auditor) []model.Auditor {
	out := make([]model.Auditor, 0, len(auditors))
	for _, auditor := range auditors {
		if auditor == nil {
			continue
		}
		out = append(out, auditor)
	}
	return out
}
