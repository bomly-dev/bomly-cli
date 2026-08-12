package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/auditors/license"
	packageauditor "github.com/bomly-dev/bomly-cli/internal/auditors/package"
	"github.com/bomly-dev/bomly-cli/internal/auditors/vulnerability"
	"github.com/bomly-dev/bomly-cli/internal/composition"
	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cargo"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cocoapods"
	"github.com/bomly-dev/bomly-cli/internal/detectors/composer"
	"github.com/bomly-dev/bomly-cli/internal/detectors/conan"
	"github.com/bomly-dev/bomly-cli/internal/detectors/githubactions"
	"github.com/bomly-dev/bomly-cli/internal/detectors/gomod"
	"github.com/bomly-dev/bomly-cli/internal/detectors/gradle"
	"github.com/bomly-dev/bomly-cli/internal/detectors/maven"
	"github.com/bomly-dev/bomly-cli/internal/detectors/mix"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/bun"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-cli/internal/detectors/nuget"
	"github.com/bomly-dev/bomly-cli/internal/detectors/pub"
	"github.com/bomly-dev/bomly-cli/internal/detectors/python"
	"github.com/bomly-dev/bomly-cli/internal/detectors/ruby"
	sbomdetector "github.com/bomly-dev/bomly-cli/internal/detectors/sbom"
	"github.com/bomly-dev/bomly-cli/internal/detectors/sbt"
	"github.com/bomly-dev/bomly-cli/internal/detectors/swiftpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/syft"
	"github.com/bomly-dev/bomly-sdk"
	"go.uber.org/zap"
)

// Configs holds built-in registry wiring options resolved by the CLI layer.
type Configs struct {
	// FailOn is the parsed list of --fail-on constraints. Vulnerability
	// constraints form an AND-set; other auditors may consume independent
	// finding-family constraints.
	FailOn                []sdk.FailOnConstraint
	AllowVulnerabilityIDs []string
	AllowLicenses         []string
	DenyLicenses          []string
	LicenseExemptPackages []string
	DenyPackages          []string
	DenyGroups            []string
	ProtectedPackages     []string
	TyposquatThreshold    string
	TyposquatMode         string
	OsvAPIBase            string
	OsvCacheDir           string
	OsvCacheTTL           string
	KEVCacheDir           string
	KEVCacheTTL           string
	ScorecardAPIBase      string
	ScorecardCacheDir     string
	ScorecardCacheTTL     string
	HTTPProxy             string
	HTTPNoProxy           string
	HTTPProxyType         string
	HTTPProxyHost         string
	HTTPProxyPort         int
	HTTPProxyUsername     string
	HTTPProxyPassword     string
	HTTPCACertFile        string
	HTTPClientProvider    *sdk.HTTPClientProvider
	// PluginConfigs carries kind-scoped per-component configuration blocks so
	// embedded components can decode the same block managed plugins receive.
	PluginConfigs config.PluginConfigs
	// CoreVersion is the running bomly core version, surfaced to embedded
	// components through sdk.HostContext.Runtime(). Empty when unknown.
	CoreVersion string
}

// Filter narrows a registry down to the runtime-relevant selections.
type Filter struct {
	DetectorFilter  sdk.DetectorFilter
	AuditorFilter   sdk.AuditorFilter
	MatcherFilter   sdk.MatcherFilter
	AnalyzerFilter  sdk.AnalyzerFilter
	EcosystemFilter sdk.EcosystemFilter
}

// DetectorDiscoveryPlan describes how one detector participates in runtime planning.
type DetectorDiscoveryPlan struct {
	SupportedEcosystems []sdk.Ecosystem
	SupportedManagers   []sdk.PackageManager
	EvidencePatterns    []string
	TargetKinds         []sdk.ExecutionTargetKind
}

// Clone returns a deep copy of the discovery plan.
func (p DetectorDiscoveryPlan) Clone() DetectorDiscoveryPlan {
	return DetectorDiscoveryPlan{
		SupportedEcosystems: append([]sdk.Ecosystem(nil), p.SupportedEcosystems...),
		SupportedManagers:   append([]sdk.PackageManager(nil), p.SupportedManagers...),
		EvidencePatterns:    append([]string(nil), p.EvidencePatterns...),
		TargetKinds:         append([]sdk.ExecutionTargetKind(nil), p.TargetKinds...),
	}
}

// Registry holds registered detectors, auditors, matchers, analyzers, and discovery plans.
type Registry struct {
	logger           *zap.Logger
	configs          Configs
	detectors        []sdk.Detector
	auditors         []sdk.Auditor
	matchers         []sdk.Matcher
	analyzers        []sdk.Analyzer
	discoveryPlans   map[string]DetectorDiscoveryPlan
	defaultEnabled   map[string]bool
	componentOrigins map[string]sdk.DetectorOrigin
	httpProvider     *sdk.HTTPClientProvider
}

// ComponentOptions records Bomly-owned registry behavior that plugin authors
// should not declare in public descriptors.
type ComponentOptions struct {
	DefaultEnabled bool
	Origin         sdk.DetectorOrigin
}

type detectorWithDescriptor struct {
	sdk.Detector
	descriptor sdk.DetectorDescriptor
}

func (d detectorWithDescriptor) Descriptor() sdk.DetectorDescriptor {
	return d.descriptor.Clone()
}

type remediationDetectorWithDescriptor struct {
	detectorWithDescriptor
}

func (d remediationDetectorWithDescriptor) RemediationHints(ctx context.Context, req sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return forwardRemediationHints(ctx, d.Detector, req)
}

type installFirstDetectorWithDescriptor struct {
	detectorWithDescriptor
}

func (d installFirstDetectorWithDescriptor) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.Detector.(sdk.InstallFirstDetector).Install(ctx, req)
}

type installFirstRemediationDetectorWithDescriptor struct {
	detectorWithDescriptor
}

func (d installFirstRemediationDetectorWithDescriptor) Install(ctx context.Context, req sdk.DetectionRequest) error {
	return d.Detector.(sdk.InstallFirstDetector).Install(ctx, req)
}

func (d installFirstRemediationDetectorWithDescriptor) RemediationHints(ctx context.Context, req sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	return forwardRemediationHints(ctx, d.Detector, req)
}

func forwardRemediationHints(ctx context.Context, detector sdk.Detector, req sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error) {
	provider, ok := detector.(sdk.DetectorRemediationProvider)
	if !ok {
		return sdk.RemediationHintResponse{}, fmt.Errorf(
			"detector %q does not implement remediation hints",
			detector.Descriptor().Name,
		)
	}
	return provider.RemediationHints(ctx, req)
}

type auditorWithDescriptor struct {
	sdk.Auditor
	descriptor sdk.AuditorDescriptor
}

func (a auditorWithDescriptor) Descriptor() sdk.AuditorDescriptor {
	return a.descriptor
}

type analyzerWithDescriptor struct {
	sdk.Analyzer
	descriptor sdk.AnalyzerDescriptor
}

func (a analyzerWithDescriptor) Descriptor() sdk.AnalyzerDescriptor {
	return a.descriptor
}

// NewRegistry creates an empty registry.
func NewRegistry(configs Configs, logger zap.Logger) *Registry {
	return &Registry{
		logger:           &logger,
		configs:          configs,
		discoveryPlans:   make(map[string]DetectorDiscoveryPlan),
		defaultEnabled:   make(map[string]bool),
		componentOrigins: make(map[string]sdk.DetectorOrigin),
		httpProvider:     configs.HTTPClientProvider,
	}
}

// Build registers detectors, auditors, matchers, and analyzers.
func (r *Registry) Build() {
	r.logger.Debug("Building scan registry")
	r.registerDetectors()
	r.registerMatchers()
	r.registerAnalyzers()
	r.registerAuditors()
	r.registerDiscoveryPlans()
}

func (r *Registry) registerDetectors() {
	for _, detector := range builtInDetectors(orderedBuiltInDetectors(r.logger, r.configs.PluginConfigs)) {
		r.RegisterDetector(detector)
	}
}

// nodeStrategyConfigFor decodes the kind-scoped plugins.detectors.<name>
// block into the shared Node strategy configuration. Decode failures are
// non-fatal: the detector runs with defaults and the problem is logged.
func nodeStrategyConfigFor(logger *zap.Logger, pluginConfigs config.PluginConfigs, name string) node.StrategyConfig {
	var cfg node.StrategyConfig
	block := pluginConfigs.ForComponent(string(sdk.PluginKindDetector), name)
	if len(block) == 0 {
		return cfg
	}
	data, err := json.Marshal(block)
	if err == nil {
		err = json.Unmarshal(data, &cfg)
	}
	if err != nil {
		if logger != nil {
			logger.Warn("detector configuration invalid; using defaults",
				zap.String("detector", name), zap.Error(err))
		}
		return node.StrategyConfig{}
	}
	return cfg
}

// RegisterDetector adds a detector to the registry.
func (r *Registry) RegisterDetector(detector sdk.Detector) {
	r.RegisterDetectorWithOptions(detector, ComponentOptions{DefaultEnabled: true, Origin: detectorOriginForRegistry(detector)})
}

// RegisterDetectorWithOptions adds a detector to the registry with internal behavior metadata.
func (r *Registry) RegisterDetectorWithOptions(detector sdk.Detector, options ComponentOptions) {
	if detector == nil {
		return
	}
	descriptor := decorateDetectorDescriptor(detector.Descriptor())
	r.detectors = append(r.detectors, detectorWithDecoratedDescriptor(detector, descriptor))
	r.setDefaultEnabled(sdk.PluginKindDetector, descriptor.Name, options.DefaultEnabled)
	r.setComponentOrigin(sdk.PluginKindDetector, descriptor.Name, options.Origin)
}

func (r *Registry) registerMatchers() {
	r.registerCompositionEntries(sdk.PluginKindMatcher)
}

// registerAnalyzers wires the built-in reachability analyzers from the build
// composition.
func (r *Registry) registerAnalyzers() {
	r.registerCompositionEntries(sdk.PluginKindAnalyzer)
}

// registerCompositionEntries registers every composition entry of one kind
// through the module registration path, preserving each entry's
// default-enabled flag and origin. Construction failures are non-fatal: the
// component is skipped with a warning, matching the historical bespoke
// wiring.
func (r *Registry) registerCompositionEntries(kind sdk.PluginKind) {
	deps := composition.Deps{
		Logger:             r.logger,
		HTTPClientProvider: r.httpClientProvider(),
		OsvAPIBase:         r.configs.OsvAPIBase,
		OsvCacheDir:        r.configs.OsvCacheDir,
		OsvCacheTTL:        r.configs.OsvCacheTTL,
		KEVCacheDir:        r.configs.KEVCacheDir,
		KEVCacheTTL:        r.configs.KEVCacheTTL,
		ScorecardAPIBase:   r.configs.ScorecardAPIBase,
		ScorecardCacheDir:  r.configs.ScorecardCacheDir,
		ScorecardCacheTTL:  r.configs.ScorecardCacheTTL,
	}
	for _, entry := range composition.Entries() {
		if entry.Kind != kind {
			continue
		}
		origin, err := entry.Origin(sdk.ExecutionEmbedded)
		if err != nil {
			r.logger.Warn("composition entry rejected", zap.String("component", entry.Name), zap.Error(err))
			continue
		}
		if err := r.RegisterModule(entry.Module(deps), ComponentOptions{DefaultEnabled: entry.DefaultEnabled, Origin: origin}); err != nil {
			r.logger.Warn("built-in component unavailable", zap.String("component", entry.Name), zap.Error(err))
		}
	}
}

func (r *Registry) httpClientProvider() *sdk.HTTPClientProvider {
	if r.httpProvider != nil {
		return r.httpProvider
	}
	provider, err := sdk.NewHTTPClientProvider(sdk.HTTPClientConfig{
		ProxyURL:      r.configs.HTTPProxy,
		NoProxy:       r.configs.HTTPNoProxy,
		ProxyType:     r.configs.HTTPProxyType,
		ProxyHost:     r.configs.HTTPProxyHost,
		ProxyPort:     r.configs.HTTPProxyPort,
		ProxyUsername: r.configs.HTTPProxyUsername,
		ProxyPassword: r.configs.HTTPProxyPassword,
		CACertFile:    r.configs.HTTPCACertFile,
	})
	if err != nil {
		r.logger.Warn("http client proxy configuration invalid; using environment defaults", zap.Error(err))
		provider, _ = sdk.NewHTTPClientProvider(sdk.HTTPClientConfig{})
	}
	r.httpProvider = provider
	return r.httpProvider
}

// RegisterMatcher adds a matcher to the registry.
func (r *Registry) RegisterMatcher(matcher sdk.Matcher) {
	r.RegisterMatcherWithOptions(matcher, ComponentOptions{DefaultEnabled: true})
}

// RegisterMatcherWithOptions adds a matcher to the registry with internal behavior metadata.
func (r *Registry) RegisterMatcherWithOptions(matcher sdk.Matcher, options ComponentOptions) {
	if matcher == nil {
		return
	}
	r.matchers = append(r.matchers, matcher)
	r.setDefaultEnabled(sdk.PluginKindMatcher, matcher.Descriptor().Name, options.DefaultEnabled)
	r.setComponentOrigin(sdk.PluginKindMatcher, matcher.Descriptor().Name, options.Origin)
}

// RegisterAnalyzer adds an analyzer to the registry.
func (r *Registry) RegisterAnalyzer(analyzer sdk.Analyzer) {
	r.RegisterAnalyzerWithOptions(analyzer, ComponentOptions{DefaultEnabled: true})
}

// RegisterAnalyzerWithOptions adds an analyzer to the registry with internal behavior metadata.
func (r *Registry) RegisterAnalyzerWithOptions(analyzer sdk.Analyzer, options ComponentOptions) {
	if analyzer == nil {
		return
	}
	descriptor := decorateAnalyzerDescriptor(analyzer.Descriptor())
	r.analyzers = append(r.analyzers, analyzerWithDescriptor{Analyzer: analyzer, descriptor: descriptor})
	r.setDefaultEnabled(sdk.PluginKindAnalyzer, descriptor.Name, options.DefaultEnabled)
	r.setComponentOrigin(sdk.PluginKindAnalyzer, descriptor.Name, options.Origin)
}

func (r *Registry) registerAuditors() {
	threshold, _ := strconv.ParseFloat(strings.TrimSpace(r.configs.TyposquatThreshold), 64)
	if threshold == 0 {
		threshold = 0.90
	}
	for _, auditor := range builtInAuditors([]sdk.Auditor{
		vulnerability.Auditor{
			FailOn:                append([]sdk.FailOnConstraint(nil), r.configs.FailOn...),
			AllowVulnerabilityIDs: append([]string(nil), r.configs.AllowVulnerabilityIDs...),
		},
		license.Auditor{
			AllowLicenses:  append([]string(nil), r.configs.AllowLicenses...),
			DenyLicenses:   append([]string(nil), r.configs.DenyLicenses...),
			ExemptPackages: append([]string(nil), r.configs.LicenseExemptPackages...),
		},
		packageauditor.Auditor{
			DenyPackages:       append([]string(nil), r.configs.DenyPackages...),
			DenyGroups:         append([]string(nil), r.configs.DenyGroups...),
			FailOn:             append([]sdk.FailOnConstraint(nil), r.configs.FailOn...),
			ProtectedPackages:  append([]string(nil), r.configs.ProtectedPackages...),
			TyposquatThreshold: threshold,
			TyposquatMode:      r.configs.TyposquatMode,
		},
	}) {
		r.RegisterAuditor(auditor)
	}
}

// RegisterAuditor adds an auditor to the registry.
func (r *Registry) RegisterAuditor(auditor sdk.Auditor) {
	r.RegisterAuditorWithOptions(auditor, ComponentOptions{DefaultEnabled: true})
}

// RegisterAuditorWithOptions adds an auditor to the registry with internal behavior metadata.
func (r *Registry) RegisterAuditorWithOptions(auditor sdk.Auditor, options ComponentOptions) {
	if auditor == nil {
		return
	}
	descriptor := decorateAuditorDescriptor(auditor.Descriptor())
	r.auditors = append(r.auditors, auditorWithDescriptor{Auditor: auditor, descriptor: descriptor})
	r.setDefaultEnabled(sdk.PluginKindAuditor, descriptor.Name, options.DefaultEnabled)
	r.setComponentOrigin(sdk.PluginKindAuditor, descriptor.Name, options.Origin)
}

func (r *Registry) registerDiscoveryPlans() {
	r.RegisterDetectorDiscoveryPlan(detectors.NameSyft, DetectorDiscoveryPlan{
		SupportedEcosystems: SupportedEcosystemsForDetector(detectors.NameSyft),
		SupportedManagers:   SupportedPackageManagersForDetector(detectors.NameSyft),
		TargetKinds:         []sdk.ExecutionTargetKind{sdk.ExecutionTargetContainerImage},
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

func (r *Registry) setDefaultEnabled(kind sdk.PluginKind, name string, enabled bool) {
	if r == nil || strings.TrimSpace(name) == "" {
		return
	}
	if r.defaultEnabled == nil {
		r.defaultEnabled = make(map[string]bool)
	}
	r.defaultEnabled[componentKey(kind, name)] = enabled
}

func (r *Registry) isDefaultEnabled(kind sdk.PluginKind, name string) bool {
	if r == nil {
		return false
	}
	enabled, ok := r.defaultEnabled[componentKey(kind, name)]
	return ok && enabled
}

// DefaultEnabledDetectorNames returns the default-selected detector names.
func (r *Registry) DefaultEnabledDetectorNames() []string {
	names := make([]string, 0)
	for _, descriptor := range r.DetectorDescriptors() {
		if descriptor.Name != "" && r.isDefaultEnabled(sdk.PluginKindDetector, descriptor.Name) {
			names = append(names, descriptor.Name)
		}
	}
	sort.Strings(names)
	return names
}

// DefaultEnabledAuditorNames returns the default-selected auditor names.
func (r *Registry) DefaultEnabledAuditorNames() []string {
	names := make([]string, 0)
	for _, descriptor := range r.AuditorDescriptors() {
		if descriptor.Name != "" && r.isDefaultEnabled(sdk.PluginKindAuditor, descriptor.Name) {
			names = append(names, descriptor.Name)
		}
	}
	sort.Strings(names)
	return names
}

// DefaultEnabledMatcherNames returns the default-selected matcher names.
func (r *Registry) DefaultEnabledMatcherNames() []string {
	names := make([]string, 0)
	for _, descriptor := range r.MatcherDescriptors() {
		if descriptor.Name != "" && r.isDefaultEnabled(sdk.PluginKindMatcher, descriptor.Name) {
			names = append(names, descriptor.Name)
		}
	}
	sort.Strings(names)
	return names
}

// DefaultEnabledAnalyzerNames returns the default-selected analyzer names.
func (r *Registry) DefaultEnabledAnalyzerNames() []string {
	names := make([]string, 0)
	for _, descriptor := range r.AnalyzerDescriptors() {
		if descriptor.Name != "" && r.isDefaultEnabled(sdk.PluginKindAnalyzer, descriptor.Name) {
			names = append(names, descriptor.Name)
		}
	}
	sort.Strings(names)
	return names
}

func (r *Registry) setComponentOrigin(kind sdk.PluginKind, name string, origin sdk.DetectorOrigin) {
	if r == nil || strings.TrimSpace(name) == "" {
		return
	}
	if origin == "" {
		origin = sdk.CoreOrigin
	}
	if r.componentOrigins == nil {
		r.componentOrigins = make(map[string]sdk.DetectorOrigin)
	}
	r.componentOrigins[componentKey(kind, name)] = origin
}

// ComponentOrigin returns Bomly-owned origin metadata for a registered component.
func (r *Registry) ComponentOrigin(kind sdk.PluginKind, name string) sdk.DetectorOrigin {
	if r == nil {
		return sdk.CoreOrigin
	}
	origin := r.componentOrigins[componentKey(kind, name)]
	if origin == "" {
		return sdk.CoreOrigin
	}
	return origin
}

// ComponentConfig returns the resolved configuration block for a registered
// component, or nil when none is configured. Embedded components can decode
// the same kind-scoped block that managed plugins receive.
func (r *Registry) ComponentConfig(kind sdk.PluginKind, name string) map[string]any {
	if r == nil {
		return nil
	}
	return r.configs.PluginConfigs.ForComponent(string(kind), name)
}

// DetectorOrigin returns Bomly-owned origin metadata for a registered detector.
func (r *Registry) DetectorOrigin(name string) sdk.DetectorOrigin {
	return r.ComponentOrigin(sdk.PluginKindDetector, name)
}

// DetectorDescriptors returns registered detector descriptors in registration order.
func (r *Registry) DetectorDescriptors() []sdk.DetectorDescriptor {
	descriptors := make([]sdk.DetectorDescriptor, 0, len(r.detectors))
	for _, detector := range r.detectors {
		descriptors = append(descriptors, detector.Descriptor())
	}
	return descriptors
}

// AllDetectors returns all registered detectors in registration order, without
// any filtering. Intended for introspection (e.g. plugin test/doctor).
func (r *Registry) AllDetectors() []sdk.Detector {
	result := make([]sdk.Detector, len(r.detectors))
	copy(result, r.detectors)
	return result
}

// AllMatchers returns all registered matchers in registration order, without
// any filtering. Intended for introspection (e.g. plugin test/doctor).
func (r *Registry) AllMatchers() []sdk.Matcher {
	result := make([]sdk.Matcher, len(r.matchers))
	copy(result, r.matchers)
	return result
}

// AllAuditors returns all registered auditors in registration order, without
// any filtering. Intended for introspection (e.g. plugin test/doctor).
func (r *Registry) AllAuditors() []sdk.Auditor {
	result := make([]sdk.Auditor, len(r.auditors))
	copy(result, r.auditors)
	return result
}

// AllAnalyzers returns all registered analyzers in registration order, without
// any filtering. Intended for introspection (e.g. plugin test/doctor).
func (r *Registry) AllAnalyzers() []sdk.Analyzer {
	result := make([]sdk.Analyzer, len(r.analyzers))
	copy(result, r.analyzers)
	return result
}

// AuditorDescriptors returns registered auditor descriptors sorted by name.
func (r *Registry) AuditorDescriptors() []sdk.AuditorDescriptor {
	descriptors := make([]sdk.AuditorDescriptor, 0, len(r.auditors))
	for _, auditor := range r.auditors {
		descriptors = append(descriptors, auditor.Descriptor())
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}

// MatcherDescriptors returns registered matcher descriptors sorted by name.
func (r *Registry) MatcherDescriptors() []sdk.MatcherDescriptor {
	descriptors := make([]sdk.MatcherDescriptor, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		descriptors = append(descriptors, matcher.Descriptor())
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}

// AnalyzerDescriptors returns registered analyzer descriptors sorted by name.
func (r *Registry) AnalyzerDescriptors() []sdk.AnalyzerDescriptor {
	descriptors := make([]sdk.AnalyzerDescriptor, 0, len(r.analyzers))
	for _, analyzer := range r.analyzers {
		descriptors = append(descriptors, analyzer.Descriptor())
	}
	sort.Slice(descriptors, func(i, j int) bool {
		return descriptors[i].Name < descriptors[j].Name
	})
	return descriptors
}

// Detectors returns matching detectors in registration order.
func (r *Registry) Detectors(req sdk.DetectionRequest) []sdk.Detector {
	matches := make([]sdk.Detector, 0, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !r.detectorSelected(req.DetectorFilter, descriptor) {
			continue
		}
		if req.Ecosystem != sdk.EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != sdk.PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		matches = append(matches, detector)
	}
	return matches
}

// PlannedDetectors returns detectors matching the requested names in the provided order.
func (r *Registry) PlannedDetectors(req sdk.DetectionRequest, names []string) []sdk.Detector {
	if len(names) == 0 {
		return r.Detectors(req)
	}

	available := make(map[string]sdk.Detector, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !r.detectorSelected(req.DetectorFilter, descriptor) {
			continue
		}
		available[descriptor.Name] = detector
	}

	matches := make([]sdk.Detector, 0, len(names))
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
func (r *Registry) Auditors(req sdk.AuditRequest) []sdk.Auditor {
	matches := make([]sdk.Auditor, 0, len(r.auditors))
	for _, auditor := range r.auditors {
		descriptor := auditor.Descriptor()
		if !r.auditorSelected(req.AuditorFilter, descriptor) {
			continue
		}
		if !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		matches = append(matches, auditor)
	}
	return matches
}

// Analyzers returns the analyzers that apply to the request, filtered by
// include/exclude selectors, ecosystem, package manager, language, and mode.
// Empty SupportedLanguages on a descriptor means "applies to any language".
func (r *Registry) Analyzers(req sdk.AnalyzeRequest) []sdk.Analyzer {
	matches := make([]sdk.Analyzer, 0, len(r.analyzers))
	for _, analyzer := range r.analyzers {
		descriptor := analyzer.Descriptor()
		if !r.analyzerSelected(req.AnalyzerFilter, descriptor) {
			continue
		}
		if req.Ecosystem != sdk.EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != sdk.PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
			continue
		}
		if req.Language != sdk.LanguageUnknown && !supportsLanguage(descriptor.SupportedLanguages, req.Language) {
			continue
		}
		matches = append(matches, analyzer)
	}
	return matches
}

// Matchers returns matching matchers sorted by priority descending then name.
func (r *Registry) Matchers(req sdk.MatchRequest) []sdk.Matcher {
	matches := make([]sdk.Matcher, 0, len(r.matchers))
	for _, matcher := range r.matchers {
		descriptor := matcher.Descriptor()
		if !r.matcherSelected(req.MatcherFilter, descriptor) {
			continue
		}
		if req.Ecosystem != sdk.EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != sdk.PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
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
func (r *Registry) Filter(filter Filter) *Registry {
	filtered := NewRegistry(r.configs, *r.logger)
	filtered.httpProvider = r.httpProvider
	for key, enabled := range r.defaultEnabled {
		filtered.defaultEnabled[key] = enabled
	}
	for key, origin := range r.componentOrigins {
		filtered.componentOrigins[key] = origin
	}

	allowedDetectors := make(map[string]struct{}, len(r.detectors))
	for _, detector := range r.detectors {
		descriptor := detector.Descriptor()
		if !r.detectorSelected(filter.DetectorFilter, descriptor) {
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
		if !r.auditorSelected(filter.AuditorFilter, descriptor) {
			continue
		}
		if !descriptorAllowsEcosystem(descriptor.SupportedEcosystems, filter.EcosystemFilter) {
			continue
		}
		filtered.auditors = append(filtered.auditors, auditor)
	}

	for _, matcher := range r.matchers {
		descriptor := matcher.Descriptor()
		if !r.matcherSelected(filter.MatcherFilter, descriptor) {
			continue
		}
		if !descriptorAllowsEcosystem(descriptor.SupportedEcosystems, filter.EcosystemFilter) {
			continue
		}
		filtered.matchers = append(filtered.matchers, matcher)
	}

	for _, analyzer := range r.analyzers {
		descriptor := analyzer.Descriptor()
		if !r.analyzerSelected(filter.AnalyzerFilter, descriptor) {
			continue
		}
		if !descriptorAllowsEcosystem(descriptor.SupportedEcosystems, filter.EcosystemFilter) {
			continue
		}
		filtered.analyzers = append(filtered.analyzers, analyzer)
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

func supportsEcosystem(supported []sdk.Ecosystem, ecosystem sdk.Ecosystem) bool {
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

func supportsLanguage(supported []sdk.Language, language sdk.Language) bool {
	if len(supported) == 0 {
		return true
	}
	for _, candidate := range supported {
		if candidate == language {
			return true
		}
	}
	return false
}

func supportsPackageManager(supported []sdk.PackageManager, manager sdk.PackageManager) bool {
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

func (r *Registry) detectorSelected(filter sdk.DetectorFilter, descriptor sdk.DetectorDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return r.isDefaultEnabled(sdk.PluginKindDetector, descriptor.Name)
}

func (r *Registry) auditorSelected(filter sdk.AuditorFilter, descriptor sdk.AuditorDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return r.isDefaultEnabled(sdk.PluginKindAuditor, descriptor.Name)
}

func (r *Registry) matcherSelected(filter sdk.MatcherFilter, descriptor sdk.MatcherDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	// Operator-mode (--matchers +name / -name) populates Exclude with the
	// catalog minus the resolved selection. Anything not in Exclude must run,
	// including default-off matchers the user opted in with +name. Without
	// this branch, falling through to registry defaults would silently drop
	// default-off matchers even though the user explicitly asked for them.
	if len(filter.Exclude) > 0 {
		return true
	}
	return r.isDefaultEnabled(sdk.PluginKindMatcher, descriptor.Name)
}

func (r *Registry) analyzerSelected(filter sdk.AnalyzerFilter, descriptor sdk.AnalyzerDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return r.isDefaultEnabled(sdk.PluginKindAnalyzer, descriptor.Name)
}

func descriptorAllowsEcosystem(supported []sdk.Ecosystem, ecosystemFilter sdk.EcosystemFilter) bool {
	include := make(map[sdk.Ecosystem]struct{}, len(ecosystemFilter.Include))
	for _, ecosystem := range ecosystemFilter.Include {
		include[ecosystem] = struct{}{}
	}
	exclude := make(map[sdk.Ecosystem]struct{}, len(ecosystemFilter.Exclude))
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

func mergeEcosystems(left, right []sdk.Ecosystem) []sdk.Ecosystem {
	if len(left) == 0 {
		return append([]sdk.Ecosystem(nil), right...)
	}
	if len(right) == 0 {
		return append([]sdk.Ecosystem(nil), left...)
	}

	merged := append([]sdk.Ecosystem(nil), left...)
	seen := make(map[sdk.Ecosystem]struct{}, len(left)+len(right))
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

func orderedBuiltInDetectors(logger *zap.Logger, pluginConfigs config.PluginConfigs) []sdk.Detector {
	detectorsByName := builtInDetectorsByName(logger, pluginConfigs)
	ordered := make([]sdk.Detector, 0, len(detectorsByName))
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
		left := ordered[i].Descriptor()
		right := ordered[j].Descriptor()
		return componentPriority(DetectorOriginForName(left.Name), left.Technique) < componentPriority(DetectorOriginForName(right.Name), right.Technique)
	})

	return ordered
}

// componentPriority assigns a priority for ordering detectors, with lower values indicating higher priority.
// The priority is determined first by the origin (external vs built-in) and then by the technique,
// with lockfile and build tool techniques prioritized over manifest, SBOM, binary, and container techniques,
// which are in turn prioritized over multiple technique and other techniques.
func componentPriority(origin sdk.DetectorOrigin, technique sdk.DetectorTechnique) int {
	if origin == sdk.ExternalOrigin {
		return 0
	}
	switch technique {
	case sdk.LockfileTechnique, sdk.BuildToolTechnique:
		return 1
	case sdk.ManifestTechnique, sdk.SBOMTechnique, sdk.BinaryTechnique, sdk.ContainerTechnique:
		return 2
	case sdk.MultipleTechnique:
		return 3
	default:
		return 4
	}
}

func decorateDetectorDescriptor(descriptor sdk.DetectorDescriptor) sdk.DetectorDescriptor {
	if aliases := builtInDetectorAliases[descriptor.Name]; len(aliases) > 0 {
		descriptor.Aliases = appendUniqueStrings(descriptor.Aliases, aliases...)
	}
	if displayName := builtInDisplayNames[descriptor.Name]; displayName != "" && descriptor.DisplayName == "" {
		descriptor.DisplayName = displayName
	}
	return descriptor
}

func detectorWithDecoratedDescriptor(detector sdk.Detector, descriptor sdk.DetectorDescriptor) sdk.Detector {
	base := detectorWithDescriptor{Detector: detector, descriptor: descriptor}
	_, hasInstall := detector.(sdk.InstallFirstDetector)
	_, hasRemediation := detector.(sdk.DetectorRemediationProvider)
	switch {
	case hasInstall && hasRemediation:
		return installFirstRemediationDetectorWithDescriptor{detectorWithDescriptor: base}
	case hasInstall:
		return installFirstDetectorWithDescriptor{detectorWithDescriptor: base}
	case hasRemediation:
		return remediationDetectorWithDescriptor{detectorWithDescriptor: base}
	default:
		return base
	}
}

func decorateAuditorDescriptor(descriptor sdk.AuditorDescriptor) sdk.AuditorDescriptor {
	if aliases := builtInAuditorAliases[descriptor.Name]; len(aliases) > 0 {
		descriptor.Aliases = appendUniqueStrings(descriptor.Aliases, aliases...)
	}
	if displayName := builtInDisplayNames[descriptor.Name]; displayName != "" && descriptor.DisplayName == "" {
		descriptor.DisplayName = displayName
	}
	return descriptor
}

func decorateAnalyzerDescriptor(descriptor sdk.AnalyzerDescriptor) sdk.AnalyzerDescriptor {
	if aliases := builtInAnalyzerAliases[descriptor.Name]; len(aliases) > 0 {
		descriptor.Aliases = appendUniqueStrings(descriptor.Aliases, aliases...)
	}
	if displayName := builtInDisplayNames[descriptor.Name]; displayName != "" && descriptor.DisplayName == "" {
		descriptor.DisplayName = displayName
	}
	return descriptor
}

var builtInDetectorAliases = map[string][]string{
	detectors.NameNPM:           {"npm-detector", "npm-lockfile", "npm-native", "npm-native-detector"},
	detectors.NamePNPM:          {"pnpm-detector", "pnpm-lockfile", "pnpm-native", "pnpm-native-detector"},
	detectors.NameYarn:          {"yarn-detector", "yarn-lockfile", "yarn-native", "yarn-native-detector"},
	detectors.NameBun:           {"bun"},
	detectors.NameBunNative:     {"bun-native"},
	detectors.NameGradle:        {"gradle"},
	detectors.NameMaven:         {"maven"},
	detectors.NameGoMod:         {"go", "gomod"},
	detectors.NameComposer:      {"composer"},
	detectors.NameBundler:       {"bundler", "ruby"},
	detectors.NameGitHubActions: {"github-actions"},
	detectors.NamePip:           {"pip"},
	detectors.NamePipenv:        {"pipenv"},
	detectors.NamePoetry:        {"poetry"},
	detectors.NameUV:            {"uv"},
	detectors.NameNuGet:         {"nuget"},
	detectors.NameCargo:         {"cargo"},
	detectors.NamePub:           {"pub"},
	detectors.NamePubNative:     {"pub-native"},
	detectors.NameCocoaPods:     {"cocoapods", "pods"},
	detectors.NameSwiftPM:       {"swiftpm"},
	detectors.NameSwiftPMNative: {"swiftpm-native"},
	detectors.NameMix:           {"mix"},
	detectors.NameConan:         {"conan"},
	detectors.NameSBT:           {"sbt"},
	detectors.NameSBTNative:     {"sbt-native"},
	detectors.NameSBOM:          {"sbom"},
	detectors.NameSyft:          {"syft"},
}

var builtInAuditorAliases = map[string][]string{
	"license":       {"licenses", "license-policy"},
	"package":       {"packages", "package-policy", "typosquat"},
	"vulnerability": {"vuln", "vulnerabilities"},
}

var builtInAnalyzerAliases = map[string][]string{
	"govulncheck": {"go-reachability", "go-reach"},
	"jsreach":     {"js-reachability", "npm-reachability", "js-reach"},
	"pyreach":     {"python-reachability", "py-reach"},
	"jvmreach":    {"jvm-reachability", "java-reach"},
}

var builtInDisplayNames = map[string]string{
	detectors.NameNPM:           "npm Detector",
	detectors.NamePNPM:          "pnpm Detector",
	detectors.NameYarn:          "Yarn Detector",
	detectors.NameBun:           "Bun Detector",
	detectors.NameBunNative:     "Bun Native Detector",
	detectors.NameGradle:        "Gradle Detector",
	detectors.NameMaven:         "Maven Detector",
	detectors.NameGoMod:         "Go Module Detector",
	detectors.NameComposer:      "Composer Detector",
	detectors.NameBundler:       "Bundler Detector",
	detectors.NameGitHubActions: "GitHub Actions Detector",
	detectors.NamePip:           "pip Detector",
	detectors.NamePipenv:        "Pipenv Detector",
	detectors.NamePoetry:        "Poetry Detector",
	detectors.NameUV:            "uv Detector",
	detectors.NameNuGet:         "NuGet Detector",
	detectors.NameCargo:         "Cargo Detector",
	detectors.NamePub:           "Pub Detector",
	detectors.NamePubNative:     "Pub Native Detector",
	detectors.NameCocoaPods:     "CocoaPods Detector",
	detectors.NameSwiftPM:       "SwiftPM Detector",
	detectors.NameSwiftPMNative: "SwiftPM Native Detector",
	detectors.NameMix:           "Mix Detector",
	detectors.NameConan:         "Conan Detector",
	detectors.NameSBT:           "sbt Detector",
	detectors.NameSBTNative:     "sbt Native Detector",
	detectors.NameSBOM:          "SBOM Detector",
	detectors.NameSyft:          "Syft Detector",
	"license":                   "License Auditor",
	"package":                   "Package Auditor",
	"vulnerability":             "Vulnerability Auditor",
	"govulncheck":               "govulncheck",
	"jsreach":                   "JavaScript Reachability",
	"pyreach":                   "Python Reachability",
	"jvmreach":                  "JVM Reachability",
}

func componentKey(kind sdk.PluginKind, name string) string {
	return string(kind) + ":" + strings.TrimSpace(name)
}

func detectorOriginForRegistry(detector sdk.Detector) sdk.DetectorOrigin {
	if detector == nil {
		return sdk.CoreOrigin
	}
	name := detector.Descriptor().Name
	if name == detectors.NameSyft {
		return sdk.BundledOrigin
	}
	if origin := DetectorOriginForName(name); origin != "" {
		return origin
	}
	return sdk.CoreOrigin
}

func builtInDetectorsByName(logger *zap.Logger, pluginConfigs config.PluginConfigs) map[string]sdk.Detector {
	syftPrimary := syft.Detector{
		Logger:              logger,
		SupportedManagers:   SupportedPackageManagersForDetector(detectors.NameSyft),
		SupportedEcosystems: SupportedEcosystemsForDetector(detectors.NameSyft),
	}
	sbomDetector := sbomdetector.Detector{Logger: logger}
	npmDetector := npm.Detector{Logger: logger, Config: nodeStrategyConfigFor(logger, pluginConfigs, detectors.NameNPM)}
	pnpmDetector := pnpm.Detector{Logger: logger, Config: nodeStrategyConfigFor(logger, pluginConfigs, detectors.NamePNPM)}
	yarnDetector := yarn.Detector{Logger: logger, Config: nodeStrategyConfigFor(logger, pluginConfigs, detectors.NameYarn)}
	bunNativeDetector := bun.NativeDetector{Logger: logger}
	bunDetector := bun.LockfileDetector{Logger: logger}
	gradleDetector := gradle.Detector{Logger: logger}
	mavenDetector := maven.Detector{Logger: logger}
	goDetector := gomod.Detector{Logger: logger}
	composerDetector := composer.Detector{Logger: logger}
	bundlerDetector := ruby.Detector{Logger: logger}
	githubActionsDetector := githubactions.Detector{}
	pipDetector := python.PipDetector{Logger: logger}
	pipenvDetector := python.PipenvDetector{Logger: logger}
	poetryDetector := python.PoetryDetector{Logger: logger}
	uvDetector := python.UVDetector{Logger: logger}
	nugetDetector := nuget.Detector{Logger: logger}
	cargoDetector := cargo.Detector{Logger: logger}
	pubDetector := pub.Detector{Logger: logger}
	pubNativeDetector := pub.NativeDetector{Logger: logger}
	cocoaPodsDetector := cocoapods.Detector{Logger: logger}
	swiftPMDetector := swiftpm.Detector{Logger: logger}
	swiftPMNativeDetector := swiftpm.NativeDetector{Logger: logger}
	mixDetector := mix.Detector{Logger: logger}
	conanDetector := conan.Detector{Logger: logger}
	sbtDetector := sbt.Detector{Logger: logger}
	sbtNativeDetector := sbt.NativeDetector{Logger: logger}

	return map[string]sdk.Detector{
		sbomDetector.Descriptor().Name:          sbomDetector,
		npmDetector.Descriptor().Name:           npmDetector,
		pnpmDetector.Descriptor().Name:          pnpmDetector,
		yarnDetector.Descriptor().Name:          yarnDetector,
		bunDetector.Descriptor().Name:           bunDetector,
		bunNativeDetector.Descriptor().Name:     bunNativeDetector,
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
		pubNativeDetector.Descriptor().Name:     pubNativeDetector,
		cocoaPodsDetector.Descriptor().Name:     cocoaPodsDetector,
		swiftPMDetector.Descriptor().Name:       swiftPMDetector,
		swiftPMNativeDetector.Descriptor().Name: swiftPMNativeDetector,
		mixDetector.Descriptor().Name:           mixDetector,
		conanDetector.Descriptor().Name:         conanDetector,
		sbtDetector.Descriptor().Name:           sbtDetector,
		sbtNativeDetector.Descriptor().Name:     sbtNativeDetector,
		syftPrimary.Descriptor().Name:           syftPrimary,
	}
}

func builtInDetectors(detectors []sdk.Detector) []sdk.Detector {
	out := make([]sdk.Detector, 0, len(detectors))
	for _, detector := range detectors {
		if detector == nil {
			continue
		}
		out = append(out, detector)
	}
	return out
}

func builtInMatchers(matchers []sdk.Matcher) []sdk.Matcher {
	out := make([]sdk.Matcher, 0, len(matchers))
	for _, matcher := range matchers {
		if matcher == nil {
			continue
		}
		out = append(out, matcher)
	}
	return out
}

func builtInAuditors(auditors []sdk.Auditor) []sdk.Auditor {
	out := make([]sdk.Auditor, 0, len(auditors))
	for _, auditor := range auditors {
		if auditor == nil {
			continue
		}
		out = append(out, auditor)
	}
	return out
}
