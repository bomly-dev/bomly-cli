package registry

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bomly-dev/bomly-cli/internal/auditors/license"
	packageauditor "github.com/bomly-dev/bomly-cli/internal/auditors/package"
	"github.com/bomly-dev/bomly-cli/internal/auditors/vulnerability"
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
	"github.com/bomly-dev/bomly-cli/internal/matchers/clearlydefined"
	"github.com/bomly-dev/bomly-cli/internal/matchers/depsdev"
	"github.com/bomly-dev/bomly-cli/internal/matchers/eol"
	"github.com/bomly-dev/bomly-cli/internal/matchers/grype"
	osvmatcher "github.com/bomly-dev/bomly-cli/internal/matchers/osv"
	"github.com/bomly-dev/bomly-cli/internal/matchers/scorecard"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// RegistryConfigs holds built-in registry wiring options resolved by the CLI layer.
type RegistryConfigs struct {
	// FailOn is the parsed list of --fail-on constraints. The policy
	// auditor evaluates findings against this AND-set; an empty slice
	// preserves the historical behaviour of emitting every finding.
	FailOn                []sdk.FailOnConstraint
	FailOnScopes          []sdk.Scope
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
	EOLAPIBase            string
	EOLCacheDir           string
	EOLCacheTTL           string
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
}

// RegistryFilter narrows a registry down to the runtime-relevant selections.
type RegistryFilter struct {
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
	logger         *zap.Logger
	configs        RegistryConfigs
	detectors      []sdk.Detector
	auditors       []sdk.Auditor
	matchers       []sdk.Matcher
	analyzers      []sdk.Analyzer
	discoveryPlans map[string]DetectorDiscoveryPlan
	httpProvider   *sdk.HTTPClientProvider
}

// NewRegistry creates an empty registry.
func NewRegistry(configs RegistryConfigs, logger zap.Logger) *Registry {
	return &Registry{
		logger:         &logger,
		configs:        configs,
		discoveryPlans: make(map[string]DetectorDiscoveryPlan),
		httpProvider:   configs.HTTPClientProvider,
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
	for _, detector := range builtInDetectors(orderedBuiltInDetectors(r.logger)) {
		r.RegisterDetector(detector)
	}
}

// RegisterDetector adds a detector to the registry.
func (r *Registry) RegisterDetector(detector sdk.Detector) {
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
	r.registerScorecardMatcher()
}

func (r *Registry) registerGrypeMatcher() {
	for _, matcher := range builtInMatchers([]sdk.Matcher{grype.Matcher{Logger: r.logger}}) {
		r.RegisterMatcher(matcher)
	}
}

func (r *Registry) registerOSVMatcher() {
	osvCfg := osvmatcher.DefaultConfig()
	osvCfg.Logger = r.logger
	osvCfg.Client = r.httpClient(30 * time.Second)
	osvCfg.KEVClient = r.httpClient(15 * time.Second)
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
		for _, matcher := range builtInMatchers([]sdk.Matcher{osvMatcher}) {
			r.RegisterMatcher(matcher)
		}
	}
}

func (r *Registry) registerEOLMatcher() {
	eolCfg := eol.DefaultConfig()
	eolCfg.Logger = r.logger
	eolCfg.Client = r.httpClient(15 * time.Second)
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
		for _, matcher := range builtInMatchers([]sdk.Matcher{eolChecker}) {
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
	depsDevCfg.Client = r.httpClient(20 * time.Second)
	depsDevChecker, err := depsdev.New(depsDevCfg)
	if err != nil {
		r.logger.Warn("deps.dev license checker unavailable", zap.Error(err))
	} else {
		for _, matcher := range builtInMatchers([]sdk.Matcher{depsDevChecker}) {
			r.RegisterMatcher(matcher)
		}
		r.logger.Debug("deps.dev matcher configured")
	}
}

func (r *Registry) registerScorecardMatcher() {
	scoreCfg := scorecard.DefaultConfig()
	scoreCfg.Logger = r.logger
	if r.configs.ScorecardAPIBase != "" {
		scoreCfg.APIBase = r.configs.ScorecardAPIBase
	}
	if r.configs.ScorecardCacheDir != "" {
		scoreCfg.CacheDir = r.configs.ScorecardCacheDir
	}
	if r.configs.ScorecardCacheTTL != "" {
		if d, err := time.ParseDuration(r.configs.ScorecardCacheTTL); err == nil {
			scoreCfg.CacheTTL = d
		} else {
			r.logger.Warn("scorecard: invalid cache_ttl; using default", zap.String("value", r.configs.ScorecardCacheTTL), zap.Error(err))
		}
	}
	scoreCfg.ClientConfig = &scorecard.ClientConfig{
		APIBase:    scoreCfg.APIBase,
		Timeout:    15 * time.Second,
		HTTPClient: r.httpClient(15 * time.Second),
	}
	scoreMatcher, err := scorecard.New(scoreCfg)
	if err != nil {
		r.logger.Warn("scorecard matcher unavailable", zap.Error(err))
		return
	}
	for _, matcher := range builtInMatchers([]sdk.Matcher{scoreMatcher}) {
		r.RegisterMatcher(matcher)
	}
	r.logger.Debug("scorecard matcher configured",
		zap.String("api_base", scoreCfg.APIBase),
		zap.String("cache_dir", scoreCfg.CacheDir),
		zap.Duration("cache_ttl", scoreCfg.CacheTTL),
	)
}

func (r *Registry) registerClearlyDefinedMatcher() {
	clearlyDefinedCfg := clearlydefined.DefaultConfig()
	clearlyDefinedCfg.Logger = r.logger
	clearlyDefinedCfg.Client = r.httpClient(20 * time.Second)
	clearlyDefinedChecker, err := clearlydefined.New(clearlyDefinedCfg)
	if err != nil {
		r.logger.Warn("ClearlyDefined license checker unavailable", zap.Error(err))
	} else {
		for _, matcher := range builtInMatchers([]sdk.Matcher{clearlyDefinedChecker}) {
			r.RegisterMatcher(matcher)
		}
		r.logger.Debug("ClearlyDefined matcher configured")
	}
}

func (r *Registry) httpClient(timeout time.Duration) *http.Client {
	return r.httpClientProvider().Client(timeout)
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
	if matcher == nil {
		return
	}
	r.matchers = append(r.matchers, matcher)
}

// registerAnalyzers wires the built-in reachability analyzers. Concrete
// analyzers are registered by separate methods so plugins (and lite builds)
// can opt out via build tags.
func (r *Registry) registerAnalyzers() {
	r.registerGovulncheckAnalyzer()
	r.registerJSReachAnalyzer()
	r.registerPyReachAnalyzer()
	r.registerJVMReachAnalyzer()
}

// registerGovulncheckAnalyzer is provided by analyzers_govulncheck.go so the
// registry package can stay free of analyzer dependencies (they pull in
// golang.org/x/vuln in the builtin build).

// RegisterAnalyzer adds an analyzer to the registry.
func (r *Registry) RegisterAnalyzer(analyzer sdk.Analyzer) {
	if analyzer == nil {
		return
	}
	r.analyzers = append(r.analyzers, analyzer)
}

func (r *Registry) registerAuditors() {
	threshold, _ := strconv.ParseFloat(strings.TrimSpace(r.configs.TyposquatThreshold), 64)
	if threshold == 0 {
		threshold = 0.90
	}
	for _, auditor := range builtInAuditors([]sdk.Auditor{
		vulnerability.Auditor{
			FailOn:                append([]sdk.FailOnConstraint(nil), r.configs.FailOn...),
			FailOnScopes:          append([]sdk.Scope(nil), r.configs.FailOnScopes...),
			AllowVulnerabilityIDs: append([]string(nil), r.configs.AllowVulnerabilityIDs...),
		},
		license.Auditor{
			AllowLicenses:  append([]string(nil), r.configs.AllowLicenses...),
			DenyLicenses:   append([]string(nil), r.configs.DenyLicenses...),
			ExemptPackages: append([]string(nil), r.configs.LicenseExemptPackages...),
			FailOnScopes:   append([]sdk.Scope(nil), r.configs.FailOnScopes...),
		},
		packageauditor.Auditor{
			DenyPackages:       append([]string(nil), r.configs.DenyPackages...),
			DenyGroups:         append([]string(nil), r.configs.DenyGroups...),
			ProtectedPackages:  append([]string(nil), r.configs.ProtectedPackages...),
			TyposquatThreshold: threshold,
			TyposquatMode:      r.configs.TyposquatMode,
			FailOnScopes:       append([]sdk.Scope(nil), r.configs.FailOnScopes...),
		},
	}) {
		r.RegisterAuditor(auditor)
	}
}

// RegisterAuditor adds an auditor to the registry.
func (r *Registry) RegisterAuditor(auditor sdk.Auditor) {
	if auditor == nil {
		return
	}
	r.auditors = append(r.auditors, auditor)
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
		if !detectorSelected(req.DetectorFilter, descriptor) {
			continue
		}
		if req.Ecosystem != sdk.EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != sdk.PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
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
func (r *Registry) PlannedDetectors(req sdk.DetectionRequest, names []string) []sdk.Detector {
	if len(names) == 0 {
		return r.Detectors(req)
	}

	available := make(map[string]sdk.Detector, len(r.detectors))
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

// Analyzers returns the analyzers that apply to the request, filtered by
// include/exclude selectors, ecosystem, package manager, language, and mode.
// Empty SupportedLanguages on a descriptor means "applies to any language".
func (r *Registry) Analyzers(req sdk.AnalyzeRequest) []sdk.Analyzer {
	matches := make([]sdk.Analyzer, 0, len(r.analyzers))
	for _, analyzer := range r.analyzers {
		descriptor := analyzer.Descriptor()
		if !analyzerSelected(req.AnalyzerFilter, descriptor) {
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
		if !supportsMode(descriptor.SupportedModes, req.Mode) {
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
		if !matcherSelected(req.MatcherFilter, descriptor) {
			continue
		}
		if req.Ecosystem != sdk.EcosystemUnknown && !supportsEcosystem(descriptor.SupportedEcosystems, req.Ecosystem) {
			continue
		}
		if req.PackageManager != sdk.PackageManagerUnknown && !supportsPackageManager(descriptor.SupportedManagers, req.PackageManager) {
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
	filtered.httpProvider = r.httpProvider

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

	for _, analyzer := range r.analyzers {
		descriptor := analyzer.Descriptor()
		if !analyzerSelected(filter.AnalyzerFilter, descriptor) {
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

func supportsMode(supported []sdk.TargetMode, mode sdk.TargetMode) bool {
	for _, candidate := range supported {
		if candidate == mode {
			return true
		}
	}
	return false
}

func detectorSelected(filter sdk.DetectorFilter, descriptor sdk.DetectorDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return descriptor.Enabled
}

func auditorSelected(filter sdk.AuditorFilter, descriptor sdk.AuditorDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return descriptor.Enabled
}

func matcherSelected(filter sdk.MatcherFilter, descriptor sdk.MatcherDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	// Operator-mode (--matchers +name / -name) populates Exclude with the
	// catalog minus the resolved selection. Anything not in Exclude must run,
	// including default-off matchers the user opted in with +name. Without
	// this branch, falling through to descriptor.Enabled would silently drop
	// default-off matchers even though the user explicitly asked for them.
	if len(filter.Exclude) > 0 {
		return true
	}
	return descriptor.Enabled
}

func analyzerSelected(filter sdk.AnalyzerFilter, descriptor sdk.AnalyzerDescriptor) bool {
	if filter.Excludes(descriptor.Name) {
		return false
	}
	if len(filter.Include) > 0 {
		return filter.Includes(descriptor.Name)
	}
	return descriptor.Enabled
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

func orderedBuiltInDetectors(logger *zap.Logger) []sdk.Detector {
	detectorsByName := builtInDetectorsByName(logger)
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
		return componentPriority(ordered[i].Descriptor().Origin, ordered[i].Descriptor().Technique) < componentPriority(ordered[j].Descriptor().Origin, ordered[j].Descriptor().Technique)
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

func builtInDetectorsByName(logger *zap.Logger) map[string]sdk.Detector {
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
	pubNativeDetector := pub.NativeDetector{Logger: logger, Fallback: pubDetector}
	cocoaPodsDetector := cocoapods.Detector{Logger: logger, Fallback: syftFallback}
	swiftPMDetector := swiftpm.Detector{Logger: logger, Fallback: syftFallback}
	swiftPMNativeDetector := swiftpm.NativeDetector{Logger: logger, Fallback: swiftPMDetector}
	mixDetector := mix.Detector{Logger: logger, Fallback: syftFallback}
	conanDetector := conan.Detector{Logger: logger, Fallback: syftFallback}
	sbtDetector := sbt.Detector{Logger: logger, Fallback: syftFallback}
	sbtNativeDetector := sbt.NativeDetector{Logger: logger, Fallback: sbtDetector}

	return map[string]sdk.Detector{
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
