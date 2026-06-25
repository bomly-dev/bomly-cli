// Package sdk is Bomly's public Go contract for dependency graphs, package
// enrichment, policy findings, and managed external plugins.
//
// Most external developers use this package to build a managed plugin. Managed
// plugins are native Go binaries that Bomly launches as separate subprocesses
// over the HashiCorp go-plugin gRPC transport. A plugin implements exactly one
// externally supported role:
//
//   - detector: reads project evidence and returns dependency graphs
//   - matcher: enriches PURL-keyed package records with vulnerability, license,
//     lifecycle, or other package metadata
//   - auditor: evaluates graph and registry data and emits findings or risk
//     scores
//
// Reachability analyzers are represented in the SDK for Bomly core and built-in
// analyzers, but external analyzer plugins are not currently supported by the
// managed plugin runtime.
//
// A plugin binary serves its role from main by calling one of the runtime
// entrypoints:
//
//	func main() {
//		sdk.ServeDetector(&detector{})
//	}
//
// The corresponding plugin-facing interfaces are ServedDetector, ServedMatcher,
// and ServedAuditor. They use the same request and response types as Bomly core:
// DetectionRequest and DetectionResult for detectors, MatchRequest and
// MatchResult for matchers, and AuditRequest and AuditResult for auditors.
//
// The central data model deliberately separates pipeline stages. Dependency is
// a detection-time graph node with identity, locations, scopes, and edges.
// PackageRegistry is a PURL-keyed set of deduplicated Package records that
// matchers enrich once per package version. Vulnerability records are
// OSV-aligned package enrichment data, including Bomly fields such as CVSS,
// EPSS, KEV, fixed versions, affected symbols, and reachability. Finding is a
// reference-style audit result: it points back to packages by PURL and, for
// vulnerability findings, to Vulnerability.ID rather than copying the whole
// package or advisory payload.
//
// Coordinates is the shared embedded identity shape used by Dependency and
// Package. Plugin authors should prefer canonical PURLs, fill Coordinates where
// possible, and use typed values such as Ecosystem, PackageManager,
// PackageType, Scope, and SeverityLevel instead of raw strings. PackageManager
// is string-backed for compatibility; use PackageManagerOther or a custom
// PackageManager value when Bomly does not yet have a first-class constant for
// a package manager.
//
// Plugin identity is split across package metadata and runtime metadata. The
// bomly-plugin.json manifest describes packaging and install fields such as ID,
// version, kind, runtime, plugin API version, entrypoint, homepage, and license.
// The runtime descriptor returned by Descriptor describes the served component:
// name, display name, aliases, tags, supported ecosystems, supported package
// managers, and role-specific behavior. Bomly verifies that manifest identity
// and runtime descriptor identity match when a packaged plugin is installed, and
// records installed trust state separately.
//
// Plugins that need configuration should read only their per-plugin config with
// DecodePluginConfigFromEnv. Plugins that make HTTP calls should create a
// process-local provider with NewHTTPClientProviderFromEnv so Bomly's proxy,
// no-proxy, and CA certificate settings are honored consistently.
//
// The repository documentation contains the workflow-oriented guides for
// packaging, installing, testing, and distributing plugins. This package
// documentation is the API-oriented reference for the types those guides use.
package sdk
