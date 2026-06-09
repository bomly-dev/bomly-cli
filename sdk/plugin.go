package sdk

// PluginAPIVersion is the current managed plugin API contract version.
const PluginAPIVersion = "bomly.plugin.v1"

// PackageManifestSchemaVersion is the package manifest schema version.
const PackageManifestSchemaVersion = "bomly.plugin.package.v1"

// InstalledPluginsSchemaVersion is the installed plugin database schema version.
const InstalledPluginsSchemaVersion = "bomly.installed-plugins.v1"

// RuntimeDescriptorSnapshotSchemaVersion is Bomly's internal installed descriptor snapshot schema.
const RuntimeDescriptorSnapshotSchemaVersion = "bomly.plugin.runtime-descriptor.v1"

// RuntimeHashiCorpGRPC identifies the supported external plugin runtime.
const RuntimeHashiCorpGRPC = "hashicorp-grpc"

// PluginKind identifies the runtime role implemented by a plugin.
type PluginKind string

const (
	// PluginKindDetector resolves dependency graphs.
	PluginKindDetector PluginKind = "detector"
	// PluginKindMatcher enriches resolved packages.
	PluginKindMatcher PluginKind = "matcher"
	// PluginKindAuditor evaluates findings and risk.
	PluginKindAuditor PluginKind = "auditor"
	// PluginKindAnalyzer runs code analysis (e.g. reachability) over the
	// matched graph and annotates registry vulnerability entries.
	PluginKindAnalyzer PluginKind = "analyzer"
)

// PluginTargetType identifies the discovery target families a plugin supports.
type PluginTargetType string

// ReadyResponse reports whether a plugin is ready to run.
type ReadyResponse struct {
	Ready bool `json:"ready"`
}

// ApplicableResponse reports whether a plugin should run for the given request.
type ApplicableResponse struct {
	Applicable bool `json:"applicable"`
}

// InstallResponse reports install-first execution details.
type InstallResponse struct {
	Performed bool `json:"performed,omitempty"`
}
