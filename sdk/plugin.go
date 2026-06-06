package sdk

// PluginAPIVersion is the current managed plugin API contract version.
const PluginAPIVersion = "bomly.plugin.v1"

// PackageManifestSchemaVersion is the package manifest schema version.
const PackageManifestSchemaVersion = "bomly.plugin.package.v1"

// InstalledPluginsSchemaVersion is the installed plugin database schema version.
const InstalledPluginsSchemaVersion = "bomly.installed-plugins.v1"

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

const (
	// PluginTargetTypeDirectory marks local directory support.
	PluginTargetTypeDirectory PluginTargetType = "directory"
	// PluginTargetTypeRepository marks git repository support.
	PluginTargetTypeRepository PluginTargetType = "repository"
	// PluginTargetTypeContainer marks container image support.
	PluginTargetTypeContainer PluginTargetType = "container"
	// PluginTargetTypeSBOM marks SBOM file support.
	PluginTargetTypeSBOM PluginTargetType = "sbom"
)

// PluginMetadata describes the runtime metadata exposed by a plugin binary.
type PluginMetadata struct {
	ID               string     `json:"id"`
	Kind             PluginKind `json:"kind"`
	PluginAPIVersion string     `json:"pluginApiVersion"`
}

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
