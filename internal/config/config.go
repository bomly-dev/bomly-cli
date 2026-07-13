// Package config defines Bomly's resolved CLI configuration shape.
//
// The Resolved struct is the canonical declaration of every runtime config
// value and environment override. The nested File structs declare YAML paths.
// Resolved tag conventions:
//
//   - `doc:"..."`     — human-readable description (rendered in docs/CONFIG_REFERENCE.md)
//   - `env:"..."`     — environment variable that sets the field
//   - `default:"..."` — default value when neither config nor flag is set
//
// The configref / schemajson / schemadocs generators (under
// internal/support/cmd/) parse this file's source to produce the published
// reference docs. If you change the path of this file, update those generators.
//
// CLI-level orchestration (flag binding, env merging, YAML loading, validation)
// remains in package cli — this package only owns the schema and the file
// shape consumed by it.
package config

// Resolved holds the fully-merged CLI configuration: defaults overridden by
// the YAML config file, then env vars, then explicit flags.
type Resolved struct {
	Path                  string   `doc:"Filesystem path to scan" env:"BOMLY_PATH"`
	Image                 string   `doc:"Container image to scan (e.g. alpine:latest)" env:"BOMLY_IMAGE" envalias:"BOMLY_CONTAINER"`
	URL                   string   `doc:"Remote Git URL to clone and scan" env:"BOMLY_URL"`
	Ref                   string   `doc:"Git ref to checkout when scanning a URL" env:"BOMLY_REF"`
	SBOM                  bool     `doc:"Treat the selected filesystem target as an SBOM file" env:"BOMLY_SBOM"`
	Recursive             bool     `doc:"Recursively discover nested manifests under the scan root" env:"BOMLY_RECURSIVE"`
	MaxDepth              int      `doc:"Maximum directory depth for recursive discovery, counted from the scan root (0 = unlimited)" env:"BOMLY_MAX_DEPTH" default:"3"`
	ExcludePaths          []string `doc:"Glob pattern(s) relative to the scan root excluded from recursive discovery, in addition to built-in ignore rules; requires recursive" env:"BOMLY_EXCLUDE"`
	Enrich                bool     `doc:"Enrich packages with external license and vulnerability data" env:"BOMLY_ENRICH"`
	Audit                 bool     `doc:"Evaluate policy and create findings from package vulnerability data" env:"BOMLY_AUDIT"`
	Analyze               bool     `doc:"Run code analysis to confirm whether vulnerabilities are reachable from application code" env:"BOMLY_ANALYZE"`
	FailOn                []string `doc:"Constraint(s) for which findings should be created. Repeatable; AND-ed. Severity: any|low|medium|high|critical. Reachability: reachable. Exploitability: exploitable" env:"BOMLY_FAIL_ON"`
	AllowVulnerabilityIDs []string `doc:"Vulnerability IDs to ignore during policy evaluation" env:"BOMLY_ALLOW_VULNERABILITY_IDS"`
	AllowLicenses         []string `doc:"Allowed SPDX license identifiers or expressions" env:"BOMLY_ALLOW_LICENSES"`
	DenyLicenses          []string `doc:"Denied SPDX license identifiers or expressions" env:"BOMLY_DENY_LICENSES"`
	LicenseExemptPackages []string `doc:"Package URLs exempt from license policy checks" env:"BOMLY_LICENSE_EXEMPT_PACKAGES"`
	DenyPackages          []string `doc:"Package URLs to deny" env:"BOMLY_DENY_PACKAGES"`
	DenyGroups            []string `doc:"Package URL namespaces to deny" env:"BOMLY_DENY_GROUPS"`
	ProtectedPackages     []string `doc:"Canonical package names to protect from typosquatting" env:"BOMLY_PROTECTED_PACKAGES"`
	TyposquatThreshold    string   `doc:"Similarity threshold for typosquatting detection" env:"BOMLY_TYPOSQUAT_THRESHOLD" default:"0.90"`
	TyposquatMode         string   `doc:"Typosquatting policy mode: warn or fail" env:"BOMLY_TYPOSQUAT_MODE" default:"warn"`
	WarnOnly              bool     `doc:"Downgrade failing findings to warnings" env:"BOMLY_WARN_ONLY"`
	Analyzers             string   `doc:"Reachability analyzer selectors; supports +name and -name modifiers" env:"BOMLY_ANALYZERS"`
	Format                string   `doc:"Primary output format: text, json, markdown, sarif, spdx, or cyclonedx. SBOM formats are scan-only" env:"BOMLY_FORMAT"`
	Outputs               []string `doc:"Additional output target(s) as <format> or <format>=<path>. Repeatable; supports text, json, markdown, sarif, spdx, and cyclonedx" env:"BOMLY_OUTPUT"`
	Interactive           bool     `doc:"Enable interactive TUI mode" env:"BOMLY_INTERACTIVE"`
	Ecosystems            string   `doc:"Ecosystem selectors; supports +name and -name modifiers" env:"BOMLY_ECOSYSTEMS"`
	Detectors             string   `doc:"Detector selectors; supports +name and -name modifiers" env:"BOMLY_DETECTORS"`
	Auditors              string   `doc:"Auditor selectors; supports +name and -name modifiers" env:"BOMLY_AUDITORS"`
	Matchers              string   `doc:"Matcher selectors; supports +name and -name modifiers" env:"BOMLY_MATCHERS"`
	InstallFirst          bool     `doc:"Run detector-specific dependency installation before resolving graphs" env:"BOMLY_INSTALL_FIRST"`
	InstallArgs           []string `doc:"Additional detector-specific install arguments" env:"BOMLY_INSTALL_ARGS"`
	Config                string   `doc:"Explicit YAML config file path" env:"BOMLY_CONFIG"`
	Quiet                 bool     `doc:"Suppress all non-error output" env:"BOMLY_QUIET"`
	Verbosity             int      `doc:"Verbosity level (0=normal, 1=verbose, 2+=debug)" env:"BOMLY_VERBOSE"`
	LoadedFiles           []string
	HTTPProxy             string                    `doc:"Outbound HTTP proxy URL used by Bomly and managed plugins" env:"BOMLY_HTTP_PROXY"`
	HTTPNoProxy           string                    `doc:"Comma-separated hosts, domains, or CIDRs that should bypass the outbound HTTP proxy" env:"BOMLY_HTTP_NO_PROXY"`
	HTTPProxyType         string                    `doc:"Outbound proxy type when using host/port proxy settings: http, https, or socks5" env:"BOMLY_HTTP_PROXY_TYPE" default:"http"`
	HTTPProxyHost         string                    `doc:"Outbound proxy hostname or IP address used when http_proxy is not set" env:"BOMLY_HTTP_PROXY_HOST"`
	HTTPProxyPort         int                       `doc:"Outbound proxy port used with http_proxy_host" env:"BOMLY_HTTP_PROXY_PORT"`
	HTTPProxyUsername     string                    `doc:"Username for proxy authentication when using host/port proxy settings" env:"BOMLY_HTTP_PROXY_USERNAME"`
	HTTPProxyPassword     string                    `doc:"Password for proxy authentication when using host/port proxy settings" env:"BOMLY_HTTP_PROXY_PASSWORD"`
	HTTPCACertFile        string                    `doc:"PEM certificate chain file to trust for outbound HTTPS connections, including TLS-intercepting proxies" env:"BOMLY_HTTP_CA_CERT_FILE"`
	Plugins               map[string]map[string]any `doc:"Per-plugin configuration keyed by managed plugin ID"`

	// OSV matcher settings
	OsvAPIBase  string `doc:"Base URL for the OSV vulnerability API" env:"BOMLY_OSV_API_BASE" default:"https://api.osv.dev"`
	OsvCacheDir string `doc:"Directory for the OSV response cache" env:"BOMLY_OSV_CACHE_DIR"`
	OsvCacheTTL string `doc:"TTL for cached OSV responses (e.g. 24h)" env:"BOMLY_OSV_CACHE_TTL" default:"24h"`

	// KEV enrichment settings
	KEVCacheDir string `doc:"Directory for the CISA KEV cache" env:"BOMLY_KEV_CACHE_DIR"`
	KEVCacheTTL string `doc:"TTL for cached KEV data (e.g. 24h)" env:"BOMLY_KEV_CACHE_TTL" default:"24h"`

	// Scorecard matcher settings
	ScorecardAPIBase  string `doc:"Base URL for the OpenSSF Scorecard public API" env:"BOMLY_SCORECARD_API_BASE" default:"https://api.scorecard.dev"`
	ScorecardCacheDir string `doc:"Directory for the Scorecard response cache" env:"BOMLY_SCORECARD_CACHE_DIR"`
	ScorecardCacheTTL string `doc:"TTL for cached Scorecard responses (e.g. 24h)" env:"BOMLY_SCORECARD_CACHE_TTL" default:"24h"`
}

// File is the nested YAML-deserialized shape of a Bomly config file. Leaf
// fields use pointers so merging can distinguish "field absent" from
// "field explicitly set to its zero value". The resolved tags map YAML leaves
// back to the flat runtime configuration, while legacy tags drive migration
// errors and generated documentation for the former flat YAML keys.
type File struct {
	Target     TargetFile                `yaml:"target,omitempty"`
	Pipeline   PipelineFile              `yaml:"pipeline,omitempty"`
	Components ComponentsFile            `yaml:"components,omitempty"`
	Policy     PolicyFile                `yaml:"policy,omitempty"`
	Output     OutputFile                `yaml:"output,omitempty"`
	Logging    LoggingFile               `yaml:"logging,omitempty"`
	Network    NetworkFile               `yaml:"network,omitempty"`
	Matchers   MatchersFile              `yaml:"matchers,omitempty"`
	Plugins    map[string]map[string]any `yaml:"plugins,omitempty" resolved:"Plugins"`
}

// TargetFile configures the execution target selected for a scan.
type TargetFile struct {
	Path      *string   `yaml:"path,omitempty" resolved:"Path" legacy:"path"`
	Container *string   `yaml:"container,omitempty" resolved:"Image" legacy:"container"` // deprecated alias for image
	Image     *string   `yaml:"image,omitempty" resolved:"Image" legacy:"image"`
	URL       *string   `yaml:"url,omitempty" resolved:"URL" legacy:"url"`
	Ref       *string   `yaml:"ref,omitempty" resolved:"Ref" legacy:"ref"`
	SBOM      *bool     `yaml:"sbom,omitempty" resolved:"SBOM" legacy:"sbom"`
	Recursive *bool     `yaml:"recursive,omitempty" resolved:"Recursive" legacy:"recursive"`
	MaxDepth  *int      `yaml:"max_depth,omitempty" resolved:"MaxDepth" legacy:"max_depth"`
	Exclude   *[]string `yaml:"exclude,omitempty" resolved:"ExcludePaths" legacy:"exclude"`
}

// PipelineFile configures optional pipeline behavior and dependency preparation.
type PipelineFile struct {
	Enrich       *bool     `yaml:"enrich,omitempty" resolved:"Enrich" legacy:"enrich"`
	Audit        *bool     `yaml:"audit,omitempty" resolved:"Audit" legacy:"audit"`
	Analyze      *bool     `yaml:"analyze,omitempty" resolved:"Analyze" legacy:"analyze"`
	InstallFirst *bool     `yaml:"install_first,omitempty" resolved:"InstallFirst" legacy:"install_first"`
	InstallArgs  *[]string `yaml:"install_args,omitempty" resolved:"InstallArgs" legacy:"install_args"`
}

// ComponentsFile configures component selection.
type ComponentsFile struct {
	Ecosystems *string `yaml:"ecosystems,omitempty" resolved:"Ecosystems" legacy:"ecosystems"`
	Detectors  *string `yaml:"detectors,omitempty" resolved:"Detectors" legacy:"detectors"`
	Auditors   *string `yaml:"auditors,omitempty" resolved:"Auditors" legacy:"auditors"`
	Matchers   *string `yaml:"matchers,omitempty" resolved:"Matchers" legacy:"matchers"`
	Analyzers  *string `yaml:"analyzers,omitempty" resolved:"Analyzers" legacy:"analyzers"`
}

// PolicyFile configures audit policy evaluation.
type PolicyFile struct {
	FailOn                *FailOnList `yaml:"fail_on,omitempty" resolved:"FailOn" legacy:"fail_on"`
	AllowVulnerabilityIDs *[]string   `yaml:"allow_vulnerability_ids,omitempty" resolved:"AllowVulnerabilityIDs" legacy:"allow_vulnerability_ids"`
	AllowLicenses         *[]string   `yaml:"allow_licenses,omitempty" resolved:"AllowLicenses" legacy:"allow_licenses"`
	DenyLicenses          *[]string   `yaml:"deny_licenses,omitempty" resolved:"DenyLicenses" legacy:"deny_licenses"`
	LicenseExemptPackages *[]string   `yaml:"license_exempt_packages,omitempty" resolved:"LicenseExemptPackages" legacy:"license_exempt_packages"`
	DenyPackages          *[]string   `yaml:"deny_packages,omitempty" resolved:"DenyPackages" legacy:"deny_packages"`
	DenyGroups            *[]string   `yaml:"deny_groups,omitempty" resolved:"DenyGroups" legacy:"deny_groups"`
	ProtectedPackages     *[]string   `yaml:"protected_packages,omitempty" resolved:"ProtectedPackages" legacy:"protected_packages"`
	TyposquatThreshold    *string     `yaml:"typosquat_threshold,omitempty" resolved:"TyposquatThreshold" legacy:"typosquat_threshold"`
	TyposquatMode         *string     `yaml:"typosquat_mode,omitempty" resolved:"TyposquatMode" legacy:"typosquat_mode"`
	WarnOnly              *bool       `yaml:"warn_only,omitempty" resolved:"WarnOnly" legacy:"warn_only"`
}

// OutputFile configures report rendering.
type OutputFile struct {
	Format      *string   `yaml:"format,omitempty" resolved:"Format" legacy:"format"`
	Outputs     *[]string `yaml:"outputs,omitempty" resolved:"Outputs" legacy:"outputs"`
	Interactive *bool     `yaml:"interactive,omitempty" resolved:"Interactive" legacy:"interactive"`
}

// LoggingFile configures CLI logging.
type LoggingFile struct {
	Quiet     *bool `yaml:"quiet,omitempty" resolved:"Quiet" legacy:"quiet"`
	Verbosity *int  `yaml:"verbosity,omitempty" resolved:"Verbosity" legacy:"verbosity"`
}

// NetworkFile configures outbound network behavior.
type NetworkFile struct {
	Proxy      ProxyFile `yaml:"proxy,omitempty"`
	CACertFile *string   `yaml:"ca_cert_file,omitempty" resolved:"HTTPCACertFile" legacy:"http_ca_cert_file"`
}

// ProxyFile configures the explicit outbound proxy.
type ProxyFile struct {
	URL      *string `yaml:"url,omitempty" resolved:"HTTPProxy" legacy:"http_proxy"`
	NoProxy  *string `yaml:"no_proxy,omitempty" resolved:"HTTPNoProxy" legacy:"http_no_proxy"`
	Type     *string `yaml:"type,omitempty" resolved:"HTTPProxyType" legacy:"http_proxy_type"`
	Host     *string `yaml:"host,omitempty" resolved:"HTTPProxyHost" legacy:"http_proxy_host"`
	Port     *int    `yaml:"port,omitempty" resolved:"HTTPProxyPort" legacy:"http_proxy_port"`
	Username *string `yaml:"username,omitempty" resolved:"HTTPProxyUsername" legacy:"http_proxy_username"`
	Password *string `yaml:"password,omitempty" resolved:"HTTPProxyPassword" legacy:"http_proxy_password"`
}

// MatchersFile configures built-in enrichment matchers.
type MatchersFile struct {
	OSV       OSVMatcherFile       `yaml:"osv,omitempty"`
	Scorecard ScorecardMatcherFile `yaml:"scorecard,omitempty"`
}

// OSVMatcherFile configures OSV vulnerability enrichment.
type OSVMatcherFile struct {
	APIBase  *string `yaml:"api_base,omitempty" resolved:"OsvAPIBase" legacy:"osv_api_base"`
	CacheDir *string `yaml:"cache_dir,omitempty" resolved:"OsvCacheDir" legacy:"osv_cache_dir"`
	CacheTTL *string `yaml:"cache_ttl,omitempty" resolved:"OsvCacheTTL" legacy:"osv_cache_ttl"`
	KEV      KEVFile `yaml:"kev,omitempty"`
}

// KEVFile configures CISA Known Exploited Vulnerabilities enrichment.
type KEVFile struct {
	CacheDir *string `yaml:"cache_dir,omitempty" resolved:"KEVCacheDir" legacy:"kev_cache_dir"`
	CacheTTL *string `yaml:"cache_ttl,omitempty" resolved:"KEVCacheTTL" legacy:"kev_cache_ttl"`
}

// ScorecardMatcherFile configures OpenSSF Scorecard enrichment.
type ScorecardMatcherFile struct {
	APIBase  *string `yaml:"api_base,omitempty" resolved:"ScorecardAPIBase" legacy:"scorecard_api_base"`
	CacheDir *string `yaml:"cache_dir,omitempty" resolved:"ScorecardCacheDir" legacy:"scorecard_cache_dir"`
	CacheTTL *string `yaml:"cache_ttl,omitempty" resolved:"ScorecardCacheTTL" legacy:"scorecard_cache_ttl"`
}
