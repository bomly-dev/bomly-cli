// Package config defines Bomly's resolved CLI configuration shape.
//
// The Resolved struct is the canonical declaration of every CLI flag, env
// var, and YAML config key. Tag conventions:
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
	Container             string   `doc:"Container image to scan (e.g. alpine:latest)" env:"BOMLY_CONTAINER"`
	URL                   string   `doc:"Remote Git URL to clone and scan" env:"BOMLY_URL"`
	Ref                   string   `doc:"Git ref to checkout when scanning a URL" env:"BOMLY_REF"`
	SBOM                  bool     `doc:"Treat the selected filesystem target as an SBOM file" env:"BOMLY_SBOM"`
	Enrich                bool     `doc:"Enrich packages with external license and vulnerability data" env:"BOMLY_ENRICH"`
	Audit                 bool     `doc:"Evaluate policy and create findings from package vulnerability data" env:"BOMLY_AUDIT"`
	Reachability          bool     `doc:"Run code analysis to confirm whether vulnerabilities are reachable from application code" env:"BOMLY_REACHABILITY"`
	FailOn                []string `doc:"Constraint(s) for which findings should be created. Repeatable; AND-ed. Severity: any|low|medium|high|critical. Reachability: reachable. Exploitability: exploitable" env:"BOMLY_FAIL_ON"`
	FailOnScopes          []string `doc:"Dependency scopes that may produce failing findings: runtime, development, unknown" env:"BOMLY_FAIL_ON_SCOPES"`
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
	Format                string   `doc:"Primary report format: text, json, markdown, or sarif" env:"BOMLY_FORMAT"`
	Outputs               []string `doc:"Additional output target(s) as <format> or <format>=<path>. Repeatable; formats include markdown, spdx, and cyclonedx" env:"BOMLY_OUTPUT"`
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

	// OSV matcher settings
	OsvAPIBase  string `doc:"Base URL for the OSV vulnerability API" env:"BOMLY_OSV_API_BASE" default:"https://api.osv.dev"`
	OsvCacheDir string `doc:"Directory for the OSV response cache" env:"BOMLY_OSV_CACHE_DIR"`
	OsvCacheTTL string `doc:"TTL for cached OSV responses (e.g. 24h)" env:"BOMLY_OSV_CACHE_TTL" default:"24h"`

	// KEV enrichment settings
	KEVCacheDir string `doc:"Directory for the CISA KEV cache" env:"BOMLY_KEV_CACHE_DIR"`
	KEVCacheTTL string `doc:"TTL for cached KEV data (e.g. 24h)" env:"BOMLY_KEV_CACHE_TTL" default:"24h"`

	// EOL enrichment settings
	EOLAPIBase  string `doc:"Base URL for the endoflife.date API" env:"BOMLY_EOL_API_BASE" default:"https://endoflife.date/api"`
	EOLCacheDir string `doc:"Directory for the EOL cache" env:"BOMLY_EOL_CACHE_DIR"`
	EOLCacheTTL string `doc:"TTL for cached EOL responses (e.g. 24h)" env:"BOMLY_EOL_CACHE_TTL" default:"24h"`

	// Scorecard matcher settings
	ScorecardAPIBase  string `doc:"Base URL for the OpenSSF Scorecard public API" env:"BOMLY_SCORECARD_API_BASE" default:"https://api.scorecard.dev"`
	ScorecardCacheDir string `doc:"Directory for the Scorecard response cache" env:"BOMLY_SCORECARD_CACHE_DIR"`
	ScorecardCacheTTL string `doc:"TTL for cached Scorecard responses (e.g. 24h)" env:"BOMLY_SCORECARD_CACHE_TTL" default:"24h"`
}

// File is the YAML-deserialized shape of a Bomly config file. The
// pointer-to-primitive fields let cli code distinguish "field absent" from
// "field set to zero value" when merging multiple config sources. The
// configref generator parses this struct's yaml tags to map each Resolved
// field to its corresponding YAML key in the reference docs.
type File struct {
	Path                  *string    `yaml:"path,omitempty"`
	Container             *string    `yaml:"container,omitempty"`
	URL                   *string    `yaml:"url,omitempty"`
	Ref                   *string    `yaml:"ref,omitempty"`
	SBOM                  *bool      `yaml:"sbom,omitempty"`
	Enrich                *bool      `yaml:"enrich,omitempty"`
	Audit                 *bool      `yaml:"audit,omitempty"`
	Reachability          *bool      `yaml:"reachability,omitempty"`
	FailOn                FailOnList `yaml:"fail_on,omitempty"`
	FailOnScopes          []string   `yaml:"fail_on_scopes,omitempty"`
	AllowVulnerabilityIDs []string   `yaml:"allow_vulnerability_ids,omitempty"`
	AllowLicenses         []string   `yaml:"allow_licenses,omitempty"`
	DenyLicenses          []string   `yaml:"deny_licenses,omitempty"`
	LicenseExemptPackages []string   `yaml:"license_exempt_packages,omitempty"`
	DenyPackages          []string   `yaml:"deny_packages,omitempty"`
	DenyGroups            []string   `yaml:"deny_groups,omitempty"`
	ProtectedPackages     []string   `yaml:"protected_packages,omitempty"`
	TyposquatThreshold    *string    `yaml:"typosquat_threshold,omitempty"`
	TyposquatMode         *string    `yaml:"typosquat_mode,omitempty"`
	WarnOnly              *bool      `yaml:"warn_only,omitempty"`
	Analyzers             *string    `yaml:"analyzers,omitempty"`
	Format                *string    `yaml:"format,omitempty"`
	Outputs               []string   `yaml:"outputs,omitempty"`
	Interactive           *bool      `yaml:"interactive,omitempty"`
	Ecosystems            *string    `yaml:"ecosystems,omitempty"`
	Detectors             *string    `yaml:"detectors,omitempty"`
	Auditors              *string    `yaml:"auditors,omitempty"`
	Matchers              *string    `yaml:"matchers,omitempty"`
	InstallFirst          *bool      `yaml:"install_first,omitempty"`
	InstallArgs           []string   `yaml:"install_args,omitempty"`
	Config                *string    `yaml:"config,omitempty"`
	Quiet                 *bool      `yaml:"quiet,omitempty"`
	Verbosity             *int       `yaml:"verbosity,omitempty"`
	Verbose               *bool      `yaml:"verbose,omitempty"`

	// OSV matcher settings
	OsvAPIBase  *string `yaml:"osv_api_base,omitempty"`
	OsvCacheDir *string `yaml:"osv_cache_dir,omitempty"`
	OsvCacheTTL *string `yaml:"osv_cache_ttl,omitempty"`

	// KEV enrichment settings
	KEVCacheDir *string `yaml:"kev_cache_dir,omitempty"`
	KEVCacheTTL *string `yaml:"kev_cache_ttl,omitempty"`

	// EOL enrichment settings
	EOLAPIBase  *string `yaml:"eol_api_base,omitempty"`
	EOLCacheDir *string `yaml:"eol_cache_dir,omitempty"`
	EOLCacheTTL *string `yaml:"eol_cache_ttl,omitempty"`

	// Scorecard matcher settings
	ScorecardAPIBase  *string `yaml:"scorecard_api_base,omitempty"`
	ScorecardCacheDir *string `yaml:"scorecard_cache_dir,omitempty"`
	ScorecardCacheTTL *string `yaml:"scorecard_cache_ttl,omitempty"`
}
