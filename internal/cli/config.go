package cli

//go:generate go run config_gen.go

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly/bomly-cli/internal/system"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type resolvedConfig struct {
	Path         string   `doc:"Filesystem path to scan" env:"BOMLY_PATH"`
	Container    string   `doc:"Container image to scan (e.g. alpine:latest)" env:"BOMLY_CONTAINER"`
	URL          string   `doc:"Remote Git URL to clone and scan" env:"BOMLY_URL"`
	Ref          string   `doc:"Git ref to checkout when scanning a URL" env:"BOMLY_REF"`
	SBOM         bool     `doc:"Treat the selected filesystem target as an SBOM file" env:"BOMLY_SBOM"`
	Audit        bool     `doc:"Enable vulnerability auditing" env:"BOMLY_AUDIT"`
	Format       string   `doc:"Primary report format: text, json, or sarif" env:"BOMLY_FORMAT"`
	Interactive  bool     `doc:"Enable interactive TUI mode" env:"BOMLY_INTERACTIVE"`
	Ecosystems   string   `doc:"Ecosystem selectors; supports +name and -name modifiers" env:"BOMLY_ECOSYSTEMS"`
	Detectors    string   `doc:"Detector selectors; supports +name and -name modifiers" env:"BOMLY_DETECTORS"`
	Auditors     string   `doc:"Auditor selectors; supports +name and -name modifiers" env:"BOMLY_AUDITORS"`
	Matchers     string   `doc:"Matcher selectors; supports +name and -name modifiers" env:"BOMLY_MATCHERS"`
	InstallFirst bool     `doc:"Run detector-specific dependency installation before resolving graphs" env:"BOMLY_INSTALL_FIRST"`
	InstallArgs  []string `doc:"Additional detector-specific install arguments" env:"BOMLY_INSTALL_ARGS"`
	Recursive    bool     `doc:"Recursively discover supported subprojects under the target path" env:"BOMLY_RECURSIVE"`
	Config       string   `doc:"Explicit YAML config file path" env:"BOMLY_CONFIG"`
	Quiet        bool     `doc:"Suppress all non-error output" env:"BOMLY_QUIET"`
	Verbosity    int      `doc:"Verbosity level (0=normal, 1=verbose, 2+=debug)" env:"BOMLY_VERBOSE"`
	LoadedFiles  []string

	// HTTP / external service settings
	HTTPProxy string `doc:"HTTP proxy URL for outbound requests" env:"BOMLY_HTTP_PROXY"`

	// OSV auditor settings
	OsvAPIBase  string `doc:"Base URL for the OSV vulnerability API" env:"BOMLY_OSV_API_BASE" default:"https://api.osv.dev"`
	OsvCacheDir string `doc:"Directory for the OSV response cache" env:"BOMLY_OSV_CACHE_DIR"`
	OsvCacheTTL string `doc:"TTL for cached OSV responses (e.g. 24h)" env:"BOMLY_OSV_CACHE_TTL" default:"24h"`

	// KEV auditor settings
	KEVCacheDir string `doc:"Directory for the CISA KEV cache" env:"BOMLY_KEV_CACHE_DIR"`
	KEVCacheTTL string `doc:"TTL for cached KEV data (e.g. 24h)" env:"BOMLY_KEV_CACHE_TTL" default:"24h"`

	// EOL enrichment settings
	EOLAPIBase  string `doc:"Base URL for the endoflife.date API" env:"BOMLY_EOL_API_BASE" default:"https://endoflife.date/api"`
	EOLCacheDir string `doc:"Directory for the EOL cache" env:"BOMLY_EOL_CACHE_DIR"`
	EOLCacheTTL string `doc:"TTL for cached EOL responses (e.g. 24h)" env:"BOMLY_EOL_CACHE_TTL" default:"24h"`
}

type fileConfig struct {
	Path         *string  `yaml:"path,omitempty"`
	Container    *string  `yaml:"container,omitempty"`
	URL          *string  `yaml:"url,omitempty"`
	Ref          *string  `yaml:"ref,omitempty"`
	SBOM         *bool    `yaml:"sbom,omitempty"`
	Audit        *bool    `yaml:"audit,omitempty"`
	Format       *string  `yaml:"format,omitempty"`
	Interactive  *bool    `yaml:"interactive,omitempty"`
	Ecosystems   *string  `yaml:"ecosystems,omitempty"`
	Detectors    *string  `yaml:"detectors,omitempty"`
	Auditors     *string  `yaml:"auditors,omitempty"`
	Matchers     *string  `yaml:"matchers,omitempty"`
	InstallFirst *bool    `yaml:"install_first,omitempty"`
	InstallArgs  []string `yaml:"install_args,omitempty"`
	Recursive    *bool    `yaml:"recursive,omitempty"`
	Config       *string  `yaml:"config,omitempty"`
	Quiet        *bool    `yaml:"quiet,omitempty"`
	Verbosity    *int     `yaml:"verbosity,omitempty"`
	Verbose      *bool    `yaml:"verbose,omitempty"`

	// HTTP / external service settings
	HTTPProxy *string `yaml:"http_proxy,omitempty"`

	// OSV auditor settings
	OsvAPIBase  *string `yaml:"osv_api_base,omitempty"`
	OsvCacheDir *string `yaml:"osv_cache_dir,omitempty"`
	OsvCacheTTL *string `yaml:"osv_cache_ttl,omitempty"`

	// KEV auditor settings
	KEVCacheDir *string `yaml:"kev_cache_dir,omitempty"`
	KEVCacheTTL *string `yaml:"kev_cache_ttl,omitempty"`

	// EOL enrichment settings
	EOLAPIBase  *string `yaml:"eol_api_base,omitempty"`
	EOLCacheDir *string `yaml:"eol_cache_dir,omitempty"`
	EOLCacheTTL *string `yaml:"eol_cache_ttl,omitempty"`
}

func (o *globalOptions) initialize(cmd *cobra.Command) error {
	cfg, err := o.loadResolvedConfig(cmd)
	if err != nil {
		return err
	}
	o.resolved = &cfg
	return nil
}

func (o *globalOptions) current() resolvedConfig {
	if o.resolved != nil {
		return *o.resolved
	}
	return resolvedConfig{
		Path:         o.Path,
		Container:    o.Container,
		URL:          o.URL,
		Ref:          o.Ref,
		SBOM:         o.SBOM,
		Audit:        o.Audit,
		Format:       o.Format,
		Interactive:  o.Interactive,
		Ecosystems:   o.Ecosystems,
		Detectors:    o.Detectors,
		Auditors:     o.Auditors,
		Matchers:     o.Matchers,
		InstallFirst: o.InstallFirst,
		InstallArgs:  append([]string(nil), o.InstallArgs...),
		Recursive:    o.Recursive,
		Config:       o.Config,
		Quiet:        o.Quiet,
		Verbosity:    o.Verbosity,
		HTTPProxy:    o.HTTPProxy,
		OsvAPIBase:   o.OsvAPIBase,
		OsvCacheDir:  o.OsvCacheDir,
		OsvCacheTTL:  o.OsvCacheTTL,
		KEVCacheDir:  o.KEVCacheDir,
		KEVCacheTTL:  o.KEVCacheTTL,
		EOLAPIBase:   o.EOLAPIBase,
		EOLCacheDir:  o.EOLCacheDir,
		EOLCacheTTL:  o.EOLCacheTTL,
	}
}

func (o *globalOptions) loadResolvedConfig(cmd *cobra.Command) (resolvedConfig, error) {
	resolved := o.current()

	configPaths, err := o.configLoadPaths()
	if err != nil {
		return resolvedConfig{}, err
	}
	for _, path := range configPaths {
		fileCfg, err := loadConfigFile(path)
		if err != nil {
			return resolvedConfig{}, invalidInputf("load config %q: %v", path, err)
		}
		if fileCfg == nil {
			continue
		}
		applyFileConfig(&resolved, *fileCfg)
		resolved.LoadedFiles = append(resolved.LoadedFiles, path)
	}

	applyEnvOverrides(&resolved)
	applyFlagOverrides(&resolved, o, cmd)
	if err := validateResolvedConfig(resolved); err != nil {
		return resolvedConfig{}, err
	}
	return resolved, nil
}

func (o *globalOptions) configLoadPaths() ([]string, error) {
	paths := make([]string, 0, 3)

	homePath, err := userConfigPath()
	if err != nil {
		return nil, err
	}
	if homePath != "" {
		paths = append(paths, homePath)
	}

	projectPath, err := o.projectConfigPathForLoading()
	if err != nil {
		return nil, err
	}
	if projectPath != "" && projectPath != homePath {
		paths = append(paths, projectPath)
	}

	if strings.TrimSpace(o.Config) != "" {
		explicitPath, err := system.Abs(o.Config)
		if err != nil {
			return nil, invalidInputf("resolve config path %q: %v", o.Config, err)
		}
		if explicitPath != homePath && explicitPath != projectPath {
			paths = append(paths, explicitPath)
		}
	}

	return paths, nil
}

func userConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		if strings.TrimSpace(err.Error()) == "" {
			return "", nil
		}
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	if strings.TrimSpace(home) == "" {
		return "", nil
	}
	return filepath.Join(home, ".bomly", "config.yaml"), nil
}

func (o *globalOptions) projectConfigPathForLoading() (string, error) {
	if strings.TrimSpace(o.URL) != "" || strings.TrimSpace(o.Container) != "" {
		return "", nil
	}

	projectRoot := strings.TrimSpace(o.Path)
	if projectRoot == "" {
		cwd, err := system.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve cwd for config discovery: %w", err)
		}
		projectRoot = cwd
	}

	absPath, err := system.Abs(projectRoot)
	if err != nil {
		return "", invalidInputf("resolve project config path %q: %v", projectRoot, err)
	}
	info, err := os.Stat(absPath)
	if err == nil && !info.IsDir() {
		absPath = filepath.Dir(absPath)
	}
	return filepath.Join(absPath, ".bomly", "config.yaml"), nil
}

func loadConfigFile(path string) (*fileConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg fileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	baseDir := filepath.Dir(path)
	normalizeFileConfigPaths(&cfg, baseDir)
	return &cfg, nil
}

func normalizeFileConfigPaths(cfg *fileConfig, baseDir string) {
	if cfg == nil {
		return
	}
	for _, target := range []*string{cfg.Path, cfg.Config} {
		if target == nil || strings.TrimSpace(*target) == "" {
			continue
		}
		if filepath.IsAbs(*target) {
			continue
		}
		*target = filepath.Clean(filepath.Join(baseDir, *target))
	}
}

func applyFileConfig(dst *resolvedConfig, src fileConfig) {
	if dst == nil {
		return
	}
	if src.Path != nil {
		dst.Path = *src.Path
	}
	if src.Container != nil {
		dst.Container = *src.Container
	}
	if src.URL != nil {
		dst.URL = *src.URL
	}
	if src.Ref != nil {
		dst.Ref = *src.Ref
	}
	if src.SBOM != nil {
		dst.SBOM = *src.SBOM
	}
	if src.Audit != nil {
		dst.Audit = *src.Audit
	}
	if src.Format != nil {
		dst.Format = *src.Format
	}
	if src.Interactive != nil {
		dst.Interactive = *src.Interactive
	}
	if src.Ecosystems != nil {
		dst.Ecosystems = *src.Ecosystems
	}
	if src.Detectors != nil {
		dst.Detectors = *src.Detectors
	}
	if src.Auditors != nil {
		dst.Auditors = *src.Auditors
	}
	if src.Matchers != nil {
		dst.Matchers = *src.Matchers
	}
	if src.InstallFirst != nil {
		dst.InstallFirst = *src.InstallFirst
	}
	if len(src.InstallArgs) > 0 {
		dst.InstallArgs = append([]string(nil), src.InstallArgs...)
	}
	if src.Recursive != nil {
		dst.Recursive = *src.Recursive
	}
	if src.Config != nil {
		dst.Config = *src.Config
	}
	if src.Quiet != nil {
		dst.Quiet = *src.Quiet
	}
	if src.Verbosity != nil {
		dst.Verbosity = *src.Verbosity
	}
	if src.Verbose != nil && *src.Verbose && dst.Verbosity == 0 {
		dst.Verbosity = 1
	}
	if src.HTTPProxy != nil {
		dst.HTTPProxy = *src.HTTPProxy
	}
	if src.OsvAPIBase != nil {
		dst.OsvAPIBase = *src.OsvAPIBase
	}
	if src.OsvCacheDir != nil {
		dst.OsvCacheDir = *src.OsvCacheDir
	}
	if src.OsvCacheTTL != nil {
		dst.OsvCacheTTL = *src.OsvCacheTTL
	}
	if src.KEVCacheDir != nil {
		dst.KEVCacheDir = *src.KEVCacheDir
	}
	if src.KEVCacheTTL != nil {
		dst.KEVCacheTTL = *src.KEVCacheTTL
	}
	if src.EOLAPIBase != nil {
		dst.EOLAPIBase = *src.EOLAPIBase
	}
	if src.EOLCacheDir != nil {
		dst.EOLCacheDir = *src.EOLCacheDir
	}
	if src.EOLCacheTTL != nil {
		dst.EOLCacheTTL = *src.EOLCacheTTL
	}
}

func applyFlagOverrides(dst *resolvedConfig, src *globalOptions, cmd *cobra.Command) {
	if dst == nil || src == nil || cmd == nil {
		return
	}
	overrideString := func(name, value string, target *string) {
		if flagChanged(cmd, name) {
			*target = value
		}
	}
	overrideBool := func(name string, value bool, target *bool) {
		if flagChanged(cmd, name) {
			*target = value
		}
	}

	overrideString("path", src.Path, &dst.Path)
	overrideString("container", src.Container, &dst.Container)
	overrideString("url", src.URL, &dst.URL)
	overrideString("ref", src.Ref, &dst.Ref)
	overrideBool("sbom", src.SBOM, &dst.SBOM)
	overrideBool("audit", src.Audit, &dst.Audit)
	overrideString("format", src.Format, &dst.Format)
	overrideBool("interactive", src.Interactive, &dst.Interactive)
	overrideString("ecosystems", src.Ecosystems, &dst.Ecosystems)
	overrideString("detectors", src.Detectors, &dst.Detectors)
	overrideString("auditors", src.Auditors, &dst.Auditors)
	overrideString("matchers", src.Matchers, &dst.Matchers)
	overrideBool("install-first", src.InstallFirst, &dst.InstallFirst)
	if flagChanged(cmd, "install-arg") {
		dst.InstallArgs = append([]string(nil), src.InstallArgs...)
	}
	overrideString("config", src.Config, &dst.Config)
	overrideBool("recursive", src.Recursive, &dst.Recursive)
	overrideBool("quiet", src.Quiet, &dst.Quiet)
	if flagChanged(cmd, "verbose") {
		dst.Verbosity = src.Verbosity
	}
}

func applyEnvOverrides(dst *resolvedConfig) {
	if dst == nil {
		return
	}
	overrideString := func(key string, target *string) {
		if value, ok := os.LookupEnv(key); ok {
			*target = value
		}
	}
	overrideBool := func(key string, target *bool) {
		value, ok := os.LookupEnv(key)
		if !ok {
			return
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on":
			*target = true
		case "0", "false", "no", "off":
			*target = false
		}
	}

	overrideString("BOMLY_PATH", &dst.Path)
	overrideString("BOMLY_CONTAINER", &dst.Container)
	overrideString("BOMLY_URL", &dst.URL)
	overrideString("BOMLY_REF", &dst.Ref)
	overrideBool("BOMLY_SBOM", &dst.SBOM)
	overrideBool("BOMLY_AUDIT", &dst.Audit)
	overrideString("BOMLY_FORMAT", &dst.Format)
	overrideBool("BOMLY_INTERACTIVE", &dst.Interactive)
	overrideString("BOMLY_ECOSYSTEMS", &dst.Ecosystems)
	overrideString("BOMLY_DETECTORS", &dst.Detectors)
	overrideString("BOMLY_AUDITORS", &dst.Auditors)
	overrideString("BOMLY_MATCHERS", &dst.Matchers)
	overrideBool("BOMLY_INSTALL_FIRST", &dst.InstallFirst)
	if value, ok := os.LookupEnv("BOMLY_INSTALL_ARGS"); ok {
		dst.InstallArgs = parseCSV(value)
	}
	overrideString("BOMLY_CONFIG", &dst.Config)
	overrideBool("BOMLY_RECURSIVE", &dst.Recursive)
	overrideBool("BOMLY_QUIET", &dst.Quiet)
	if value, ok := os.LookupEnv("BOMLY_VERBOSE"); ok {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on":
			if dst.Verbosity == 0 {
				dst.Verbosity = 1
			}
		case "2":
			dst.Verbosity = 2
		case "3":
			dst.Verbosity = 3
		case "0", "false", "no", "off":
			dst.Verbosity = 0
		}
	}
	overrideString("BOMLY_HTTP_PROXY", &dst.HTTPProxy)
	overrideString("BOMLY_OSV_API_BASE", &dst.OsvAPIBase)
	overrideString("BOMLY_OSV_CACHE_DIR", &dst.OsvCacheDir)
	overrideString("BOMLY_OSV_CACHE_TTL", &dst.OsvCacheTTL)
	overrideString("BOMLY_KEV_CACHE_DIR", &dst.KEVCacheDir)
	overrideString("BOMLY_KEV_CACHE_TTL", &dst.KEVCacheTTL)
	overrideString("BOMLY_EOL_API_BASE", &dst.EOLAPIBase)
	overrideString("BOMLY_EOL_CACHE_DIR", &dst.EOLCacheDir)
	overrideString("BOMLY_EOL_CACHE_TTL", &dst.EOLCacheTTL)
}

func validateResolvedConfig(cfg resolvedConfig) error {
	if cfg.Interactive && strings.TrimSpace(cfg.Format) != "" {
		return invalidInputf("--interactive cannot be combined with --format")
	}
	if cfg.Quiet && cfg.Verbosity > 0 {
		return invalidInputf("--quiet cannot be combined with --verbose")
	}
	return nil
}

func flagChanged(cmd *cobra.Command, name string) bool {
	flag := cmd.Flags().Lookup(name)
	return flag != nil && flag.Changed
}
