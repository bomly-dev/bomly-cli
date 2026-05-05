package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/config"
	"github.com/bomly-dev/bomly-cli/internal/system"
	"github.com/spf13/cobra"
)

// resolvedConfig and fileConfig are cli-side aliases for the canonical config
// schema in internal/config. The struct fields, doc/env/default tags, and
// yaml tags there are the source the configref / schemajson / schemadocs
// generators read.
type (
	resolvedConfig = config.Resolved
	fileConfig     = config.File
)

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
	cfg := o.Resolved
	config.ApplyDefaults(&cfg)
	return cfg
}

func (o *globalOptions) loadResolvedConfig(cmd *cobra.Command) (resolvedConfig, error) {
	resolved := o.current()

	configPaths, err := o.configLoadPaths()
	if err != nil {
		return resolvedConfig{}, err
	}
	for _, path := range configPaths {
		fileCfg, err := config.LoadFile(path)
		if err != nil {
			return resolvedConfig{}, invalidInputf("load config %q: %v", path, err)
		}
		if fileCfg == nil {
			continue
		}
		config.ApplyFileConfig(&resolved, *fileCfg)
		resolved.LoadedFiles = append(resolved.LoadedFiles, path)
	}

	config.ApplyEnvOverrides(&resolved)
	applyFlagOverrides(&resolved, o, cmd)
	config.ApplyDefaults(&resolved)
	if err := config.Validate(resolved); err != nil {
		return resolvedConfig{}, invalidInputf("%v", err)
	}
	return resolved, nil
}

func (o *globalOptions) configLoadPaths() ([]string, error) {
	paths := make([]string, 0, 3)

	homePath, err := config.UserConfigPath()
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
	overrideBool("enrich", src.Enrich, &dst.Enrich)
	overrideBool("audit", src.Audit, &dst.Audit)
	overrideString("fail-on", src.FailOn, &dst.FailOn)
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
	overrideBool("quiet", src.Quiet, &dst.Quiet)
	if flagChanged(cmd, "verbose") {
		dst.Verbosity = src.Verbosity
	}
}

func flagChanged(cmd *cobra.Command, name string) bool {
	flag := cmd.Flags().Lookup(name)
	return flag != nil && flag.Changed
}
