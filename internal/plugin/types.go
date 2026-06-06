package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/registry"
	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

const (
	// EnvPluginHome overrides the default plugin store root for tests and advanced usage.
	EnvPluginHome = "BOMLY_PLUGIN_HOME"
	// EnvPluginAPIVersion is passed to managed plugin subprocesses.
	EnvPluginAPIVersion = "BOMLY_PLUGIN_API_VERSION"
	// EnvPluginConfig is passed to managed plugin subprocesses.
	EnvPluginConfig = "BOMLY_CONFIG"
)

// LaunchOptions carries launch context for managed external plugins.
type LaunchOptions struct {
	ConfigPath         string
	Verbosity          int
	HTTPProxy          string
	HTTPNoProxy        string
	HTTPProxyType      string
	HTTPProxyHost      string
	HTTPProxyPort      int
	HTTPProxyUsername  string
	HTTPProxyPassword  string
	HTTPCACertFile     string
	HTTPClientProvider *plugschema.HTTPClientProvider
	PluginConfigs      map[string]map[string]any
}

type launchOptionsKey struct{}

// WithLaunchOptions returns a context carrying managed plugin launch options.
func WithLaunchOptions(ctx context.Context, options LaunchOptions) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, launchOptionsKey{}, options)
}

// LaunchOptionsFromContext returns managed plugin launch options from ctx.
func LaunchOptionsFromContext(ctx context.Context) (LaunchOptions, bool) {
	if ctx == nil {
		return LaunchOptions{}, false
	}
	options, ok := ctx.Value(launchOptionsKey{}).(LaunchOptions)
	return options, ok
}

// Manifest describes one installed managed plugin package.
type Manifest struct {
	SchemaVersion      string                         `json:"schemaVersion"`
	ID                 string                         `json:"id"`
	Name               string                         `json:"name"`
	Version            string                         `json:"version"`
	Kind               plugschema.PluginKind          `json:"kind"`
	Runtime            string                         `json:"runtime"`
	PluginAPIVersion   string                         `json:"pluginApiVersion"`
	BomlyVersion       string                         `json:"bomlyVersion"`
	Entrypoint         map[string]string              `json:"entrypoint"`
	DetectorDescriptor *plugschema.DetectorDescriptor `json:"detectorDescriptor,omitempty"`
	MatcherDescriptor  *plugschema.MatcherDescriptor  `json:"matcherDescriptor,omitempty"`
	AuditorDescriptor  *plugschema.AuditorDescriptor  `json:"auditorDescriptor,omitempty"`
	AnalyzerDescriptor *plugschema.AnalyzerDescriptor `json:"analyzerDescriptor,omitempty"`
	Source             string                         `json:"source,omitempty"`
	Description        string                         `json:"description,omitempty"`
	Homepage           string                         `json:"homepage,omitempty"`
	License            string                         `json:"license,omitempty"`
}

// InstalledPlugin records one plugin installation.
type InstalledPlugin struct {
	ID       string                `json:"id"`
	Version  string                `json:"version"`
	Enabled  bool                  `json:"enabled"`
	Source   string                `json:"source,omitempty"`
	Checksum string                `json:"checksum,omitempty"`
	Path     string                `json:"path"`
	Runtime  string                `json:"runtime"`
	Kind     plugschema.PluginKind `json:"kind,omitempty"`
}

// InstalledDB stores the installed plugin set.
type InstalledDB struct {
	SchemaVersion string            `json:"schemaVersion"`
	Plugins       []InstalledPlugin `json:"plugins"`
}

// InstallOptions controls plugin installation behavior.
type InstallOptions struct {
	DevBinary             bool
	Checksum              string
	InsecureSkipChecksum  bool
	githubReleaseDownload bool
}

// InstallResult describes the installed plugin.
type InstallResult struct {
	Manifest         Manifest
	Installed        InstalledPlugin
	ResolvedSource   string
	ChecksumVerified bool
}

// PluginInfo is the combined managed-plugin view used by the CLI and runtime loader.
type PluginInfo struct {
	Manifest
	Installed  *InstalledPlugin
	BuiltIn    bool
	Enabled    bool
	Entrypoint string
	SourceType string
	// ReadyFn, when non-nil, is called by Test() to probe readiness for built-in plugins.
	// Populated by the CLI layer from the in-process component instance.
	// Never serialized to JSON.
	ReadyFn func(context.Context) (bool, string, error) `json:"-"`
}

// VerifyResult describes the checks performed for one plugin.
type VerifyResult struct {
	PluginInfo
	Checks []string
}

// TestResult describes runtime readiness checks for one plugin.
type TestResult struct {
	PluginInfo
	Ready bool   `json:"ready"`
	Probe string `json:"probe,omitempty"`
}

// DoctorResult describes combined verification and runtime readiness checks.
type DoctorResult struct {
	PluginInfo
	Checks  []string `json:"checks,omitempty"`
	Ready   bool     `json:"ready"`
	Healthy bool     `json:"healthy"`
	Probe   string   `json:"probe,omitempty"`
}

// PluginListResponse is the structured JSON response for the plugin list command,
// with plugins grouped by kind.
type PluginListResponse struct {
	Detectors []PluginInfo `json:"detectors"`
	Matchers  []PluginInfo `json:"matchers"`
	Auditors  []PluginInfo `json:"auditors"`
	Analyzers []PluginInfo `json:"analyzers"`
}

// GroupPluginInfos groups a flat slice of PluginInfo by kind into a PluginListResponse.
func GroupPluginInfos(infos []PluginInfo) PluginListResponse {
	resp := PluginListResponse{
		Detectors: []PluginInfo{},
		Matchers:  []PluginInfo{},
		Auditors:  []PluginInfo{},
		Analyzers: []PluginInfo{},
	}
	for _, info := range infos {
		switch info.Kind {
		case plugschema.PluginKindDetector:
			resp.Detectors = append(resp.Detectors, info)
		case plugschema.PluginKindMatcher:
			resp.Matchers = append(resp.Matchers, info)
		case plugschema.PluginKindAuditor:
			resp.Auditors = append(resp.Auditors, info)
		case plugschema.PluginKindAnalyzer:
			resp.Analyzers = append(resp.Analyzers, info)
		}
	}
	return resp
}

func defaultRoot() (string, error) {
	if override := strings.TrimSpace(os.Getenv(EnvPluginHome)); override != "" {
		return filepath.Clean(override), nil
	}
	if strings.Contains(filepath.Base(os.Args[0]), ".test") {
		return filepath.Join(os.TempDir(), "bomly-test-empty-plugins"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".bomly", "plugins"), nil
}

func resolveRoot(root string) (string, error) {
	if strings.TrimSpace(root) != "" {
		return filepath.Clean(root), nil
	}
	return defaultRoot()
}

func installedDBPath(root string) string {
	return filepath.Join(root, "installed.json")
}

func storeRoot(root string) string {
	return filepath.Join(root, "store")
}

func platformKey() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

func entrypointForManifest(manifest Manifest) (string, error) {
	entry := strings.TrimSpace(manifest.Entrypoint[platformKey()])
	if entry == "" {
		return "", fmt.Errorf("plugin %s@%s does not provide entrypoint for %s", manifest.ID, manifest.Version, platformKey())
	}
	return filepath.FromSlash(entry), nil
}

func loadInstalledDB(root string) (InstalledDB, error) {
	path := installedDBPath(root)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return InstalledDB{SchemaVersion: plugschema.InstalledPluginsSchemaVersion}, nil
		}
		return InstalledDB{}, fmt.Errorf("read installed plugin database: %w", err)
	}
	var db InstalledDB
	if err := json.Unmarshal(data, &db); err != nil {
		return InstalledDB{}, fmt.Errorf("decode installed plugin database: %w", err)
	}
	if db.SchemaVersion == "" {
		db.SchemaVersion = plugschema.InstalledPluginsSchemaVersion
	}
	return db, nil
}

func saveInstalledDB(root string, db InstalledDB) error {
	if db.SchemaVersion == "" {
		db.SchemaVersion = plugschema.InstalledPluginsSchemaVersion
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("create plugin root: %w", err)
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("encode installed plugin database: %w", err)
	}
	target := installedDBPath(root)
	tempFile, err := os.CreateTemp(root, "installed-*.json")
	if err != nil {
		return fmt.Errorf("create temp installed plugin database: %w", err)
	}
	tempPath := tempFile.Name()
	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("write temp installed plugin database: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close temp installed plugin database: %w", err)
	}
	if err := os.Rename(tempPath, target); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("replace installed plugin database: %w", err)
	}
	return nil
}

func manifestPath(dir string) string {
	return filepath.Join(dir, "bomly-plugin.json")
}

func readManifest(dir string) (Manifest, error) {
	data, err := os.ReadFile(manifestPath(dir))
	if err != nil {
		return Manifest{}, fmt.Errorf("read plugin manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode plugin manifest: %w", err)
	}
	manifest = normalizeManifest(manifest)
	return manifest, validateManifest(manifest)
}

func writeManifest(dir string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifestForDisk(manifest), "", "  ")
	if err != nil {
		return fmt.Errorf("encode plugin manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath(dir), data, 0o644); err != nil {
		return fmt.Errorf("write plugin manifest: %w", err)
	}
	return nil
}

func normalizeManifest(manifest Manifest) Manifest {
	if manifest.Kind == plugschema.PluginKindDetector && manifest.DetectorDescriptor != nil {
		manifest.DetectorDescriptor = normalizeDetectorDescriptor(manifest.DetectorDescriptor)
	}
	return manifest
}

func manifestForDisk(manifest Manifest) Manifest {
	if manifest.Kind == plugschema.PluginKindDetector && manifest.DetectorDescriptor != nil {
		manifest.DetectorDescriptor = cloneDetectorDescriptor(manifest.DetectorDescriptor)
		manifest.DetectorDescriptor.SupportedEcosystems = nil
		manifest.DetectorDescriptor.SupportedManagers = nil
	}
	return manifest
}

func validateManifest(manifest Manifest) error {
	switch manifest.SchemaVersion {
	case "", plugschema.PackageManifestSchemaVersion:
	default:
		return fmt.Errorf("unsupported plugin manifest schema version %q", manifest.SchemaVersion)
	}
	if strings.TrimSpace(manifest.ID) == "" {
		return errors.New("plugin manifest id is required")
	}
	if strings.TrimSpace(manifest.Name) == "" {
		return errors.New("plugin manifest name is required")
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return errors.New("plugin manifest version is required")
	}
	switch manifest.Kind {
	case plugschema.PluginKindDetector, plugschema.PluginKindMatcher, plugschema.PluginKindAuditor:
	default:
		return fmt.Errorf("plugin manifest kind %q is invalid", manifest.Kind)
	}
	if runtimeValue := strings.TrimSpace(manifest.Runtime); runtimeValue != plugschema.RuntimeHashiCorpGRPC {
		return fmt.Errorf("plugin runtime %q is unsupported", runtimeValue)
	}
	if apiVersion := strings.TrimSpace(manifest.PluginAPIVersion); apiVersion != plugschema.PluginAPIVersion {
		return fmt.Errorf("plugin API version %q is unsupported", apiVersion)
	}
	if manifest.Kind == plugschema.PluginKindDetector && (manifest.DetectorDescriptor == nil || len(manifest.DetectorDescriptor.PackageManagerSupport) == 0) {
		return errors.New("detector plugins must declare at least one package manager support entry")
	}
	switch manifest.Kind {
	case plugschema.PluginKindDetector:
		if err := plugschema.ValidateDetectorDescriptor(manifest.DetectorDescriptor); err != nil {
			return err
		}
	case plugschema.PluginKindMatcher:
		if err := plugschema.ValidateMatcherDescriptor(manifest.MatcherDescriptor); err != nil {
			return err
		}
	case plugschema.PluginKindAuditor:
		if err := plugschema.ValidateAuditorDescriptor(manifest.AuditorDescriptor); err != nil {
			return err
		}
	}
	entry, err := entrypointForManifest(manifest)
	if err != nil {
		return err
	}
	cleanEntry := filepath.Clean(entry)
	if filepath.IsAbs(cleanEntry) || strings.HasPrefix(cleanEntry, "..") {
		return fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
	}
	return nil
}

func checksumFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for checksum: %w", err)
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("checksum file: %w", err)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func withCanonicalManifestDefaults(manifest Manifest, source string) Manifest {
	if manifest.SchemaVersion == "" {
		manifest.SchemaVersion = plugschema.PackageManifestSchemaVersion
	}
	if manifest.Runtime == "" {
		manifest.Runtime = plugschema.RuntimeHashiCorpGRPC
	}
	if manifest.PluginAPIVersion == "" {
		manifest.PluginAPIVersion = plugschema.PluginAPIVersion
	}
	if manifest.Source == "" {
		manifest.Source = source
	}
	return manifest
}

func insertInstalledPlugin(db InstalledDB, record InstalledPlugin) InstalledDB {
	replaced := false
	out := make([]InstalledPlugin, 0, len(db.Plugins)+1)
	for _, existing := range db.Plugins {
		if existing.ID == record.ID {
			if !replaced {
				out = append(out, record)
				replaced = true
			}
			continue
		}
		out = append(out, existing)
	}
	if !replaced {
		out = append(out, record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	db.Plugins = out
	return db
}

func removeInstalledPlugin(db InstalledDB, id string) InstalledDB {
	out := make([]InstalledPlugin, 0, len(db.Plugins))
	for _, plugin := range db.Plugins {
		if plugin.ID == id {
			continue
		}
		out = append(out, plugin)
	}
	db.Plugins = out
	return db
}

func updateInstalledPlugin(root, id string, mutate func(*InstalledPlugin) error) (*InstalledPlugin, error) {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return nil, err
	}
	db, err := loadInstalledDB(root)
	if err != nil {
		return nil, err
	}
	for idx := range db.Plugins {
		if db.Plugins[idx].ID != id {
			continue
		}
		if err := mutate(&db.Plugins[idx]); err != nil {
			return nil, err
		}
		if err := saveInstalledDB(root, db); err != nil {
			return nil, err
		}
		return &db.Plugins[idx], nil
	}
	return nil, fmt.Errorf("plugin %q is not installed", id)
}

func detectorDiscoveryPlan(manifest Manifest) (registry.DetectorDiscoveryPlan, bool) {
	if manifest.Kind != plugschema.PluginKindDetector {
		return registry.DetectorDiscoveryPlan{}, false
	}
	if manifest.DetectorDescriptor == nil {
		return registry.DetectorDiscoveryPlan{}, false
	}
	descriptor := manifest.DetectorDescriptor
	managers := make([]plugschema.PackageManager, 0, len(descriptor.PackageManagerSupport))
	ecosystems := make([]plugschema.Ecosystem, 0, len(manifest.DetectorDescriptor.SupportedEcosystems))
	patterns := make([]string, 0)
	seenPatterns := make(map[string]struct{})
	for _, support := range descriptor.PackageManagerSupport {
		manager, err := plugschema.ParsePackageManager(support.PackageManager.Name())
		if err != nil {
			continue
		}
		managers = append(managers, manager)
		eco := manager.Ecosystem()
		if !slices.Contains(ecosystems, eco) {
			ecosystems = append(ecosystems, eco)
		}
		for _, pattern := range support.EvidencePatterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			if _, ok := seenPatterns[pattern]; ok {
				continue
			}
			seenPatterns[pattern] = struct{}{}
			patterns = append(patterns, pattern)
		}
		for _, pattern := range registry.EvidencePatternsForPackageManager(manager) {
			if _, ok := seenPatterns[pattern]; ok {
				continue
			}
			seenPatterns[pattern] = struct{}{}
			patterns = append(patterns, pattern)
		}
	}
	for _, raw := range manifest.DetectorDescriptor.SupportedEcosystems {
		eco, err := plugschema.ParseEcosystem(string(raw))
		if err == nil && !slices.Contains(ecosystems, eco) {
			ecosystems = append(ecosystems, eco)
		}
	}
	targetKinds := []plugschema.ExecutionTargetKind{plugschema.ExecutionTargetFilesystem, plugschema.ExecutionTargetGitRepository}
	if len(ecosystems) == 0 && len(managers) > 0 {
		for _, manager := range managers {
			eco := manager.Ecosystem()
			if !slices.Contains(ecosystems, eco) {
				ecosystems = append(ecosystems, eco)
			}
		}
	}
	if len(patterns) == 0 && !slices.Contains(targetKinds, plugschema.ExecutionTargetContainerImage) {
		return registry.DetectorDiscoveryPlan{}, false
	}
	return registry.DetectorDiscoveryPlan{
		SupportedEcosystems: ecosystems,
		SupportedManagers:   managers,
		EvidencePatterns:    patterns,
		TargetKinds:         targetKinds,
	}, true
}

func findInstalled(root, id string) (*InstalledPlugin, error) {
	db, err := loadInstalledDB(root)
	if err != nil {
		return nil, err
	}
	for _, plugin := range db.Plugins {
		if plugin.ID == id {
			return new(plugin), nil
		}
	}
	return nil, fmt.Errorf("plugin %q is not installed", id)
}

func manifestFromMetadata(metadata *plugschema.PluginMetadata, detector *plugschema.DetectorDescriptor, packageManagerSupport []plugschema.PackageManagerSupport, matcher *plugschema.MatcherDescriptor, auditor *plugschema.AuditorDescriptor, source string, binaryName string) (Manifest, error) {
	if metadata == nil {
		return Manifest{}, errors.New("plugin metadata is nil")
	}
	if err := plugschema.ValidateMetadata(metadata); err != nil {
		return Manifest{}, err
	}
	if strings.TrimSpace(binaryName) == "" {
		return Manifest{}, errors.New("plugin binary name is empty")
	}
	return withCanonicalManifestDefaults(Manifest{
		ID:                 metadata.ID,
		Name:               metadata.Name,
		Version:            metadata.Version,
		Kind:               metadata.Kind,
		BomlyVersion:       metadata.BomlyVersionConstraint,
		Entrypoint:         map[string]string{platformKey(): filepath.ToSlash(filepath.Join("bin", binaryName))},
		DetectorDescriptor: cloneDetectorDescriptorWithSupport(detector, packageManagerSupport),
		MatcherDescriptor:  cloneMatcherDescriptor(matcher),
		AuditorDescriptor:  cloneAuditorDescriptor(auditor),
		Description:        metadata.Description,
		Homepage:           metadata.Homepage,
		License:            metadata.License,
	}, source), nil
}

func manifestWithRuntimeContract(manifest Manifest, metadata *plugschema.PluginMetadata, detector *plugschema.DetectorDescriptor, packageManagerSupport []plugschema.PackageManagerSupport, matcher *plugschema.MatcherDescriptor, auditor *plugschema.AuditorDescriptor) Manifest {
	if metadata == nil {
		return manifest
	}
	if manifest.Description == "" {
		manifest.Description = metadata.Description
	}
	if manifest.Homepage == "" {
		manifest.Homepage = metadata.Homepage
	}
	if manifest.License == "" {
		manifest.License = metadata.License
	}
	if manifest.BomlyVersion == "" {
		manifest.BomlyVersion = metadata.BomlyVersionConstraint
	}
	if manifest.DetectorDescriptor == nil {
		manifest.DetectorDescriptor = cloneDetectorDescriptorWithSupport(detector, packageManagerSupport)
	}
	if manifest.MatcherDescriptor == nil {
		manifest.MatcherDescriptor = cloneMatcherDescriptor(matcher)
	}
	if manifest.AuditorDescriptor == nil {
		manifest.AuditorDescriptor = cloneAuditorDescriptor(auditor)
	}
	return manifest
}

func runtimeMetadataMatchesManifest(metadata *plugschema.PluginMetadata, detector *plugschema.DetectorDescriptor, packageManagerSupport []plugschema.PackageManagerSupport, matcher *plugschema.MatcherDescriptor, auditor *plugschema.AuditorDescriptor, manifest Manifest) error {
	if metadata == nil {
		return errors.New("plugin metadata is nil")
	}
	if err := plugschema.ValidateMetadata(metadata); err != nil {
		return err
	}
	if metadata.ID != manifest.ID {
		return fmt.Errorf("plugin runtime metadata id %q does not match manifest id %q", metadata.ID, manifest.ID)
	}
	if metadata.Version != manifest.Version {
		return fmt.Errorf("plugin runtime metadata version %q does not match manifest version %q", metadata.Version, manifest.Version)
	}
	if metadata.Kind != manifest.Kind {
		return fmt.Errorf("plugin runtime metadata kind %q does not match manifest kind %q", metadata.Kind, manifest.Kind)
	}
	if metadata.PluginAPIVersion != manifest.PluginAPIVersion {
		return fmt.Errorf("plugin runtime metadata API version %q does not match manifest API version %q", metadata.PluginAPIVersion, manifest.PluginAPIVersion)
	}
	switch manifest.Kind {
	case plugschema.PluginKindDetector:
		if detector == nil || manifest.DetectorDescriptor == nil {
			return errors.New("plugin runtime detector descriptor is missing")
		}
		if !packageManagerSupportEqual(packageManagerSupport, manifest.DetectorDescriptor.PackageManagerSupport) {
			return fmt.Errorf("plugin runtime detector package manager support does not match manifest detector support")
		}
		if !slices.Equal(detector.FallbackDetectors, manifest.DetectorDescriptor.FallbackDetectors) ||
			detector.Origin != manifest.DetectorDescriptor.Origin ||
			detector.SupportsInstallFirst != manifest.DetectorDescriptor.SupportsInstallFirst {
			return fmt.Errorf("plugin runtime detector descriptor does not match manifest detector descriptor")
		}
	case plugschema.PluginKindMatcher:
		if matcher == nil || manifest.MatcherDescriptor == nil {
			return errors.New("plugin runtime matcher descriptor is missing")
		}
		if matcher.Origin != manifest.MatcherDescriptor.Origin {
			return fmt.Errorf("plugin runtime matcher descriptor does not match manifest matcher descriptor")
		}
	case plugschema.PluginKindAuditor:
		if auditor == nil || manifest.AuditorDescriptor == nil {
			return errors.New("plugin runtime auditor descriptor is missing")
		}
		if auditor.Origin != manifest.AuditorDescriptor.Origin {
			return fmt.Errorf("plugin runtime auditor descriptor does not match manifest auditor descriptor")
		}
	}
	return nil
}

// LoadInstalledPlugins returns the full installed managed-plugin set.
func LoadInstalledPlugins(root string) ([]PluginInfo, error) {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return nil, err
	}
	db, err := loadInstalledDB(root)
	if err != nil {
		return nil, err
	}
	infos := make([]PluginInfo, 0, len(db.Plugins))
	for _, item := range db.Plugins {
		manifest, err := readManifest(item.Path)
		if err != nil {
			return nil, fmt.Errorf("read installed plugin %s: %w", item.ID, err)
		}
		entry, err := entrypointForManifest(manifest)
		if err != nil {
			return nil, err
		}
		infos = append(infos, PluginInfo{
			Manifest:   manifest,
			Installed:  new(item),
			Enabled:    item.Enabled,
			Entrypoint: filepath.Join(item.Path, entry),
			SourceType: "external",
		})
	}
	return infos, nil
}

// ListPluginInfos returns built-in and installed plugin info in one list.
func ListPluginInfos(root string, builtins []PluginInfo) ([]PluginInfo, error) {
	installed, err := LoadInstalledPlugins(root)
	if err != nil {
		return nil, err
	}
	all := append(append([]PluginInfo(nil), builtins...), installed...)
	sort.Slice(all, func(i, j int) bool {
		if all[i].ID == all[j].ID {
			return all[i].Version < all[j].Version
		}
		return all[i].ID < all[j].ID
	})
	return all, nil
}

// LoadRuntimePlugins loads enabled external plugins.
func LoadRuntimePlugins(root string) ([]PluginInfo, error) {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return nil, err
	}
	db, err := loadInstalledDB(root)
	if err != nil {
		return nil, err
	}
	out := make([]PluginInfo, 0, len(db.Plugins))
	for _, item := range db.Plugins {
		if !item.Enabled {
			continue
		}
		manifest, err := readManifest(item.Path)
		if err != nil {
			return nil, fmt.Errorf("read installed plugin %s: %w", item.ID, err)
		}
		entry, err := entrypointForManifest(manifest)
		if err != nil {
			return nil, err
		}
		out = append(out, PluginInfo{
			Manifest:   manifest,
			Installed:  new(item),
			Enabled:    item.Enabled,
			Entrypoint: filepath.Join(item.Path, entry),
			SourceType: "external",
		})
	}
	return out, nil
}

type metadataClient interface {
	Metadata(context.Context) (*plugschema.PluginMetadata, error)
	DetectorDescriptor(context.Context) (*plugschema.DetectorDescriptor, error)
	DetectorPackageManagerSupport(context.Context) ([]plugschema.PackageManagerSupport, error)
	MatcherDescriptor(context.Context) (*plugschema.MatcherDescriptor, error)
	AuditorDescriptor(context.Context) (*plugschema.AuditorDescriptor, error)
}

func cloneDetectorDescriptor(descriptor *plugschema.DetectorDescriptor) *plugschema.DetectorDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.PackageManagerSupport = clonePackageManagerSupport(descriptor.PackageManagerSupport)
	copyValue.Capabilities = append([]string(nil), descriptor.Capabilities...)
	copyValue.FallbackDetectors = append([]string(nil), descriptor.FallbackDetectors...)
	return &copyValue
}

func normalizeDetectorDescriptor(descriptor *plugschema.DetectorDescriptor) *plugschema.DetectorDescriptor {
	clone := cloneDetectorDescriptor(descriptor)
	if clone == nil || len(clone.PackageManagerSupport) == 0 {
		return clone
	}
	clone.SupportedManagers = supportedManagersFromPackageManagerSupport(clone.PackageManagerSupport)
	clone.SupportedEcosystems = supportedEcosystemsFromPackageManagers(clone.SupportedManagers)
	return clone
}

func cloneDetectorDescriptorWithSupport(descriptor *plugschema.DetectorDescriptor, support []plugschema.PackageManagerSupport) *plugschema.DetectorDescriptor {
	clone := normalizeDetectorDescriptor(descriptor)
	if clone == nil {
		return nil
	}
	clone.PackageManagerSupport = clonePackageManagerSupport(support)
	return normalizeDetectorDescriptor(clone)
}

func clonePackageManagerSupport(src []plugschema.PackageManagerSupport) []plugschema.PackageManagerSupport {
	out := make([]plugschema.PackageManagerSupport, len(src))
	for i, entry := range src {
		out[i] = entry
		out[i].EvidencePatterns = append([]string(nil), entry.EvidencePatterns...)
	}
	return out
}

func packageManagerSupportEqual(left, right []plugschema.PackageManagerSupport) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i].PackageManager != right[i].PackageManager {
			return false
		}
		if !slices.Equal(left[i].EvidencePatterns, right[i].EvidencePatterns) {
			return false
		}
	}
	return true
}

func supportedManagersFromPackageManagerSupport(support []plugschema.PackageManagerSupport) []plugschema.PackageManager {
	managers := make([]plugschema.PackageManager, 0, len(support))
	for _, entry := range support {
		manager := entry.PackageManager
		if manager == plugschema.PackageManagerUnknown || slices.Contains(managers, manager) {
			continue
		}
		managers = append(managers, manager)
	}
	return managers
}

func supportedEcosystemsFromPackageManagers(managers []plugschema.PackageManager) []plugschema.Ecosystem {
	ecosystems := make([]plugschema.Ecosystem, 0, len(managers))
	for _, manager := range managers {
		ecosystem := manager.Ecosystem()
		if ecosystem == plugschema.EcosystemUnknown || slices.Contains(ecosystems, ecosystem) {
			continue
		}
		ecosystems = append(ecosystems, ecosystem)
	}
	return ecosystems
}

func cloneMatcherDescriptor(descriptor *plugschema.MatcherDescriptor) *plugschema.MatcherDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.Capabilities = append([]string(nil), descriptor.Capabilities...)
	return &copyValue
}

func cloneAuditorDescriptor(descriptor *plugschema.AuditorDescriptor) *plugschema.AuditorDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	return &copyValue
}

func cloneAnalyzerDescriptor(descriptor *plugschema.AnalyzerDescriptor) *plugschema.AnalyzerDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.SupportedLanguages = append([]plugschema.Language(nil), descriptor.SupportedLanguages...)
	copyValue.SupportedTiers = append([]plugschema.ReachabilityTier(nil), descriptor.SupportedTiers...)
	return &copyValue
}
