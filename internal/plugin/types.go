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
	SchemaVersion    string                `json:"schemaVersion"`
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	Version          string                `json:"version"`
	Kind             plugschema.PluginKind `json:"kind"`
	Runtime          string                `json:"runtime"`
	PluginAPIVersion string                `json:"pluginApiVersion"`
	BomlyVersion     string                `json:"bomlyVersion"`
	Entrypoint       map[string]string     `json:"entrypoint"`
	Source           string                `json:"source,omitempty"`
	Description      string                `json:"description,omitempty"`
	Homepage         string                `json:"homepage,omitempty"`
	License          string                `json:"license,omitempty"`
}

// RuntimeDescriptorSnapshot stores Bomly-verified runtime descriptors for an installed plugin.
type RuntimeDescriptorSnapshot struct {
	SchemaVersion      string                         `json:"schemaVersion"`
	ID                 string                         `json:"id"`
	Kind               plugschema.PluginKind          `json:"kind"`
	PluginAPIVersion   string                         `json:"pluginApiVersion"`
	DetectorDescriptor *plugschema.DetectorDescriptor `json:"detectorDescriptor,omitempty"`
	MatcherDescriptor  *plugschema.MatcherDescriptor  `json:"matcherDescriptor,omitempty"`
	AuditorDescriptor  *plugschema.AuditorDescriptor  `json:"auditorDescriptor,omitempty"`
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
	DevBinary              bool
	Checksum               string
	InsecureSkipChecksum   bool
	githubReleaseDownload  bool
	githubReleaseAssetName string
}

// InstallResult describes the installed plugin.
type InstallResult struct {
	Manifest         Manifest
	Installed        InstalledPlugin
	ResolvedSource   string
	ChecksumVerified bool
}

// Info is the combined managed-plugin view used by the CLI and runtime loader.
type Info struct {
	Manifest
	DetectorDescriptor *plugschema.DetectorDescriptor `json:"detectorDescriptor,omitempty"`
	MatcherDescriptor  *plugschema.MatcherDescriptor  `json:"matcherDescriptor,omitempty"`
	AuditorDescriptor  *plugschema.AuditorDescriptor  `json:"auditorDescriptor,omitempty"`
	AnalyzerDescriptor *plugschema.AnalyzerDescriptor `json:"analyzerDescriptor,omitempty"`
	Installed          *InstalledPlugin
	BuiltIn            bool
	Enabled            bool
	Entrypoint         string
	SourceType         string
	// ReadyFn, when non-nil, is called by Test() to probe readiness for built-in plugins.
	// Populated by the CLI layer from the in-process component instance.
	// Never serialized to JSON.
	ReadyFn func(context.Context) (bool, string, error) `json:"-"`
}

// VerifyResult describes the checks performed for one plugin.
type VerifyResult struct {
	Info
	Checks []string
}

// TestResult describes runtime readiness checks for one plugin.
type TestResult struct {
	Info
	Ready bool   `json:"ready"`
	Probe string `json:"probe,omitempty"`
}

// DoctorResult describes combined verification and runtime readiness checks.
type DoctorResult struct {
	Info
	Checks  []string `json:"checks,omitempty"`
	Ready   bool     `json:"ready"`
	Healthy bool     `json:"healthy"`
	Probe   string   `json:"probe,omitempty"`
}

// ListResponse is the structured JSON response for the plugin list command,
// with plugins grouped by kind.
type ListResponse struct {
	Detectors []Info `json:"detectors"`
	Matchers  []Info `json:"matchers"`
	Auditors  []Info `json:"auditors"`
	Analyzers []Info `json:"analyzers"`
}

// GroupPluginInfos groups a flat slice of PluginInfo by kind into a PluginListResponse.
func GroupPluginInfos(infos []Info) ListResponse {
	resp := ListResponse{
		Detectors: []Info{},
		Matchers:  []Info{},
		Auditors:  []Info{},
		Analyzers: []Info{},
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
	cleanEntry, err := cleanRelativePluginPath(entry)
	if err != nil {
		return "", fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
	}
	return cleanEntry, nil
}

func cleanRelativePluginPath(value string) (string, error) {
	slashPath := strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	if slashPath == "" || slashPath == "." || strings.Contains(slashPath, ":") {
		return "", errors.New("invalid relative path")
	}
	cleanPath := filepath.Clean(filepath.FromSlash(slashPath))
	if filepath.IsAbs(cleanPath) || cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(os.PathSeparator)) {
		return "", errors.New("path escapes base directory")
	}
	if cleanPath == "." {
		return "", errors.New("invalid relative path")
	}
	return cleanPath, nil
}

func pathInPluginDir(root, relativePath string) (string, error) {
	cleanPath, err := cleanRelativePluginPath(relativePath)
	if err != nil {
		return "", err
	}
	destination := filepath.Join(root, cleanPath)
	rel, err := filepath.Rel(root, destination)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("path escapes base directory")
	}
	return destination, nil
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

func runtimeSnapshotPath(dir string) string {
	return filepath.Join(dir, "bomly-plugin.runtime.json")
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
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode plugin manifest: %w", err)
	}
	if err := os.WriteFile(manifestPath(dir), data, 0o644); err != nil {
		return fmt.Errorf("write plugin manifest: %w", err)
	}
	return nil
}

func readRuntimeSnapshot(dir string) (RuntimeDescriptorSnapshot, error) {
	data, err := os.ReadFile(runtimeSnapshotPath(dir))
	if err != nil {
		return RuntimeDescriptorSnapshot{}, fmt.Errorf("read plugin runtime descriptor snapshot: %w", err)
	}
	var snapshot RuntimeDescriptorSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return RuntimeDescriptorSnapshot{}, fmt.Errorf("decode plugin runtime descriptor snapshot: %w", err)
	}
	snapshot = normalizeRuntimeSnapshot(snapshot)
	return snapshot, validateRuntimeSnapshot(snapshot)
}

func writeRuntimeSnapshot(dir string, snapshot RuntimeDescriptorSnapshot) error {
	snapshot = normalizeRuntimeSnapshot(snapshot)
	if err := validateRuntimeSnapshot(snapshot); err != nil {
		return err
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("encode plugin runtime descriptor snapshot: %w", err)
	}
	if err := os.WriteFile(runtimeSnapshotPath(dir), data, 0o644); err != nil {
		return fmt.Errorf("write plugin runtime descriptor snapshot: %w", err)
	}
	return nil
}

func normalizeRuntimeSnapshot(snapshot RuntimeDescriptorSnapshot) RuntimeDescriptorSnapshot {
	if snapshot.SchemaVersion == "" {
		snapshot.SchemaVersion = plugschema.RuntimeDescriptorSnapshotSchemaVersion
	}
	if snapshot.Kind == plugschema.PluginKindDetector && snapshot.DetectorDescriptor != nil {
		snapshot.DetectorDescriptor = normalizeDetectorDescriptor(snapshot.DetectorDescriptor)
	}
	return snapshot
}

func validateRuntimeSnapshot(snapshot RuntimeDescriptorSnapshot) error {
	if snapshot.SchemaVersion != plugschema.RuntimeDescriptorSnapshotSchemaVersion {
		return fmt.Errorf("unsupported plugin runtime descriptor snapshot schema version %q", snapshot.SchemaVersion)
	}
	if strings.TrimSpace(snapshot.ID) == "" {
		return errors.New("plugin runtime descriptor snapshot id is required")
	}
	if apiVersion := strings.TrimSpace(snapshot.PluginAPIVersion); apiVersion != plugschema.PluginAPIVersion {
		return fmt.Errorf("plugin runtime descriptor snapshot API version %q is unsupported", apiVersion)
	}
	switch snapshot.Kind {
	case plugschema.PluginKindDetector:
		if snapshot.DetectorDescriptor == nil || len(snapshot.DetectorDescriptor.PackageManagerSupport) == 0 {
			return errors.New("detector plugin runtime snapshot must include detector descriptor and package manager support")
		}
		return plugschema.ValidateDetectorDescriptor(snapshot.DetectorDescriptor)
	case plugschema.PluginKindMatcher:
		return plugschema.ValidateMatcherDescriptor(snapshot.MatcherDescriptor)
	case plugschema.PluginKindAuditor:
		return plugschema.ValidateAuditorDescriptor(snapshot.AuditorDescriptor)
	default:
		return fmt.Errorf("plugin runtime descriptor snapshot kind %q is invalid", snapshot.Kind)
	}
}

func normalizeManifest(manifest Manifest) Manifest {
	return manifest
}

func validateManifest(manifest Manifest) error {
	manifest = normalizeManifest(manifest)
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
	entry, err := entrypointForManifest(manifest)
	if err != nil {
		return err
	}
	if _, err := pathInPluginDir(".", entry); err != nil {
		return fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
	}
	return nil
}

func checksumFile(path string) (string, error) {
	// Callers must constrain path to a trusted location before requesting a checksum.
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve file for checksum: %w", err)
	}
	info, err := os.Stat(cleanPath)
	if err != nil {
		return "", fmt.Errorf("stat file for checksum: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("checksum path %q is a directory", path)
	}
	file, err := os.Open(cleanPath)
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

func detectorDiscoveryPlan(info Info) (registry.DetectorDiscoveryPlan, bool) {
	if info.Kind != plugschema.PluginKindDetector {
		return registry.DetectorDiscoveryPlan{}, false
	}
	if info.DetectorDescriptor == nil {
		return registry.DetectorDiscoveryPlan{}, false
	}
	descriptor := info.DetectorDescriptor
	managers := make([]plugschema.PackageManager, 0, len(descriptor.PackageManagerSupport))
	ecosystems := make([]plugschema.Ecosystem, 0, len(descriptor.SupportedEcosystems))
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
	for _, raw := range descriptor.SupportedEcosystems {
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

func manifestFromRuntimeSnapshot(snapshot RuntimeDescriptorSnapshot, source string, binaryName string) (Manifest, error) {
	if err := validateRuntimeSnapshot(snapshot); err != nil {
		return Manifest{}, err
	}
	if strings.TrimSpace(binaryName) == "" {
		return Manifest{}, errors.New("plugin binary name is empty")
	}
	return withCanonicalManifestDefaults(Manifest{
		ID:         snapshot.ID,
		Name:       snapshot.ID,
		Version:    "0.0.0-dev",
		Kind:       snapshot.Kind,
		Entrypoint: map[string]string{platformKey(): filepath.ToSlash(filepath.Join("bin", binaryName))},
	}, source), nil
}

func runtimeSnapshotMatchesManifest(snapshot RuntimeDescriptorSnapshot, manifest Manifest) error {
	if err := validateRuntimeSnapshot(snapshot); err != nil {
		return err
	}
	if snapshot.ID != manifest.ID {
		return fmt.Errorf("plugin runtime descriptor name %q does not match manifest id %q", snapshot.ID, manifest.ID)
	}
	if snapshot.Kind != manifest.Kind {
		return fmt.Errorf("plugin runtime kind %q does not match manifest kind %q", snapshot.Kind, manifest.Kind)
	}
	if snapshot.PluginAPIVersion != manifest.PluginAPIVersion {
		return fmt.Errorf("plugin runtime API version %q does not match manifest API version %q", snapshot.PluginAPIVersion, manifest.PluginAPIVersion)
	}
	return nil
}

func runtimeSnapshotMatchesSnapshot(live, installed RuntimeDescriptorSnapshot) error {
	if err := validateRuntimeSnapshot(live); err != nil {
		return err
	}
	if err := validateRuntimeSnapshot(installed); err != nil {
		return err
	}
	if live.ID != installed.ID || live.Kind != installed.Kind || live.PluginAPIVersion != installed.PluginAPIVersion {
		return fmt.Errorf("plugin runtime descriptor identity does not match installed snapshot")
	}
	switch installed.Kind {
	case plugschema.PluginKindDetector:
		if !detectorDescriptorEqual(live.DetectorDescriptor, installed.DetectorDescriptor) {
			return fmt.Errorf("plugin runtime detector descriptor does not match installed snapshot")
		}
	case plugschema.PluginKindMatcher:
		if !matcherDescriptorEqual(live.MatcherDescriptor, installed.MatcherDescriptor) {
			return fmt.Errorf("plugin runtime matcher descriptor does not match installed snapshot")
		}
	case plugschema.PluginKindAuditor:
		if !auditorDescriptorEqual(live.AuditorDescriptor, installed.AuditorDescriptor) {
			return fmt.Errorf("plugin runtime auditor descriptor does not match installed snapshot")
		}
	}
	return nil
}

// LoadInstalledPlugins returns the full installed managed-plugin set.
func LoadInstalledPlugins(root string) ([]Info, error) {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return nil, err
	}
	db, err := loadInstalledDB(root)
	if err != nil {
		return nil, err
	}
	infos := make([]Info, 0, len(db.Plugins))
	for _, item := range db.Plugins {
		manifest, err := readManifest(item.Path)
		if err != nil {
			return nil, fmt.Errorf("read installed plugin %s: %w", item.ID, err)
		}
		entry, err := entrypointForManifest(manifest)
		if err != nil {
			return nil, err
		}
		fullEntrypoint, err := pathInPluginDir(item.Path, entry)
		if err != nil {
			return nil, fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
		}
		snapshot, err := readRuntimeSnapshot(item.Path)
		if err != nil {
			return nil, fmt.Errorf("read installed plugin %s: %w", item.ID, err)
		}
		infos = append(infos, Info{
			Manifest:           manifest,
			DetectorDescriptor: cloneDetectorDescriptor(snapshot.DetectorDescriptor),
			MatcherDescriptor:  cloneMatcherDescriptor(snapshot.MatcherDescriptor),
			AuditorDescriptor:  cloneAuditorDescriptor(snapshot.AuditorDescriptor),
			Installed:          new(item),
			Enabled:            item.Enabled,
			Entrypoint:         fullEntrypoint,
			SourceType:         "external",
		})
	}
	return infos, nil
}

// ListPluginInfos returns built-in and installed plugin info in one list.
func ListPluginInfos(root string, builtins []Info) ([]Info, error) {
	installed, err := LoadInstalledPlugins(root)
	if err != nil {
		return nil, err
	}
	all := append(append([]Info(nil), builtins...), installed...)
	sort.Slice(all, func(i, j int) bool {
		if all[i].ID == all[j].ID {
			return all[i].Version < all[j].Version
		}
		return all[i].ID < all[j].ID
	})
	return all, nil
}

// LoadRuntimePlugins loads enabled external plugins.
func LoadRuntimePlugins(root string) ([]Info, error) {
	var err error
	root, err = resolveRoot(root)
	if err != nil {
		return nil, err
	}
	db, err := loadInstalledDB(root)
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(db.Plugins))
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
		fullEntrypoint, err := pathInPluginDir(item.Path, entry)
		if err != nil {
			return nil, fmt.Errorf("plugin entrypoint %q must stay within the plugin directory", entry)
		}
		snapshot, err := readRuntimeSnapshot(item.Path)
		if err != nil {
			return nil, fmt.Errorf("read installed plugin %s: %w", item.ID, err)
		}
		out = append(out, Info{
			Manifest:           manifest,
			DetectorDescriptor: cloneDetectorDescriptor(snapshot.DetectorDescriptor),
			MatcherDescriptor:  cloneMatcherDescriptor(snapshot.MatcherDescriptor),
			AuditorDescriptor:  cloneAuditorDescriptor(snapshot.AuditorDescriptor),
			Installed:          new(item),
			Enabled:            item.Enabled,
			Entrypoint:         fullEntrypoint,
			SourceType:         "external",
		})
	}
	return out, nil
}

func detectorDescriptorEqual(left, right *plugschema.DetectorDescriptor) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return componentDescriptorEqual(componentFromDetectorDescriptor(*left), componentFromDetectorDescriptor(*right)) &&
		left.Technique == right.Technique &&
		packageManagerSupportEqual(left.PackageManagerSupport, right.PackageManagerSupport) &&
		slices.Equal(left.FallbackDetectors, right.FallbackDetectors) &&
		left.SupportsInstallFirst == right.SupportsInstallFirst
}

func matcherDescriptorEqual(left, right *plugschema.MatcherDescriptor) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return componentDescriptorEqual(componentFromMatcherDescriptor(*left), componentFromMatcherDescriptor(*right))
}

func auditorDescriptorEqual(left, right *plugschema.AuditorDescriptor) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return componentDescriptorEqual(componentFromAuditorDescriptor(*left), componentFromAuditorDescriptor(*right))
}

func componentDescriptorEqual(left, right plugschema.ComponentDescriptor) bool {
	return left.Name == right.Name &&
		left.DisplayName == right.DisplayName &&
		slices.Equal(left.Aliases, right.Aliases) &&
		slices.Equal(left.Tags, right.Tags) &&
		slices.Equal(left.SupportedEcosystems, right.SupportedEcosystems) &&
		slices.Equal(left.SupportedManagers, right.SupportedManagers)
}

func componentFromDetectorDescriptor(descriptor plugschema.DetectorDescriptor) plugschema.ComponentDescriptor {
	return plugschema.ComponentDescriptor{Name: descriptor.Name, DisplayName: descriptor.DisplayName, Aliases: descriptor.Aliases, Tags: descriptor.Tags, SupportedEcosystems: descriptor.SupportedEcosystems, SupportedManagers: descriptor.SupportedManagers}
}

func componentFromMatcherDescriptor(descriptor plugschema.MatcherDescriptor) plugschema.ComponentDescriptor {
	return plugschema.ComponentDescriptor(descriptor)
}

func componentFromAuditorDescriptor(descriptor plugschema.AuditorDescriptor) plugschema.ComponentDescriptor {
	return plugschema.ComponentDescriptor(descriptor)
}

func cloneDetectorDescriptor(descriptor *plugschema.DetectorDescriptor) *plugschema.DetectorDescriptor {
	if descriptor == nil {
		return nil
	}
	copyValue := *descriptor
	copyValue.SupportedEcosystems = append([]plugschema.Ecosystem(nil), descriptor.SupportedEcosystems...)
	copyValue.SupportedManagers = append([]plugschema.PackageManager(nil), descriptor.SupportedManagers...)
	copyValue.PackageManagerSupport = clonePackageManagerSupport(descriptor.PackageManagerSupport)
	copyValue.Tags = append([]string(nil), descriptor.Tags...)
	copyValue.FallbackDetectors = append([]string(nil), descriptor.FallbackDetectors...)
	copyValue.IgnoredDirectories = append([]string(nil), descriptor.IgnoredDirectories...)
	copyValue.IgnoredDirectoryMarkers = append([]string(nil), descriptor.IgnoredDirectoryMarkers...)
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
	copyValue.Aliases = append([]string(nil), descriptor.Aliases...)
	copyValue.Tags = append([]string(nil), descriptor.Tags...)
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
