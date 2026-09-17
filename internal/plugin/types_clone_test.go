package plugin

import (
	"encoding/json"
	"testing"

	"github.com/bomly-dev/bomly-sdk/model"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

func TestCloneDetectorDescriptorDeepCopiesDiscoveryFields(t *testing.T) {
	original := &sdkplugin.DetectorDescriptor{
		Name:                    "example",
		Aliases:                 []string{"example-alias"},
		Tags:                    []string{"dependency-detection"},
		IgnoredDirectories:      []string{"node_modules"},
		IgnoredDirectoryMarkers: []string{"pyvenv.cfg"},
		PackageManagerSupport: []sdkplugin.PackageManagerSupport{
			sdkplugin.Support(model.PackageManagerNPM, "package.json").WithMultiModule(),
		},
		RemediationCapabilities: []sdkplugin.RemediationCapability{{
			SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
			Actions:           []model.RemediationAction{model.RemediationActionDirectBump},
		}},
	}
	clone := cloneDetectorDescriptor(original)

	if got := clone.IgnoredDirectories; len(got) != 1 || got[0] != "node_modules" {
		t.Fatalf("expected cloned ignored directories, got %#v", got)
	}
	if got := clone.IgnoredDirectoryMarkers; len(got) != 1 || got[0] != "pyvenv.cfg" {
		t.Fatalf("expected cloned ignored directory markers, got %#v", got)
	}
	if len(clone.PackageManagerSupport) != 1 || !clone.PackageManagerSupport[0].MultiModule {
		t.Fatalf("expected MultiModule to survive cloning, got %#v", clone.PackageManagerSupport)
	}

	// Mutating the clone's slices must not touch the original.
	clone.IgnoredDirectories[0] = "mutated"
	clone.IgnoredDirectoryMarkers[0] = "mutated"
	clone.Aliases[0] = "mutated"
	clone.Tags[0] = "mutated"
	clone.PackageManagerSupport[0].EvidencePatterns[0] = "mutated"
	clone.RemediationCapabilities[0].SupportedManagers[0] = model.PackageManagerGoMod
	clone.RemediationCapabilities[0].Actions[0] = model.RemediationActionLockfileRefresh
	if original.IgnoredDirectories[0] != "node_modules" ||
		original.IgnoredDirectoryMarkers[0] != "pyvenv.cfg" ||
		original.Aliases[0] != "example-alias" ||
		original.Tags[0] != "dependency-detection" ||
		original.PackageManagerSupport[0].EvidencePatterns[0] != "package.json" ||
		original.RemediationCapabilities[0].SupportedManagers[0] != model.PackageManagerNPM ||
		original.RemediationCapabilities[0].Actions[0] != model.RemediationActionDirectBump {
		t.Fatal("clone shares backing arrays with the original descriptor")
	}
}

func TestCloneMatcherDescriptorDeepCopiesSlices(t *testing.T) {
	original := &sdkplugin.MatcherDescriptor{
		Name:                "matcher",
		Aliases:             []string{"matcher-alias"},
		Tags:                []string{"vulnerability"},
		SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:   []model.PackageManager{model.PackageManagerNPM},
		Capabilities:        []string{sdkplugin.CapabilityPackageUpdates},
		ConfigSchema:        json.RawMessage(`{"type":"object"}`),
	}
	clone := cloneMatcherDescriptor(original)
	clone.Aliases[0] = "mutated"
	clone.Tags[0] = "mutated"
	clone.SupportedEcosystems[0] = model.EcosystemGo
	clone.SupportedManagers[0] = model.PackageManagerGoMod
	clone.Capabilities[0] = "mutated"
	clone.ConfigSchema[0] = 'X'
	if original.Aliases[0] != "matcher-alias" ||
		original.Tags[0] != "vulnerability" ||
		original.SupportedEcosystems[0] != model.EcosystemNPM ||
		original.SupportedManagers[0] != model.PackageManagerNPM ||
		original.Capabilities[0] != sdkplugin.CapabilityPackageUpdates ||
		original.ConfigSchema[0] != '{' {
		t.Fatal("matcher clone shares backing arrays with the original descriptor")
	}
}

func TestCloneAuditorDescriptorDeepCopiesSlices(t *testing.T) {
	original := &sdkplugin.AuditorDescriptor{
		Name:                "auditor",
		Aliases:             []string{"auditor-alias"},
		Tags:                []string{"policy"},
		SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM},
		SupportedManagers:   []model.PackageManager{model.PackageManagerNPM},
		ConfigSchema:        json.RawMessage(`{"type":"object"}`),
	}
	clone := cloneAuditorDescriptor(original)
	clone.Aliases[0] = "mutated"
	clone.Tags[0] = "mutated"
	clone.SupportedEcosystems[0] = model.EcosystemGo
	clone.SupportedManagers[0] = model.PackageManagerGoMod
	clone.ConfigSchema[0] = 'X'
	if original.Aliases[0] != "auditor-alias" ||
		original.Tags[0] != "policy" ||
		original.SupportedEcosystems[0] != model.EcosystemNPM ||
		original.SupportedManagers[0] != model.PackageManagerNPM ||
		original.ConfigSchema[0] != '{' {
		t.Fatal("auditor clone shares backing arrays with the original descriptor")
	}
}

func TestCloneAnalyzerDescriptorDeepCopiesSlices(t *testing.T) {
	original := &sdkplugin.AnalyzerDescriptor{
		Name:                "analyzer",
		Aliases:             []string{"analyzer-alias"},
		Tags:                []string{"reachability"},
		SupportedEcosystems: []model.Ecosystem{model.EcosystemGo},
		SupportedManagers:   []model.PackageManager{model.PackageManagerGoMod},
		SupportedLanguages:  []model.Language{model.LanguageGo},
		SupportedTiers:      []model.ReachabilityTier{model.TierSymbol},
		Capabilities:        []string{sdkplugin.CapabilityPackageUpdates},
		ConfigSchema:        json.RawMessage(`{"type":"object"}`),
	}
	clone := cloneAnalyzerDescriptor(original)
	clone.Aliases[0] = "mutated"
	clone.Tags[0] = "mutated"
	clone.SupportedEcosystems[0] = model.EcosystemNPM
	clone.SupportedManagers[0] = model.PackageManagerNPM
	clone.SupportedLanguages[0] = model.LanguageJavaScript
	clone.SupportedTiers[0] = model.TierPackage
	clone.Capabilities[0] = "mutated"
	clone.ConfigSchema[0] = 'X'
	if original.Aliases[0] != "analyzer-alias" ||
		original.Tags[0] != "reachability" ||
		original.SupportedEcosystems[0] != model.EcosystemGo ||
		original.SupportedManagers[0] != model.PackageManagerGoMod ||
		original.SupportedLanguages[0] != model.LanguageGo ||
		original.SupportedTiers[0] != model.TierSymbol ||
		original.Capabilities[0] != sdkplugin.CapabilityPackageUpdates ||
		original.ConfigSchema[0] != '{' {
		t.Fatal("analyzer clone shares backing arrays with the original descriptor")
	}
}

func TestValidateManifestAcceptsAnalyzerKind(t *testing.T) {
	manifest := withCanonicalManifestDefaults(Manifest{
		ID:         "acme.analyzer.fake",
		Name:       "acme analyzer",
		Version:    "1.0.0",
		Kind:       sdkplugin.PluginKindAnalyzer,
		Entrypoint: map[string]string{platformKey(): "bin/analyzer"},
	}, "test")
	if err := validateManifest(manifest); err != nil {
		t.Fatalf("validateManifest() rejected analyzer kind: %v", err)
	}
}

func TestRuntimeSnapshotRoundTripWithAnalyzerDescriptor(t *testing.T) {
	dir := t.TempDir()
	snapshot := RuntimeDescriptorSnapshot{
		ID:               "acme.analyzer.fake",
		Kind:             sdkplugin.PluginKindAnalyzer,
		PluginAPIVersion: sdkplugin.PluginAPIVersion,
		AnalyzerDescriptor: &sdkplugin.AnalyzerDescriptor{
			Name:               "acme.analyzer.fake",
			SupportedLanguages: []model.Language{model.LanguageGo},
			SupportedTiers:     []model.ReachabilityTier{model.TierSymbol},
			Capabilities:       []string{sdkplugin.CapabilityPackageUpdates},
			ConfigSchema:       json.RawMessage(`{"type":"object","additionalProperties":false}`),
		},
	}
	if err := writeRuntimeSnapshot(dir, snapshot); err != nil {
		t.Fatalf("writeRuntimeSnapshot() error = %v", err)
	}
	loaded, err := readRuntimeSnapshot(dir)
	if err != nil {
		t.Fatalf("readRuntimeSnapshot() error = %v", err)
	}
	if loaded.Kind != sdkplugin.PluginKindAnalyzer || loaded.AnalyzerDescriptor == nil {
		t.Fatalf("round-trip lost analyzer descriptor: %#v", loaded)
	}
	if !analyzerDescriptorEqual(loaded.AnalyzerDescriptor, snapshot.AnalyzerDescriptor) {
		t.Fatalf("analyzer descriptor round-trip mismatch: %#v", loaded.AnalyzerDescriptor)
	}
	if err := runtimeSnapshotMatchesSnapshot(loaded, normalizeRuntimeSnapshot(snapshot)); err != nil {
		t.Fatalf("runtimeSnapshotMatchesSnapshot() error = %v", err)
	}
}

func TestProtocolV1DetectorSnapshotDefaultsAbsentOptionalCapabilities(t *testing.T) {
	snapshot := RuntimeDescriptorSnapshot{
		ID:               "legacy-detector",
		Kind:             sdkplugin.PluginKindDetector,
		PluginAPIVersion: sdkplugin.PluginAPIVersion,
		DetectorDescriptor: &sdkplugin.DetectorDescriptor{
			Name: "legacy-detector",
			PackageManagerSupport: []sdkplugin.PackageManagerSupport{
				sdkplugin.Support(model.PackageManagerNPM, "package.json"),
			},
		},
	}
	normalized := normalizeRuntimeSnapshot(snapshot)
	if err := validateRuntimeSnapshot(normalized); err != nil {
		t.Fatalf("legacy protocol-v1 snapshot rejected: %v", err)
	}
	descriptor := normalized.DetectorDescriptor
	if descriptor.SupportsInstallFirst ||
		len(descriptor.IgnoredDirectories) != 0 ||
		len(descriptor.IgnoredDirectoryMarkers) != 0 ||
		len(descriptor.RemediationCapabilities) != 0 {
		t.Fatalf("absent optional capabilities did not retain safe defaults: %#v", descriptor)
	}
}

func TestRuntimeSnapshotRejectsUnadvertisedOrMalformedRole(t *testing.T) {
	tests := []struct {
		name     string
		snapshot RuntimeDescriptorSnapshot
	}{
		{
			name: "detector kind without detector descriptor",
			snapshot: RuntimeDescriptorSnapshot{
				ID: "broken", Kind: sdkplugin.PluginKindDetector,
				PluginAPIVersion:  sdkplugin.PluginAPIVersion,
				MatcherDescriptor: &sdkplugin.MatcherDescriptor{Name: "broken"},
			},
		},
		{
			name: "matcher kind with malformed descriptor",
			snapshot: RuntimeDescriptorSnapshot{
				ID: "broken", Kind: sdkplugin.PluginKindMatcher,
				PluginAPIVersion:  sdkplugin.PluginAPIVersion,
				MatcherDescriptor: &sdkplugin.MatcherDescriptor{},
			},
		},
		{
			name: "unknown API version",
			snapshot: RuntimeDescriptorSnapshot{
				ID: "broken", Kind: sdkplugin.PluginKindMatcher,
				PluginAPIVersion:  "bomly.plugin.v999",
				MatcherDescriptor: &sdkplugin.MatcherDescriptor{Name: "broken"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRuntimeSnapshot(normalizeRuntimeSnapshot(test.snapshot)); err == nil {
				t.Fatalf("validateRuntimeSnapshot accepted %#v", test.snapshot)
			}
		})
	}
}
