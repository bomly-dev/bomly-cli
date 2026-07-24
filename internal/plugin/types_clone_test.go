package plugin

import (
	"testing"

	plugschema "github.com/bomly-dev/bomly-cli/sdk"
)

func TestCloneDetectorDescriptorDeepCopiesDiscoveryFields(t *testing.T) {
	original := &plugschema.DetectorDescriptor{
		Name:                    "example",
		Aliases:                 []string{"example-alias"},
		Tags:                    []string{"dependency-detection"},
		IgnoredDirectories:      []string{"node_modules"},
		IgnoredDirectoryMarkers: []string{"pyvenv.cfg"},
		PackageManagerSupport: []plugschema.PackageManagerSupport{
			plugschema.Support(plugschema.PackageManagerNPM, "package.json").WithMultiModule(),
		},
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
	if original.IgnoredDirectories[0] != "node_modules" ||
		original.IgnoredDirectoryMarkers[0] != "pyvenv.cfg" ||
		original.Aliases[0] != "example-alias" ||
		original.Tags[0] != "dependency-detection" ||
		original.PackageManagerSupport[0].EvidencePatterns[0] != "package.json" {
		t.Fatal("clone shares backing arrays with the original descriptor")
	}
}

func TestCloneMatcherDescriptorDeepCopiesSlices(t *testing.T) {
	original := &plugschema.MatcherDescriptor{
		Name:                "matcher",
		Aliases:             []string{"matcher-alias"},
		Tags:                []string{"vulnerability"},
		SupportedEcosystems: []plugschema.Ecosystem{plugschema.EcosystemNPM},
		SupportedManagers:   []plugschema.PackageManager{plugschema.PackageManagerNPM},
	}
	clone := cloneMatcherDescriptor(original)
	clone.Aliases[0] = "mutated"
	clone.Tags[0] = "mutated"
	clone.SupportedEcosystems[0] = plugschema.EcosystemGo
	clone.SupportedManagers[0] = plugschema.PackageManagerGoMod
	if original.Aliases[0] != "matcher-alias" ||
		original.Tags[0] != "vulnerability" ||
		original.SupportedEcosystems[0] != plugschema.EcosystemNPM ||
		original.SupportedManagers[0] != plugschema.PackageManagerNPM {
		t.Fatal("matcher clone shares backing arrays with the original descriptor")
	}
}

func TestCloneAuditorDescriptorDeepCopiesSlices(t *testing.T) {
	original := &plugschema.AuditorDescriptor{
		Name:                "auditor",
		Aliases:             []string{"auditor-alias"},
		Tags:                []string{"policy"},
		SupportedEcosystems: []plugschema.Ecosystem{plugschema.EcosystemNPM},
		SupportedManagers:   []plugschema.PackageManager{plugschema.PackageManagerNPM},
	}
	clone := cloneAuditorDescriptor(original)
	clone.Aliases[0] = "mutated"
	clone.Tags[0] = "mutated"
	clone.SupportedEcosystems[0] = plugschema.EcosystemGo
	clone.SupportedManagers[0] = plugschema.PackageManagerGoMod
	if original.Aliases[0] != "auditor-alias" ||
		original.Tags[0] != "policy" ||
		original.SupportedEcosystems[0] != plugschema.EcosystemNPM ||
		original.SupportedManagers[0] != plugschema.PackageManagerNPM {
		t.Fatal("auditor clone shares backing arrays with the original descriptor")
	}
}

func TestProtocolV1DetectorSnapshotDefaultsAbsentOptionalCapabilities(t *testing.T) {
	snapshot := RuntimeDescriptorSnapshot{
		ID:               "legacy-detector",
		Kind:             plugschema.PluginKindDetector,
		PluginAPIVersion: plugschema.PluginAPIVersion,
		DetectorDescriptor: &plugschema.DetectorDescriptor{
			Name: "legacy-detector",
			PackageManagerSupport: []plugschema.PackageManagerSupport{
				plugschema.Support(plugschema.PackageManagerNPM, "package.json"),
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
		len(descriptor.IgnoredDirectoryMarkers) != 0 {
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
				ID: "broken", Kind: plugschema.PluginKindDetector,
				PluginAPIVersion:  plugschema.PluginAPIVersion,
				MatcherDescriptor: &plugschema.MatcherDescriptor{Name: "broken"},
			},
		},
		{
			name: "matcher kind with malformed descriptor",
			snapshot: RuntimeDescriptorSnapshot{
				ID: "broken", Kind: plugschema.PluginKindMatcher,
				PluginAPIVersion:  plugschema.PluginAPIVersion,
				MatcherDescriptor: &plugschema.MatcherDescriptor{},
			},
		},
		{
			name: "unknown API version",
			snapshot: RuntimeDescriptorSnapshot{
				ID: "broken", Kind: plugschema.PluginKindMatcher,
				PluginAPIVersion:  "bomly.plugin.v999",
				MatcherDescriptor: &plugschema.MatcherDescriptor{Name: "broken"},
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
