package registry

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestSupportCatalogEvidencePatterns(t *testing.T) {
	patterns := EvidencePatternsForPackageManager(sdk.PackageManagerGoMod)
	want := []string{"go.mod"}
	if !reflect.DeepEqual(patterns, want) {
		t.Fatalf("expected gomod evidence %v, got %v", want, patterns)
	}

	patterns[0] = "changed"
	if got := EvidencePatternsForPackageManager(sdk.PackageManagerGoMod); !reflect.DeepEqual(got, want) {
		t.Fatalf("expected evidence patterns to be copied, got %v", got)
	}

}

func TestSupportCatalogDetectorChainOrdering(t *testing.T) {
	chain := DetectorNamesForPackageManager(sdk.PackageManagerNPM)
	want := []string{detectors.NameNPM, detectors.NameNPMNative, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected npm detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(sdk.PackageManagerPNPM)
	want = []string{detectors.NamePNPM, detectors.NamePNPMNative, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected pnpm detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(sdk.PackageManagerYarn)
	want = []string{detectors.NameYarn, detectors.NameYarnNative, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected yarn detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(sdk.PackageManagerBun)
	want = []string{detectors.NameBun, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected Bun detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(sdk.PackageManagerCargo)
	want = []string{detectors.NameCargo, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected cargo detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(sdk.PackageManagerSBT)
	want = []string{detectors.NameSBTNative, detectors.NameSBT}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected sbt detector chain %v, got %v", want, chain)
	}

	for _, tc := range []struct {
		manager sdk.PackageManager
		native  string
	}{
		{manager: sdk.PackageManagerNuGet, native: detectors.NameNuGet},
		{manager: sdk.PackageManagerPub, native: detectors.NamePubNative},
		{manager: sdk.PackageManagerCocoaPods, native: detectors.NameCocoaPods},
		{manager: sdk.PackageManagerSwiftPM, native: detectors.NameSwiftPMNative},
		{manager: sdk.PackageManagerMix, native: detectors.NameMix},
		{manager: sdk.PackageManagerConan, native: detectors.NameConan},
	} {
		chain = DetectorNamesForPackageManager(tc.manager)
		want = []string{tc.native}
		if tc.manager == sdk.PackageManagerPub {
			want = append(want, detectors.NamePub)
		}
		if tc.manager == sdk.PackageManagerSwiftPM {
			want = append(want, detectors.NameSwiftPM)
		}
		want = append(want, detectors.NameSyft)
		if !reflect.DeepEqual(chain, want) {
			t.Fatalf("expected %s detector chain %v, got %v", tc.manager.Name(), want, chain)
		}
	}
}

func TestSupportEntriesForTechniqueFiltersEvidencePatterns(t *testing.T) {
	for _, tc := range []struct {
		name           string
		manager        sdk.PackageManager
		technique      sdk.DetectorTechnique
		wantDetectors  []string
		wantEvidence   []string
		rejectEvidence []string
	}{
		{
			name:           "pub native",
			manager:        sdk.PackageManagerPub,
			technique:      sdk.BuildToolTechnique,
			wantDetectors:  []string{detectors.NamePubNative},
			wantEvidence:   []string{"pubspec.lock", "pubspec.yaml", "pubspec.yml"},
			rejectEvidence: []string{},
		},
		{
			name:           "swiftpm native",
			manager:        sdk.PackageManagerSwiftPM,
			technique:      sdk.BuildToolTechnique,
			wantDetectors:  []string{detectors.NameSwiftPMNative},
			wantEvidence:   []string{"Package.resolved", ".package.resolved", "Package.swift", "project.xcworkspace/xcshareddata/swiftpm/Package.resolved"},
			rejectEvidence: []string{},
		},
		{
			name:           "sbt native",
			manager:        sdk.PackageManagerSBT,
			technique:      sdk.BuildToolTechnique,
			wantDetectors:  []string{detectors.NameSBTNative},
			wantEvidence:   []string{"build.sbt", "project/plugins.sbt", "project/build.properties"},
			rejectEvidence: []string{},
		},
		{
			name:           "npm native fallback",
			manager:        sdk.PackageManagerNPM,
			technique:      sdk.BuildToolTechnique,
			wantDetectors:  []string{detectors.NameNPMNative},
			wantEvidence:   []string{"package.json"},
			rejectEvidence: []string{"package-lock.json"},
		},
		{
			name:           "swiftpm lockfile",
			manager:        sdk.PackageManagerSwiftPM,
			technique:      sdk.LockfileTechnique,
			wantDetectors:  []string{detectors.NameSwiftPM},
			wantEvidence:   []string{"Package.resolved", ".package.resolved", "Package.swift", "project.xcworkspace/xcshareddata/swiftpm/Package.resolved"},
			rejectEvidence: []string{},
		},
		{
			name:           "mix lockfile",
			manager:        sdk.PackageManagerMix,
			technique:      sdk.LockfileTechnique,
			wantDetectors:  []string{detectors.NameMix},
			wantEvidence:   []string{"mix.lock", "mix.exs"},
			rejectEvidence: []string{},
		},
		{
			name:           "conan lockfile",
			manager:        sdk.PackageManagerConan,
			technique:      sdk.LockfileTechnique,
			wantDetectors:  []string{detectors.NameConan},
			wantEvidence:   []string{"conan.lock", "conanfile.txt", "conanfile.py", "conaninfo.txt"},
			rejectEvidence: []string{},
		},
		{
			name:           "sbt manifest",
			manager:        sdk.PackageManagerSBT,
			technique:      sdk.ManifestTechnique,
			wantDetectors:  []string{detectors.NameSBT},
			wantEvidence:   []string{"build.sbt", "project/plugins.sbt", "project/build.properties"},
			rejectEvidence: []string{},
		},
		{
			name:           "npm lockfile",
			manager:        sdk.PackageManagerNPM,
			technique:      sdk.LockfileTechnique,
			wantDetectors:  []string{detectors.NameNPM},
			wantEvidence:   []string{"npm-shrinkwrap.json", "package-lock.json"},
			rejectEvidence: []string{},
		},
		{
			name:           "cargo lockfile",
			manager:        sdk.PackageManagerCargo,
			technique:      sdk.LockfileTechnique,
			wantDetectors:  []string{detectors.NameCargo},
			wantEvidence:   []string{"Cargo.lock", "Cargo.toml"},
			rejectEvidence: []string{},
		},
		{
			name:           "cargo multiple",
			manager:        sdk.PackageManagerCargo,
			technique:      sdk.MultipleTechnique,
			wantDetectors:  []string{detectors.NameSyft},
			wantEvidence:   []string{"Cargo.lock"},
			rejectEvidence: []string{"Cargo.toml"},
		},
		{
			name:           "nuget multiple",
			manager:        sdk.PackageManagerNuGet,
			technique:      sdk.MultipleTechnique,
			wantDetectors:  []string{detectors.NameSyft},
			wantEvidence:   []string{"packages.lock.json", "*.deps.json"},
			rejectEvidence: []string{"packages.config", "*.csproj", "*.fsproj", "*.vbproj", "*.vcxproj", "project.assets.json"},
		},
		{
			name:           "pub multiple",
			manager:        sdk.PackageManagerPub,
			technique:      sdk.MultipleTechnique,
			wantDetectors:  []string{detectors.NameSyft},
			wantEvidence:   []string{"pubspec.yml", "pubspec.yaml", "pubspec.lock"},
			rejectEvidence: []string{},
		},
		{
			name:           "cocoapods multiple",
			manager:        sdk.PackageManagerCocoaPods,
			technique:      sdk.MultipleTechnique,
			wantDetectors:  []string{detectors.NameSyft},
			wantEvidence:   []string{"Podfile.lock"},
			rejectEvidence: []string{"Podfile"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry, ok := supportEntryForManager(SupportEntriesForTechnique(tc.technique), tc.manager)
			if !ok {
				t.Fatalf("expected support entry for %s", tc.manager.Name())
			}
			if !reflect.DeepEqual(entry.Detectors, tc.wantDetectors) {
				t.Fatalf("expected detectors %v, got %v", tc.wantDetectors, entry.Detectors)
			}
			if !reflect.DeepEqual(entry.EvidencePatterns, tc.wantEvidence) {
				t.Fatalf("expected evidence %v, got %v", tc.wantEvidence, entry.EvidencePatterns)
			}
			for _, rejected := range tc.rejectEvidence {
				for _, pattern := range entry.EvidencePatterns {
					if pattern == rejected {
						t.Fatalf("did not expect %q in %s evidence %v", rejected, tc.technique, entry.EvidencePatterns)
					}
				}
			}
		})
	}

	wantMerged := []string{"Cargo.lock", "Cargo.toml"}
	if got := EvidencePatternsForPackageManager(sdk.PackageManagerCargo); !reflect.DeepEqual(got, wantMerged) {
		t.Fatalf("expected merged cargo evidence %v, got %v", wantMerged, got)
	}
}

func TestSupportCatalogExcludesOtherSentinel(t *testing.T) {
	for _, manager := range SupportedPackageManagers() {
		if manager == sdk.PackageManagerOther {
			t.Fatal("expected built-in support catalog to exclude other package manager")
		}
	}
	if patterns := EvidencePatternsForPackageManager(sdk.PackageManagerOther); len(patterns) != 0 {
		t.Fatalf("expected no built-in evidence for other package manager, got %v", patterns)
	}
	if chain := DetectorNamesForPackageManager(sdk.PackageManagerOther); len(chain) != 0 {
		t.Fatalf("expected no built-in detector chain for other package manager, got %v", chain)
	}
}

func supportEntryForManager(entries []PackageManagerSupport, manager sdk.PackageManager) (PackageManagerSupport, bool) {
	for _, entry := range entries {
		if entry.Manager == manager {
			return entry, true
		}
	}
	return PackageManagerSupport{}, false
}
