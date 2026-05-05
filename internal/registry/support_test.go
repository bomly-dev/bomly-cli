package registry

import (
	"reflect"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

func TestSupportCatalogEvidencePatterns(t *testing.T) {
	patterns := EvidencePatternsForPackageManager(model.PackageManagerGoMod)
	want := []string{"go.mod"}
	if !reflect.DeepEqual(patterns, want) {
		t.Fatalf("expected gomod evidence %v, got %v", want, patterns)
	}

	patterns[0] = "changed"
	if got := EvidencePatternsForPackageManager(model.PackageManagerGoMod); !reflect.DeepEqual(got, want) {
		t.Fatalf("expected evidence patterns to be copied, got %v", got)
	}

}

func TestSupportCatalogDetectorChainOrdering(t *testing.T) {
	chain := DetectorNamesForPackageManager(model.PackageManagerNPM)
	want := []string{detectors.NameNPM, detectors.NameNPMNative, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected npm detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(model.PackageManagerPNPM)
	want = []string{detectors.NamePNPM, detectors.NamePNPMNative, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected pnpm detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(model.PackageManagerYarn)
	want = []string{detectors.NameYarn, detectors.NameYarnNative, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected yarn detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(model.PackageManagerCargo)
	want = []string{detectors.NameCargo, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected cargo detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(model.PackageManagerSBT)
	want = []string{detectors.NameSBT}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected sbt detector chain %v, got %v", want, chain)
	}

	for _, tc := range []struct {
		manager model.PackageManager
		native  string
	}{
		{manager: model.PackageManagerNuGet, native: detectors.NameNuGet},
		{manager: model.PackageManagerPub, native: detectors.NamePub},
		{manager: model.PackageManagerCocoaPods, native: detectors.NameCocoaPods},
		{manager: model.PackageManagerSwiftPM, native: detectors.NameSwiftPM},
		{manager: model.PackageManagerMix, native: detectors.NameMix},
		{manager: model.PackageManagerConan, native: detectors.NameConan},
	} {
		chain = DetectorNamesForPackageManager(tc.manager)
		want = []string{tc.native, detectors.NameSyft}
		if !reflect.DeepEqual(chain, want) {
			t.Fatalf("expected %s detector chain %v, got %v", tc.manager.Name(), want, chain)
		}
	}
}

func TestSupportEntriesForTechniqueFiltersEvidencePatterns(t *testing.T) {
	for _, tc := range []struct {
		name           string
		manager        model.PackageManager
		technique      model.DetectorTechnique
		wantDetectors  []string
		wantEvidence   []string
		rejectEvidence []string
	}{
		{
			name:           "npm native fallback",
			manager:        model.PackageManagerNPM,
			technique:      model.BuildToolTechnique,
			wantDetectors:  []string{detectors.NameNPMNative},
			wantEvidence:   []string{"package.json"},
			rejectEvidence: []string{"package-lock.json"},
		},
		{
			name:           "swiftpm lockfile",
			manager:        model.PackageManagerSwiftPM,
			technique:      model.LockfileTechnique,
			wantDetectors:  []string{detectors.NameSwiftPM},
			wantEvidence:   []string{"Package.resolved", ".package.resolved", "Package.swift", "project.xcworkspace/xcshareddata/swiftpm/Package.resolved"},
			rejectEvidence: []string{},
		},
		{
			name:           "mix lockfile",
			manager:        model.PackageManagerMix,
			technique:      model.LockfileTechnique,
			wantDetectors:  []string{detectors.NameMix},
			wantEvidence:   []string{"mix.lock", "mix.exs"},
			rejectEvidence: []string{},
		},
		{
			name:           "conan lockfile",
			manager:        model.PackageManagerConan,
			technique:      model.LockfileTechnique,
			wantDetectors:  []string{detectors.NameConan},
			wantEvidence:   []string{"conan.lock", "conanfile.txt", "conanfile.py", "conaninfo.txt"},
			rejectEvidence: []string{},
		},
		{
			name:           "sbt manifest",
			manager:        model.PackageManagerSBT,
			technique:      model.ManifestTechnique,
			wantDetectors:  []string{detectors.NameSBT},
			wantEvidence:   []string{"build.sbt", "project/plugins.sbt", "project/build.properties"},
			rejectEvidence: []string{},
		},
		{
			name:           "npm lockfile",
			manager:        model.PackageManagerNPM,
			technique:      model.LockfileTechnique,
			wantDetectors:  []string{detectors.NameNPM},
			wantEvidence:   []string{"package-lock.json"},
			rejectEvidence: []string{},
		},
		{
			name:           "cargo lockfile",
			manager:        model.PackageManagerCargo,
			technique:      model.LockfileTechnique,
			wantDetectors:  []string{detectors.NameCargo},
			wantEvidence:   []string{"Cargo.lock", "Cargo.toml"},
			rejectEvidence: []string{},
		},
		{
			name:           "cargo multiple",
			manager:        model.PackageManagerCargo,
			technique:      model.MultipleTechnique,
			wantDetectors:  []string{detectors.NameSyft},
			wantEvidence:   []string{"Cargo.lock"},
			rejectEvidence: []string{"Cargo.toml"},
		},
		{
			name:           "nuget multiple",
			manager:        model.PackageManagerNuGet,
			technique:      model.MultipleTechnique,
			wantDetectors:  []string{detectors.NameSyft},
			wantEvidence:   []string{"packages.lock.json", "*.deps.json"},
			rejectEvidence: []string{"packages.config", "*.csproj", "*.fsproj", "*.vbproj", "*.vcxproj", "project.assets.json"},
		},
		{
			name:           "pub multiple",
			manager:        model.PackageManagerPub,
			technique:      model.MultipleTechnique,
			wantDetectors:  []string{detectors.NameSyft},
			wantEvidence:   []string{"pubspec.yml", "pubspec.yaml", "pubspec.lock"},
			rejectEvidence: []string{},
		},
		{
			name:           "cocoapods multiple",
			manager:        model.PackageManagerCocoaPods,
			technique:      model.MultipleTechnique,
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
	if got := EvidencePatternsForPackageManager(model.PackageManagerCargo); !reflect.DeepEqual(got, wantMerged) {
		t.Fatalf("expected merged cargo evidence %v, got %v", wantMerged, got)
	}
}

func TestSupportCatalogExcludesOtherSentinel(t *testing.T) {
	for _, manager := range SupportedPackageManagers() {
		if manager == model.PackageManagerOther {
			t.Fatal("expected built-in support catalog to exclude other package manager")
		}
	}
	if patterns := EvidencePatternsForPackageManager(model.PackageManagerOther); len(patterns) != 0 {
		t.Fatalf("expected no built-in evidence for other package manager, got %v", patterns)
	}
	if chain := DetectorNamesForPackageManager(model.PackageManagerOther); len(chain) != 0 {
		t.Fatalf("expected no built-in detector chain for other package manager, got %v", chain)
	}
}

func supportEntryForManager(entries []PackageManagerSupport, manager model.PackageManager) (PackageManagerSupport, bool) {
	for _, entry := range entries {
		if entry.Manager == manager {
			return entry, true
		}
	}
	return PackageManagerSupport{}, false
}
