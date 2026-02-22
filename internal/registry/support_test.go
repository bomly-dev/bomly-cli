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
	want := []string{detectors.NameNPM, detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected npm detector chain %v, got %v", want, chain)
	}

	chain = DetectorNamesForPackageManager(model.PackageManagerCargo)
	want = []string{detectors.NameSyft}
	if !reflect.DeepEqual(chain, want) {
		t.Fatalf("expected cargo detector chain %v, got %v", want, chain)
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
