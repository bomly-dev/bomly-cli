package registry

import (
	"reflect"
	"testing"
)

// TestPlannedChainSnapshot pins the exact planned chain per package manager so
// any future re-wiring of the detector catalog is a conscious, reviewed edit.
//
// History: before the host executed planned chains first-success, detector
// order was encoded in per-detector Fallback fields. A parity test on the old
// wiring proved that DetectorNamesForPackageManager matched the Fallback-walk
// order for every package manager, so this snapshot is the behavioral
// continuation of that wiring. The npm/pnpm/yarn chains collapsed to
// [<manager>, syft-detector] when the lockfile and build-tool detectors were
// merged into one detector per manager that owns the lockfile→buildtool
// order internally.
func TestPlannedChainSnapshot(t *testing.T) {
	// Managers not listed here are Syft-only: their chain is exactly
	// ["syft-detector"].
	expected := map[string][]string{
		"npm":            {"npm", "syft-detector"},
		"pnpm":           {"pnpm", "syft-detector"},
		"yarn":           {"yarn", "syft-detector"},
		"bun":            {"bun-detector", "bun-native-detector", "syft-detector"},
		"gradle":         {"gradle-detector", "syft-detector"},
		"maven":          {"maven-detector", "syft-detector"},
		"gomod":          {"go-detector", "syft-detector"},
		"composer":       {"composer-detector", "syft-detector"},
		"bundler":        {"bundler-detector", "syft-detector"},
		"github-actions": {"github-actions-detector", "syft-detector"},
		"pip":            {"pip-detector", "syft-detector"},
		"pipenv":         {"pipenv-detector", "syft-detector"},
		"poetry":         {"poetry-detector", "syft-detector"},
		"uv":             {"uv-detector", "syft-detector"},
		"nuget":          {"nuget-detector", "syft-detector"},
		"cargo":          {"cargo-detector", "syft-detector"},
		"pub":            {"pub-native-detector", "pub-detector", "syft-detector"},
		"cocoapods":      {"cocoapods-detector", "syft-detector"},
		"swiftpm":        {"swiftpm-native-detector", "swiftpm-detector", "syft-detector"},
		"mix":            {"mix-detector", "syft-detector"},
		"conan":          {"conan-detector", "syft-detector"},
		"sbt":            {"sbt-native-detector", "sbt-detector", "syft-detector"},
		"sbom":           {"sbom-detector"},
	}

	seen := map[string]bool{}
	for _, manager := range SupportedPackageManagers() {
		chain := DetectorNamesForPackageManager(manager)
		want, ok := expected[manager.Name()]
		if !ok {
			want = []string{"syft-detector"}
		} else {
			seen[manager.Name()] = true
		}
		if !reflect.DeepEqual(chain, want) {
			t.Errorf("package manager %q: planned chain %v != snapshot %v", manager.Name(), chain, want)
		}
	}
	for name := range expected {
		if !seen[name] {
			t.Errorf("snapshot entry %q is not a supported package manager", name)
		}
	}
}
