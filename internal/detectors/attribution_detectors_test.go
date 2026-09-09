package detectors_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/cargo"
	"github.com/bomly-dev/bomly-cli/internal/detectors/cocoapods"
	"github.com/bomly-dev/bomly-cli/internal/detectors/composer"
	"github.com/bomly-dev/bomly-cli/internal/detectors/conan"
	"github.com/bomly-dev/bomly-cli/internal/detectors/mix"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-cli/internal/detectors/nuget"
	"github.com/bomly-dev/bomly-cli/internal/detectors/pub"
	"github.com/bomly-dev/bomly-cli/internal/detectors/python"
	"github.com/bomly-dev/bomly-cli/internal/detectors/ruby"
	"github.com/bomly-dev/bomly-cli/internal/detectors/swiftpm"
	sdk "github.com/bomly-dev/bomly-sdk"
)

// Two detectors are absent on purpose. The bun detector attaches no positions,
// so it emits no locations for attribution to land on; the go detector runs the
// go toolchain, and its own package covers the same ground without it.
//
// TestDetectorsAttributeTheirLocations drives the file-backed detectors over
// their own fixtures and checks the attribution reaches the locations they
// emit. One table rather than a copy per package: the rule is the same for all
// of them, and a detector added to the registry without a module root is the
// failure this catches.
func TestDetectorsAttributeTheirLocations(t *testing.T) {
	cases := []struct {
		name     string
		fixture  string
		resolve  func(string) (sdk.DetectionResult, error)
		wantRoot string
	}{
		{
			name:    "cargo",
			fixture: "cargo/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return cargo.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "cocoapods",
			fixture: "cocoapods/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return cocoapods.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "composer",
			fixture: "composer/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return composer.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "conan",
			fixture: "conan/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return conan.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "mix",
			fixture: "mix/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return mix.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "nuget",
			fixture: "nuget/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return nuget.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "pub",
			fixture: "pub/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return pub.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "ruby",
			fixture: "ruby/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return ruby.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "swiftpm",
			fixture: "swiftpm/testdata/project",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return swiftpm.Detector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "pnpm",
			fixture: "node/testdata/lockfiles/pnpm-v9",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return pnpm.LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "yarn",
			fixture: "node/testdata/lockfiles/yarn-v1",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return yarn.LockfileDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "poetry",
			fixture: "python/testdata/lockfiles/poetry",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return python.PoetryDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "uv",
			fixture: "python/testdata/lockfiles/uv",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return python.UVDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "pip",
			fixture: "python/testdata/lockfiles/pip",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return python.PipDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
		{
			name:    "pipenv",
			fixture: "python/testdata/lockfiles/pipenv",
			resolve: func(dir string) (sdk.DetectionResult, error) {
				return python.PipenvDetector{}.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: dir})
			},
			wantRoot: ".",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := testCase.resolve(filepath.Join("..", "detectors", filepath.FromSlash(testCase.fixture)))
			if err != nil {
				t.Fatalf("ResolveGraph() error = %v", err)
			}
			if result.Graphs == nil {
				t.Fatal("expected resolved graphs")
			}
			attributed := 0
			for _, entry := range result.Graphs.Entries {
				for _, dep := range entry.Graph.DependencyNodes() {
					for _, location := range dep.Locations {
						if location.ModuleRoot != testCase.wantRoot {
							t.Fatalf("%s: location %+v was not attributed to %q", dep.NodeID(), location, testCase.wantRoot)
						}
						if location.Relationship == "" {
							t.Fatalf("%s: location %+v carries no relationship", dep.NodeID(), location)
						}
						attributed++
					}
				}
			}
			if attributed == 0 {
				t.Fatal("this fixture emits locations, so attributing none means the wiring is missing")
			}
		})
	}
}
