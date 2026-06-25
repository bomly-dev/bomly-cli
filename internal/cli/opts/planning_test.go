package opts

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

func TestPlanSubprojectsDetectsFilesystemPackageManager(t *testing.T) {
	projectDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()

	subprojects, err := PlanSubprojects(reg, Request{
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: projectDir},
	})
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if len(subprojects) != 1 {
		t.Fatalf("expected one subproject, got %#v", subprojects)
	}
	if got := subprojects[0].PrimaryPackageManager(); got != sdk.PackageManagerNPM {
		t.Fatalf("expected npm package manager, got %s", got)
	}
}

func TestPlanSubprojectsReportsActiveFilters(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()

	_, err := PlanSubprojects(reg, Request{
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: t.TempDir()},
		DetectorFilter:  sdk.DetectorFilter{Include: []string{"missing-detector"}},
	})
	if !errors.Is(err, ErrNoSubprojects) {
		t.Fatalf("expected ErrNoSubprojects, got %v", err)
	}
	// "Nothing to evaluate" (5), not a generic execution error (1) or a
	// resolution failure (3): no subprojects were discovered at all.
	if got := exit.Code(err); got != 5 {
		t.Fatalf("expected exit code 5 for no subprojects, got %d", got)
	}
}

func TestPlanSubprojectsNoFilterStillReportsNothingToEvaluate(t *testing.T) {
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()

	// Empty directory, no filter: still "nothing to evaluate" (exit 5), per the
	// with-or-without-filter scope.
	_, err := PlanSubprojects(reg, Request{
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: t.TempDir()},
	})
	if !errors.Is(err, ErrNoSubprojects) {
		t.Fatalf("expected ErrNoSubprojects, got %v", err)
	}
	if got := exit.Code(err); got != 5 {
		t.Fatalf("expected exit code 5 for an empty target, got %d", got)
	}
}

func TestPathPatternHelpers(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "bomly.spdx.json")
	if err := os.WriteFile(file, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write sbom file: %v", err)
	}

	if !pathMatchesPatterns(dir, []string{"*.spdx.json"}) {
		t.Fatal("expected directory pattern to match")
	}
	if matches := matchingPatternsForFile(file, []string{"*.spdx.json"}); len(matches) != 1 {
		t.Fatalf("expected file pattern match, got %#v", matches)
	}
	resolved, ok := resolveMatchedManifestPath(dir, []string{"*.spdx.json"})
	if !ok || resolved != file {
		t.Fatalf("expected resolved manifest %q, got %q (%v)", file, resolved, ok)
	}
}
