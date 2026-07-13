package opts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/cli/exit"
	"github.com/bomly-dev/bomly-cli/internal/engine"
	"github.com/bomly-dev/bomly-cli/sdk"
	"go.uber.org/zap"
)

// writeEvidenceFile creates an empty manifest evidence file at a slash-form
// path relative to root, creating parent directories as needed.
func writeEvidenceFile(t *testing.T, root, rel string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(full, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func planRecursive(t *testing.T, root string, mutate func(*Request)) ([]sdk.Subproject, error) {
	t.Helper()
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	req := Request{
		Registry:        reg,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root},
		Recursive:       true,
		MaxDepth:        3,
	}
	if mutate != nil {
		mutate(&req)
	}
	return PlanSubprojects(reg, req)
}

func subprojectRelPaths(subprojects []sdk.Subproject) []string {
	paths := make([]string, 0, len(subprojects))
	for _, subproject := range subprojects {
		paths = append(paths, subproject.RelativePath)
	}
	return paths
}

func subprojectManagersByPath(subprojects []sdk.Subproject) map[string]sdk.PackageManager {
	managers := make(map[string]sdk.PackageManager, len(subprojects))
	for _, subproject := range subprojects {
		managers[subproject.RelativePath] = subproject.PrimaryPackageManager()
	}
	return managers
}

func TestPlanSubprojectsRecursiveFindsNestedManifests(t *testing.T) {
	root := t.TempDir()
	// Mirrors the bomly-agent-study smoke fixture shape: no root manifest,
	// three ecosystems in nested directories.
	writeEvidenceFile(t, root, "fixtures/api-java/pom.xml")
	writeEvidenceFile(t, root, "fixtures/service/requirements.txt")
	writeEvidenceFile(t, root, "fixtures/webapp/package-lock.json")
	writeEvidenceFile(t, root, "harness/requirements.txt")

	subprojects, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	wantPaths := []string{"fixtures/api-java", "fixtures/service", "fixtures/webapp", "harness"}
	if got := subprojectRelPaths(subprojects); !reflect.DeepEqual(got, wantPaths) {
		t.Fatalf("expected subprojects %v, got %v", wantPaths, got)
	}
	managers := subprojectManagersByPath(subprojects)
	wantManagers := map[string]sdk.PackageManager{
		"fixtures/api-java": sdk.PackageManagerMaven,
		"fixtures/service":  sdk.PackageManagerPip,
		"fixtures/webapp":   sdk.PackageManagerNPM,
		"harness":           sdk.PackageManagerPip,
	}
	if !reflect.DeepEqual(managers, wantManagers) {
		t.Fatalf("expected managers %v, got %v", wantManagers, managers)
	}
}

func TestPlanSubprojectsRecursiveMaxDepthBoundary(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "fixtures/api-java/pom.xml")
	writeEvidenceFile(t, root, "fixtures/service/requirements.txt")
	writeEvidenceFile(t, root, "fixtures/webapp/package-lock.json")
	writeEvidenceFile(t, root, "harness/requirements.txt")
	writeEvidenceFile(t, root, "a/b/c/d/e/requirements.txt")

	cases := []struct {
		name      string
		maxDepth  int
		wantPaths []string
	}{
		{name: "depth 1", maxDepth: 1, wantPaths: []string{"harness"}},
		{name: "depth 2", maxDepth: 2, wantPaths: []string{"fixtures/api-java", "fixtures/service", "fixtures/webapp", "harness"}},
		{name: "default depth 3", maxDepth: 3, wantPaths: []string{"fixtures/api-java", "fixtures/service", "fixtures/webapp", "harness"}},
		{name: "unlimited", maxDepth: 0, wantPaths: []string{"a/b/c/d/e", "fixtures/api-java", "fixtures/service", "fixtures/webapp", "harness"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subprojects, err := planRecursive(t, root, func(req *Request) { req.MaxDepth = tc.maxDepth })
			if err != nil {
				t.Fatalf("PlanSubprojects() error = %v", err)
			}
			if got := subprojectRelPaths(subprojects); !reflect.DeepEqual(got, tc.wantPaths) {
				t.Fatalf("expected subprojects %v, got %v", tc.wantPaths, got)
			}
		})
	}
}

func TestPlanSubprojectsRecursiveDefaultDepthIsThree(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "harness/requirements.txt")
	writeEvidenceFile(t, root, "a/b/c/d/requirements.txt")

	subprojects, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if got, want := subprojectRelPaths(subprojects), []string{"harness"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected depth-4 manifest to be skipped at default depth, got %v", got)
	}

	subprojects, err = planRecursive(t, root, func(req *Request) { req.MaxDepth = 4 })
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if got, want := subprojectRelPaths(subprojects), []string{"a/b/c/d", "harness"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected depth-4 manifest at --max-depth 4, got %v", got)
	}
}

func TestPlanSubprojectsRecursiveExcludeGlobs(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "apps/web/package-lock.json")
	writeEvidenceFile(t, root, "apps/api/requirements.txt")
	writeEvidenceFile(t, root, "tools/requirements.txt")

	cases := []struct {
		name      string
		excludes  []string
		wantPaths []string
	}{
		{name: "path glob", excludes: []string{"apps/*"}, wantPaths: []string{"tools"}},
		{name: "exact path", excludes: []string{"apps/api"}, wantPaths: []string{"apps/web", "tools"}},
		{name: "basename at any depth", excludes: []string{"web"}, wantPaths: []string{"apps/api", "tools"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subprojects, err := planRecursive(t, root, func(req *Request) { req.ExcludeGlobs = tc.excludes })
			if err != nil {
				t.Fatalf("PlanSubprojects() error = %v", err)
			}
			if got := subprojectRelPaths(subprojects); !reflect.DeepEqual(got, tc.wantPaths) {
				t.Fatalf("expected subprojects %v, got %v", tc.wantPaths, got)
			}
		})
	}
}

func TestPlanSubprojectsRecursivePrunesNativeMultiModuleDescendants(t *testing.T) {
	cases := []struct {
		name    string
		manager sdk.PackageManager
		root    string
		nested  string
	}{
		{name: "maven reactor", manager: sdk.PackageManagerMaven, root: "pom.xml", nested: "module-a/pom.xml"},
		{name: "gradle subproject", manager: sdk.PackageManagerGradle, root: "settings.gradle", nested: "app/build.gradle"},
		{name: "npm workspace", manager: sdk.PackageManagerNPM, root: "package-lock.json", nested: "apps/web/package-lock.json"},
		{name: "cargo workspace", manager: sdk.PackageManagerCargo, root: "Cargo.toml", nested: "crates/member/Cargo.toml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeEvidenceFile(t, root, tc.root)
			writeEvidenceFile(t, root, tc.nested)

			subprojects, err := planRecursive(t, root, nil)
			if err != nil {
				t.Fatalf("PlanSubprojects() error = %v", err)
			}
			if got, want := subprojectRelPaths(subprojects), []string{"."}; !reflect.DeepEqual(got, want) {
				t.Fatalf("expected nested %s subproject to be pruned, got %v", tc.manager.Name(), got)
			}
			if got := subprojects[0].PrimaryPackageManager(); got != tc.manager {
				t.Fatalf("expected %s at root, got %s", tc.manager.Name(), got.Name())
			}
		})
	}
}

func TestPlanSubprojectsRecursiveDoesNotPruneAcrossPackageManagers(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "pom.xml")
	writeEvidenceFile(t, root, "scripts/requirements.txt")

	subprojects, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	managers := subprojectManagersByPath(subprojects)
	want := map[string]sdk.PackageManager{
		".":       sdk.PackageManagerMaven,
		"scripts": sdk.PackageManagerPip,
	}
	if !reflect.DeepEqual(managers, want) {
		t.Fatalf("expected managers %v, got %v", want, managers)
	}
}

func TestPlanSubprojectsRecursiveGomodNestedModulesAreIndependent(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "go.mod")
	writeEvidenceFile(t, root, "tools/go.mod")

	subprojects, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	// Nested Go modules are excluded from the parent module by Go semantics,
	// so gomod never participates in ancestor pruning.
	if got, want := subprojectRelPaths(subprojects), []string{".", "tools"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected independent go modules %v, got %v", want, got)
	}
}

func TestPlanSubprojectsRecursiveSkipsBuiltinIgnoredDirs(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "requirements.txt")
	writeEvidenceFile(t, root, "node_modules/pkg/package-lock.json")
	writeEvidenceFile(t, root, "vendor/lib/go.mod")
	writeEvidenceFile(t, root, ".hidden/pom.xml")
	writeEvidenceFile(t, root, "target/pom.xml")
	writeEvidenceFile(t, root, "dist/package-lock.json")
	writeEvidenceFile(t, root, "venv/pyvenv.cfg")
	writeEvidenceFile(t, root, "venv/lib/requirements.txt")

	subprojects, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if got, want := subprojectRelPaths(subprojects), []string{"."}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected only the root subproject, got %v", got)
	}
}

func TestPlanSubprojectsRecursiveDoesNotFollowSymlinkedDirs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	writeEvidenceFile(t, root, "requirements.txt")
	writeEvidenceFile(t, outside, "linked/package-lock.json")
	if err := os.Symlink(filepath.Join(outside, "linked"), filepath.Join(root, "linked")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	subprojects, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if got, want := subprojectRelPaths(subprojects), []string{"."}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected symlinked directory to be ignored, got %v", got)
	}
}

func TestPlanSubprojectsRecursiveDeterministicOrder(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "zeta/requirements.txt")
	writeEvidenceFile(t, root, "alpha/package-lock.json")
	writeEvidenceFile(t, root, "mid/nested/pom.xml")

	first, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("first PlanSubprojects() error = %v", err)
	}
	second, err := planRecursive(t, root, nil)
	if err != nil {
		t.Fatalf("second PlanSubprojects() error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic subprojects, got %v then %v", subprojectRelPaths(first), subprojectRelPaths(second))
	}
}

func TestPlanSubprojectsRecursiveRejectsSingleFileTarget(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "requirements.txt")
	if err := os.WriteFile(file, []byte(""), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}

	_, err := planRecursive(t, file, nil)
	if err == nil {
		t.Fatal("expected error for --recursive on a single file target")
	}
	if got := exit.Code(err); got != 4 {
		t.Fatalf("expected exit code 4 (invalid input), got %d: %v", got, err)
	}
	if !strings.Contains(err.Error(), "--recursive requires a directory target") {
		t.Fatalf("expected directory-target message, got %q", err.Error())
	}
}

func TestNoSubprojectsErrorSuggestsRecursiveWhenNestedManifestsExist(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "fixtures/webapp/package-lock.json")
	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()

	_, err := PlanSubprojects(reg, Request{
		Registry:        reg,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root},
	})
	if !errors.Is(err, ErrNoSubprojects) {
		t.Fatalf("expected ErrNoSubprojects, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "retry with --recursive") || !strings.Contains(msg, "fixtures/webapp") {
		t.Fatalf("expected --recursive hint naming the nested directory, got %q", msg)
	}
}

func TestNoSubprojectsErrorRecursiveVariantMentionsDepthAndExcludes(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "apps/web/package-lock.json")

	_, err := planRecursive(t, root, func(req *Request) {
		req.ExcludeGlobs = []string{"apps"}
	})
	if !errors.Is(err, ErrNoSubprojects) {
		t.Fatalf("expected ErrNoSubprojects, got %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "recursive discovery, max depth 3, 1 exclude pattern(s)") {
		t.Fatalf("expected recursive search description, got %q", msg)
	}
	if strings.Contains(msg, "retry with --recursive") {
		t.Fatalf("recursive run must not suggest --recursive, got %q", msg)
	}
}

func TestDescribeDiscoveryUsesSharedSkipRules(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "dist/package-lock.json")
	writeEvidenceFile(t, root, "target/pom.xml")
	writeEvidenceFile(t, root, "src/requirements.txt")

	lines := DescribeDiscovery(sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root})
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "dist") || strings.Contains(joined, "target") {
		t.Fatalf("expected probe to honor built-in skip rules, got %q", joined)
	}
	if !strings.Contains(joined, "requirements.txt at src") {
		t.Fatalf("expected probe to report src evidence, got %q", joined)
	}
}

// fakeRulesDetector is a minimal detector used to prove that recursive
// discovery honors detector-declared ignore rules and native multi-module
// support the same way for registered plugins as for built-ins.
type fakeRulesDetector struct {
	descriptor sdk.DetectorDescriptor
	supports   []sdk.PackageManagerSupport
}

func (d fakeRulesDetector) Descriptor() sdk.DetectorDescriptor { return d.descriptor }
func (d fakeRulesDetector) PackageManagerSupport() []sdk.PackageManagerSupport {
	return d.supports
}
func (d fakeRulesDetector) Ready(context.Context, sdk.DetectionRequest) error { return nil }
func (d fakeRulesDetector) Applicable(context.Context, sdk.DetectionRequest) (bool, error) {
	return false, nil
}
func (d fakeRulesDetector) ResolveGraph(context.Context, sdk.DetectionRequest) (sdk.DetectionResult, error) {
	return sdk.DetectionResult{}, nil
}

func TestPlanSubprojectsRecursiveHonorsDetectorDeclaredIgnoreRules(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "app/requirements.txt")
	writeEvidenceFile(t, root, "generated-src/requirements.txt")
	writeEvidenceFile(t, root, "cache/.bomlyskip")
	writeEvidenceFile(t, root, "cache/requirements.txt")

	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	reg.RegisterDetector(fakeRulesDetector{descriptor: sdk.DetectorDescriptor{
		Name:                             "fake-rules-detector",
		DiscoveryIgnoredDirectories:      []string{"generated-*"},
		DiscoveryIgnoredDirectoryMarkers: []string{".bomlyskip"},
	}})

	subprojects, err := PlanSubprojects(reg, Request{
		Registry:        reg,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root},
		Recursive:       true,
		MaxDepth:        3,
	})
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if got, want := subprojectRelPaths(subprojects), []string{"app"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected detector-declared rules to skip generated-src and marker dir, got %v", got)
	}
}

func TestPlanSubprojectsRecursiveHonorsDetectorDeclaredMultiModule(t *testing.T) {
	root := t.TempDir()
	writeEvidenceFile(t, root, "go.mod")
	writeEvidenceFile(t, root, "tools/go.mod")

	reg := engine.NewRegistry(engine.RegistryConfigs{}, *zap.NewNop())
	reg.Build()
	// gomod does not prune by default (nested modules are independent); a
	// registered detector declaring native multi-module support for it must
	// flip that, proving plugins can opt their manager into pruning.
	reg.RegisterDetector(fakeRulesDetector{
		descriptor: sdk.DetectorDescriptor{Name: "fake-go-workspace-detector"},
		supports:   []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGoMod, "go.mod").WithNativeMultiModule()},
	})

	subprojects, err := PlanSubprojects(reg, Request{
		Registry:        reg,
		ExecutionTarget: sdk.ExecutionTarget{Kind: sdk.ExecutionTargetFilesystem, Location: root},
		Recursive:       true,
		MaxDepth:        3,
	})
	if err != nil {
		t.Fatalf("PlanSubprojects() error = %v", err)
	}
	if got, want := subprojectRelPaths(subprojects), []string{"."}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected declared multi-module support to prune nested module, got %v", got)
	}
}

func TestBuiltinDiscoveryRulesMatchExpectedCatalog(t *testing.T) {
	rules := builtinDiscoveryRules()

	wantGlobs := []string{"node_modules", "vendor", "target", "build", "dist", "__pycache__"}
	for _, glob := range wantGlobs {
		if !slices.Contains(rules.ignoredDirGlobs, glob) {
			t.Errorf("expected built-in ignored directory %q, got %v", glob, rules.ignoredDirGlobs)
		}
	}
	if !slices.Contains(rules.ignoredDirMarkers, "pyvenv.cfg") {
		t.Errorf("expected pyvenv.cfg marker, got %v", rules.ignoredDirMarkers)
	}

	wantManagers := []sdk.PackageManager{
		sdk.PackageManagerMaven, sdk.PackageManagerGradle,
		sdk.PackageManagerNPM, sdk.PackageManagerPNPM, sdk.PackageManagerYarn,
		sdk.PackageManagerCargo, sdk.PackageManagerSBT, sdk.PackageManagerMix,
	}
	for _, manager := range wantManagers {
		if _, ok := rules.multiModuleManagers[manager]; !ok {
			t.Errorf("expected %s in the native multi-module set, got %v", manager.Name(), rules.multiModuleManagers)
		}
	}
	if _, ok := rules.multiModuleManagers[sdk.PackageManagerGoMod]; ok {
		t.Error("gomod must not be in the native multi-module set: nested go.mod modules are independent")
	}
}
