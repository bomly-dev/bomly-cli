// This file intentionally has no build tag. It compiles as part of
// `go test ./...` (make test) so that SDK changes which break the embedded
// example-plugin fixture surface immediately, instead of only in the slow,
// smoke-tagged golden-update workflow.

package smoke

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// examplePluginMainSource is the Go source for the example managed detector
// plugin. The smoke-tagged plugin workflow tests write it to disk and build it
// at runtime; TestExamplePluginFixtureCompiles below compile-checks it without
// the `smoke` build tag. Keep it in sync with the sdk plugin API.
const examplePluginMainSource = `package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

const pluginID = "bomly.example.gomod-detector"

type detector struct{}

func (d *detector) Descriptor(context.Context) (*sdk.DetectorDescriptor, error) {
	return &sdk.DetectorDescriptor{
		Name: pluginID,
	}, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error) {
	return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGoMod, "go.mod")}, nil
}

func (d *detector) Ready(context.Context, *sdk.DetectRequest) (*sdk.ReadyResponse, error) {
	return &sdk.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *sdk.DetectRequest) (*sdk.ApplicableResponse, error) {
	return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *sdk.DetectRequest) (*sdk.DetectResponse, error) {
	moduleName, err := readModuleName(filepath.Join(req.ProjectPath, "go.mod"))
	if err != nil {
		return nil, err
	}
	pkg := sdk.NewDependency(sdk.Dependency{
		Ecosystem: string(sdk.EcosystemGo),
		Name:      moduleName,
		Version:   "v0.0.0",
		PURL:      "pkg:golang/" + moduleName + "@v0.0.0",
		FoundBy:   pluginID,
	})
	graph := sdk.New()
	if err := graph.AddNode(pkg); err != nil {
		return nil, err
	}
	return &sdk.DetectResponse{
		SubprojectInfo:      req.Subproject,
		RootExecutionTarget: req.ExecutionTarget,
		DetectorName:        pluginID,
		Origin:              sdk.ExternalOrigin,
		Graphs: &sdk.GraphContainer{
			Entries: []sdk.GraphEntry{{
				Manifest: sdk.ManifestMetadata{
					Path: filepath.Join(req.ProjectPath, "go.mod"),
					Kind: sdk.ManifestKind("go.mod"),
				},
				Graph: graph,
			}},
		},
	}, nil
}

func readModuleName(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "module ") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		if name == "" {
			return "", fmt.Errorf("go.mod module directive is empty")
		}
		return name, nil
	}
	return "", fmt.Errorf("go.mod does not contain a module directive")
}

func main() {
	sdk.ServeDetector(&detector{})
}
`

// TestExamplePluginFixtureCompiles builds examplePluginMainSource against the
// live sdk package via a throwaway module that replaces github.com/bomly-dev/
// bomly-cli with this checkout. It runs without the `smoke` build tag so a
// breaking sdk change fails `make test` rather than slipping through to the
// golden-update workflow.
func TestExamplePluginFixtureCompiles(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not found on PATH: %v", err)
	}

	root := fixtureRepoRoot(t)
	srcDir := t.TempDir()

	goMod := "module bomly-fixture-compile\n\ngo 1.25\n\nrequire github.com/bomly-dev/bomly-cli v0.0.0\n\nreplace github.com/bomly-dev/bomly-cli => " + filepath.ToSlash(root) + "\n"
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(examplePluginMainSource), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	cmd := exec.Command("go", "build", "-mod=mod", "-o", filepath.Join(t.TempDir(), "plugin-fixture"), ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("example plugin fixture failed to compile against the sdk: %v\n%s\n"+
			"Update examplePluginMainSource in test/smoke/fixture_compile_test.go to match the current sdk plugin API.", err, out)
	}
}

// fixtureRepoRoot returns the repo root relative to this file (test/smoke/).
func fixtureRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller file for repo root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
