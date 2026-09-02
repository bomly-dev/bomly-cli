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
	"strings"
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

	sdk "github.com/bomly-dev/bomly-sdk"
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
	pkg, err := sdk.NewDependencyNode(sdk.Coordinates{
		Ecosystem: sdk.EcosystemGo,
		Name:      moduleName,
		Version:   "v0.0.0",
		PURL:      "pkg:golang/" + moduleName + "@v0.0.0",
	})
	if err != nil {
		return nil, err
	}
	pkg.FoundBy = pluginID
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

// minSupportedSDKVersion is the oldest github.com/bomly-dev/bomly-sdk release
// whose plugin binaries the current Bomly binary must keep loading and
// running. Bump it only when a wire-protocol major version is retired.
//
// It lives in this file, which carries no build tag, because both the
// smoke-tagged wire-compatibility test and the untagged fixture compile guard
// need it -- and the guard is the one that runs in `make test`.
const minSupportedSDKVersion = "v0.1.0"

// legacyExamplePluginMainSource is the same fixture written against the
// oldest SDK release whose plugin binaries must keep loading
// (minSupportedSDKVersion). It exists because that guarantee is about the
// wire, not the source API: ADR-0041 replaced sdk.NewDependency with the node
// constructors, so one source cannot compile against both v0.1.0 and the
// current pin, and pretending otherwise would have meant retiring the
// compatibility test rather than the API.
//
// Do not modernize this. It is pinned to a released API on purpose, and the
// day it stops compiling against minSupportedSDKVersion is the day that
// version's plugin binaries genuinely stopped being buildable -- which is a
// decision to take deliberately, by bumping minSupportedSDKVersion.
const legacyExamplePluginMainSource = `package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/bomly-dev/bomly-sdk"
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
		Coordinates: sdk.Coordinates{
			Ecosystem: sdk.EcosystemGo,
			Name:      moduleName,
			Version:   "v0.0.0",
			PURL:      "pkg:golang/" + moduleName + "@v0.0.0",
		},
		FoundBy: pluginID,
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

// exampleAnalyzerPluginMainSource is the Go source for the example managed
// analyzer plugin. It annotates one vulnerability with a package-tier
// reachability result. When the host accepts package-update deltas
// (req.AcceptPackageUpdates), it returns only the touched package via
// PackageUpdates; otherwise it returns the full registry for older hosts.
// Every hook appends the process ID to the configured pid_file so the smoke
// workflow can prove that one pooled subprocess served every call.
const exampleAnalyzerPluginMainSource = `package main

import (
	"context"
	"fmt"
	"os"
	"sort"

	sdk "github.com/bomly-dev/bomly-sdk"
)

const pluginID = "bomly.example.reach-analyzer"

// pluginConfig is the analyzer's configuration block, advertised through the
// descriptor's ConfigSchema and decoded from the plugins.analyzers.<name>
// config the host passes down.
type pluginConfig struct {
	PIDFile string ` + "`" + `json:"pid_file" doc:"File the analyzer appends its process ID to on every call"` + "`" + `
}

type analyzer struct{}

func (a *analyzer) Descriptor(context.Context) (*sdk.AnalyzerDescriptor, error) {
	return &sdk.AnalyzerDescriptor{
		Name:               pluginID,
		SupportedLanguages: []sdk.Language{sdk.LanguageGo},
		SupportedTiers:     []sdk.ReachabilityTier{sdk.TierPackage},
		Capabilities:       []string{sdk.CapabilityPackageUpdates},
		ConfigSchema:       sdk.MustConfigSchemaFor(pluginConfig{}),
	}, nil
}

func (a *analyzer) Ready(context.Context, *sdk.AnalyzeRequest) (*sdk.ReadyResponse, error) {
	recordPID()
	return &sdk.ReadyResponse{Ready: true}, nil
}

func (a *analyzer) Applicable(context.Context, *sdk.AnalyzeRequest) (*sdk.ApplicableResponse, error) {
	recordPID()
	return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (a *analyzer) Analyze(_ context.Context, req *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error) {
	recordPID()
	annotated := annotatedPackage(req)
	stats := map[string]sdk.ReachabilityStats{pluginID: {Reachable: 1}}
	if req.AcceptPackageUpdates {
		// The host understands deltas: return only the package we touched.
		return &sdk.AnalyzeResponse{
			PackageUpdates: []*sdk.Package{annotated},
			AnalyzerStats:  stats,
		}, nil
	}
	// Legacy hosts expect the full registry back.
	registry := req.Registry
	if registry == nil {
		registry = sdk.NewPackageRegistry()
	}
	registry = sdk.ApplyPackageUpdates(registry, []*sdk.Package{annotated})
	return &sdk.AnalyzeResponse{Registry: registry, AnalyzerStats: stats}, nil
}

// annotatedPackage marks one vulnerability reachable on the first registry
// package (by PURL order), or on a synthetic package when the registry is
// empty, so the workflow test can observe the annotation in scan output.
func annotatedPackage(req *sdk.AnalyzeRequest) *sdk.Package {
	purl := "pkg:golang/bomly.example/synthetic@v0.0.0"
	if req.Registry != nil {
		purls := make([]string, 0, req.Registry.Len())
		for _, pkg := range req.Registry.All() {
			if pkg != nil && pkg.PURL != "" {
				purls = append(purls, pkg.PURL)
			}
		}
		sort.Strings(purls)
		if len(purls) > 0 {
			purl = purls[0]
		}
	}
	return &sdk.Package{
		Coordinates: sdk.Coordinates{PURL: purl},
		Vulnerabilities: []sdk.Vulnerability{{
			ID:     "EXAMPLE-REACH-0001",
			Source: pluginID,
			Reachability: &sdk.Reachability{
				Status:   sdk.ReachabilityReachable,
				Tier:     sdk.TierPackage,
				Analyzer: pluginID,
			},
		}},
	}
}

// recordPID appends the plugin process ID to the configured pid_file. Errors
// are ignored: recording is diagnostic and must never fail the analysis.
func recordPID() {
	var cfg pluginConfig
	if err := sdk.DecodePluginConfigFromEnv(&cfg); err != nil || cfg.PIDFile == "" {
		return
	}
	file, err := os.OpenFile(cfg.PIDFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, "%d\n", os.Getpid())
}

func main() {
	sdk.ServeAnalyzer(&analyzer{})
}
`

// sdkModuleVersion returns the github.com/bomly-dev/bomly-sdk version this
// repository pins, so fixture modules compile against exactly the SDK release
// plugin authors would use.
func sdkModuleVersion(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "github.com/bomly-dev/bomly-sdk")
	cmd.Dir = fixtureRepoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve pinned bomly-sdk version: %v\n%s", err, out)
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		t.Fatal("pinned bomly-sdk version is empty")
	}
	return version
}

// TestExamplePluginFixtureCompiles builds examplePluginMainSource against the
// pinned github.com/bomly-dev/bomly-sdk release — exactly what an external
// plugin author compiles against. It runs without the `smoke` build tag so a
// breaking sdk pin bump fails `make test` rather than slipping through to the
// golden-update workflow.
func TestExamplePluginFixtureCompiles(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not found on PATH: %v", err)
	}
	compileFixtureSource(t, "examplePluginMainSource", examplePluginMainSource, sdkModuleVersion(t))
	// And the legacy source against the oldest release whose binaries must
	// keep loading, so the wire-compatibility smoke cannot silently stop
	// building what it claims to test.
	compileFixtureSource(t, "legacyExamplePluginMainSource", legacyExamplePluginMainSource, minSupportedSDKVersion)
}

// TestExampleAnalyzerPluginFixtureCompiles is the analyzer sibling of
// TestExamplePluginFixtureCompiles: it compile-checks the embedded example
// analyzer plugin against the pinned sdk release without the `smoke` tag.
func TestExampleAnalyzerPluginFixtureCompiles(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not found on PATH: %v", err)
	}
	compileFixtureSource(t, "exampleAnalyzerPluginMainSource", exampleAnalyzerPluginMainSource, sdkModuleVersion(t))
}

// compileFixtureSource builds one embedded plugin fixture source against the
// given github.com/bomly-dev/bomly-sdk version.
func compileFixtureSource(t *testing.T, name, source, sdkVersion string) {
	t.Helper()

	srcDir := t.TempDir()

	goMod := "module bomly-fixture-compile\n\ngo 1.25\n\nrequire github.com/bomly-dev/bomly-sdk " + sdkVersion + "\n"
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(source), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	cmd := exec.Command("go", "build", "-mod=mod", "-o", filepath.Join(t.TempDir(), "plugin-fixture"), ".")
	cmd.Dir = srcDir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s failed to compile against sdk %s: %v\n%s\n"+
			"Update %s in test/smoke/fixture_compile_test.go to match the current sdk plugin API.", name, sdkVersion, err, out, name)
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
