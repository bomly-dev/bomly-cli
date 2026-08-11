# How To Implement A Detector Plugin

A detector plugin turns project evidence into a Bomly dependency graph. Use a detector when Bomly needs a new way to read dependency data, such as a new package manager, a specialized manifest format, or an internal dependency source.

A detector is one `sdk.Module` with `Kind: sdk.PluginKindDetector`. The same module can be compiled into a host build (embedded) or served as a managed plugin binary with `sdk.ServeModule` — you write the component once. [Plugin basics](../PLUGINS.md#write-a-plugin) covers the module model, repository contract, configuration, testing, and release flow shared by every role; this guide covers what is specific to detectors.

The [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk) documents `sdk.Module`, `sdk.DetectorModule`, the `sdk.Detector` interface, `sdk.DetectionRequest`, `sdk.DetectionResult`, graph helpers, and the package-manager support types used below.

## Start From The Template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository ("Use this template" on GitHub). It ships a working matcher; turning it into a detector means changing the module kind, the descriptor, and the role method — the layout, manifest, tests, and release workflow stay the same:

```text
plugin/                  importable package: descriptor, Config, Detector, Module()
cmd/<binary-name>/
  main.go                one line: sdk.ServeModule(plugin.Module())
bomly-plugin.json        package manifest ("kind": "detector")
testdata/                fixtures for unit tests
.github/workflows/       CI and the release workflow
go.mod                   pins a released github.com/bomly-dev/bomly-sdk version
```

## The Module

The component lives in an importable `plugin/` package that exports `Module()`:

```go
package plugin

import (
    "context"
    "fmt"

    sdk "github.com/bomly-dev/bomly-sdk"
)

// Name must equal the "id" field in bomly-plugin.json.
const Name = "com.example.bun-lock-detector"

// Config is the detector's typed configuration block.
type Config struct {
    IncludeDev bool `json:"includeDev" doc:"Include devDependencies in the graph" default:"false"`
}

// Detector reads bun.lock evidence and returns a dependency graph.
// sdk.BaseDetector supplies default Ready/Applicable implementations
// (always ready, always applicable).
type Detector struct {
    sdk.BaseDetector
    config Config
}

func descriptor() sdk.DetectorDescriptor {
    return sdk.DetectorDescriptor{
        Name:        Name,
        DisplayName: "Bun Lock Detector",
        Aliases:     []string{"bun-lock"},
        Tags:        []string{"dependency-detection", "bun"},
        // Directories recursive discovery must never descend into for this
        // ecosystem (see "Discovery metadata" below).
        IgnoredDirectories: []string{"node_modules"},
        ConfigSchema:       sdk.MustConfigSchemaFor(Config{}),
    }
}

func support() []sdk.PackageManagerSupport {
    return []sdk.PackageManagerSupport{
        sdk.Support(sdk.PackageManagerOther, "bun.lock", "bun.lockb", "package.json"),
    }
}

func (d *Detector) Descriptor() sdk.DetectorDescriptor { return descriptor() }

func (d *Detector) PackageManagerSupport() []sdk.PackageManagerSupport { return support() }

// ResolveGraph reads the request and returns one or more manifest-scoped graphs.
func (d *Detector) ResolveGraph(ctx context.Context, req sdk.DetectionRequest) (sdk.DetectionResult, error) {
    graph := sdk.New()
    dep := sdk.NewDependency(sdk.Dependency{
        Coordinates: sdk.Coordinates{
            Ecosystem: sdk.EcosystemNPM,
            Name:      "is-odd",
            Version:   "3.0.1",
            PURL:      "pkg:npm/is-odd@3.0.1",
        },
        FoundBy: Name,
    })
    if err := graph.AddNode(dep); err != nil {
        return sdk.DetectionResult{}, fmt.Errorf("add node: %w", err)
    }
    return sdk.DetectionResult{
        SubprojectInfo:      req.Subproject,
        RootExecutionTarget: req.ExecutionTarget,
        Graphs: sdk.SingleGraphContainer(graph, sdk.ManifestMetadata{
            Path: "bun.lock",
        }),
    }, nil
}

// Module packages the detector for both execution modes.
func Module() sdk.Module {
    return sdk.Module{
        Kind: sdk.PluginKindDetector,
        Detector: &sdk.DetectorModule{
            Descriptor: descriptor(),
            Support:    support(),
            New: func(_ context.Context, host sdk.HostContext) (sdk.Detector, error) {
                detector := &Detector{}
                if err := host.DecodeConfig(&detector.config); err != nil {
                    return nil, fmt.Errorf("decode %s config: %w", Name, err)
                }
                return detector, nil
            },
        },
    }
}
```

The binary entrypoint stays one line:

```go
package main

import (
    sdk "github.com/bomly-dev/bomly-sdk"

    "example.com/bomly-plugin-bun-lock/plugin"
)

func main() { sdk.ServeModule(plugin.Module()) }
```

## What Each Part Does

- `Descriptor` is the detector's static registration: name (must equal the manifest `id`), display name, aliases, tags, supported ecosystems and managers, discovery metadata, and config schema.
- `Support` (or the `PackageManagerSupport` method) tells Bomly which package managers and evidence files can plan this detector — declared on the module so Bomly can plan without constructing the component.
- `New` constructs the detector once per execution, with a `sdk.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the detector can run right now. Return `nil` when ready; return an error whose message explains the reason (for example `fmt.Errorf("bun executable not found on PATH")`) when it cannot. `sdk.BaseDetector` embeds an always-ready default.
- `Applicable(ctx, req) (bool, error)` reports whether the detector should run for this request (right project shape, right evidence present).
- `ResolveGraph` does the work: read evidence, build graphs, return them.

Honor the context in every method: probing, parsing, and subprocess work should stop promptly when the scan is cancelled.

## Detector Chains And Hand-Off

Bomly plans detector chains per package manager and runs them first-success: when the planned primary detector reports not ready or not applicable, or fails, the next detector in the chain gets the request. Syft is typically the last fallback for ecosystems it covers.

Hand off gracefully instead of failing hard:

- Report a missing toolchain through `Ready` with a clear reason, not through a `ResolveGraph` error. The reason appears in scan output when a fallback is used (`FallbackReason` on the result the fallback produces).
- Report "this project is not for me" through `Applicable`, not through an empty graph.
- Reserve `ResolveGraph` errors for real failures on projects the detector should have handled.

## Discovery Metadata

Detector plugins participate in subproject discovery and scan planning through descriptor fields, aggregated across every registered detector exactly like the built-ins:

- `PackageManagerSupport.EvidencePatterns` — file names (such as `bun.lock`) whose presence plans this detector for a directory.
- `DetectorDescriptor.IgnoredDirectories` — directory basename globs recursive discovery (`--recursive`) must not descend into (a Node detector declares `node_modules`, a Maven detector declares `target`).
- `DetectorDescriptor.IgnoredDirectoryMarkers` — file names that mark a directory as ignored regardless of its name (`pyvenv.cfg` marks a Python virtualenv).
- `sdk.Support(...).WithMultiModule()` — declares that the detector natively expands nested workspace or reactor modules from a root manifest, so recursive discovery does not scan the same modules twice.

All of these are optional; older plugins that omit them keep working.

## Build The Graph

Use SDK graph helpers instead of constructing graph internals by hand:

```go
parent := sdk.NewDependency(sdk.Dependency{
    Coordinates: sdk.Coordinates{Name: "app", Version: "0.0.0", PURL: "pkg:generic/app@0.0.0"},
})
child := sdk.NewDependency(sdk.Dependency{
    Coordinates: sdk.Coordinates{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
})

graph := sdk.New()
if err := graph.AddNode(parent); err != nil {
    return sdk.DetectionResult{}, err
}
if err := graph.AddNode(child); err != nil {
    return sdk.DetectionResult{}, err
}
if err := graph.AddEdge(parent.ID, child.ID); err != nil {
    return sdk.DetectionResult{}, err
}
```

Prefer canonical PURLs and fill `Coordinates` where possible — matchers enrich packages by PURL, and findings reference them the same way. Return `req.Subproject` and `req.ExecutionTarget` in the result so Bomly keeps it tied to the planned scan target. Use `DetectionResult.Warnings` for non-fatal problems worth surfacing (the graph is usable, but something about the project will degrade an install elsewhere).

## Optional Capabilities

**Install-first.** A detector that must prepare dependencies before reading them (for example, running a resolving install) implements `sdk.InstallFirstDetector` (`Install(ctx, req) error`) and sets `SupportsInstallFirst` in its descriptor. Do not install package managers themselves; Bomly assumes required package managers already exist.

**Remediation hints.** A detector that understands package-manager fix strategies can advertise them and contribute read-only evidence after vulnerability enrichment:

```go
// In the descriptor:
RemediationCapabilities: []sdk.RemediationCapability{{
    SupportedManagers: []sdk.PackageManager{sdk.PackageManagerNPM},
    Actions: []sdk.RemediationAction{
        sdk.RemediationActionDirectBump,
        sdk.RemediationActionTransitiveOverride,
    },
}},
```

Then implement `sdk.DetectorRemediationProvider` on the detector:

```go
func (d *Detector) RemediationHints(ctx context.Context, req sdk.RemediationHintRequest) (sdk.RemediationHintResponse, error)
```

Return hints only for dependency IDs and manifest paths this detector produced. Hints may name supported strategies and give plain-language package-manager advice. They must not choose a fix version, edit files, run commands, or make network calls — Bomly validates every hint and the central remediation component chooses the final action. Detectors without the capability are simply never asked.

## Configuration

Declare a typed `Config` struct with `json`, `doc:`, and `default:` tags, advertise it with `ConfigSchema: sdk.MustConfigSchemaFor(Config{})`, and decode it in `New` with `host.DecodeConfig(&cfg)`. Users set the block under `plugins.detectors.<name>`:

```yaml
plugins:
  detectors:
    com.example.bun-lock-detector:
      includeDev: true
```

The same block reaches the component in both execution modes. See [Configuration in the plugin guide](../PLUGINS.md#configuration-and-proxy-support) for details and the deprecated flat form.

## Test It

Unit-test parsing and graph construction against `testdata/` fixtures, and run the SDK conformance suite:

```go
func TestConformance(t *testing.T) {
    conformance.Test(t, conformance.Config{
        Module:       Module(),
        ManifestPath: filepath.Join("..", "bomly-plugin.json"),
    })
}
```

Local development loop:

```bash
go build -o ./bin/bomly-plugin-bun-lock ./cmd/bomly-plugin-bun-lock
bomly plugins install ./bin/bomly-plugin-bun-lock --dev
bomly plugins enable com.example.bun-lock-detector
bomly scan --path ./my-project --detectors com.example.bun-lock-detector --json
bomly plugins verify com.example.bun-lock-detector
bomly plugins test com.example.bun-lock-detector
bomly plugins doctor com.example.bun-lock-detector
```

Use `--detectors +<name>` to add the detector to the default set instead of replacing it. See [Testing a plugin](../PLUGINS.md#test-a-plugin) for the shared workflow, including `conformance.ProbeBinary` for probing the built binary over the real managed transport.

## Package And Release

Follow the template's release workflow: one archive per platform named `<name>_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) containing the binary, `bomly-plugin.json`, `README.md`, and `LICENSE`, plus a `SHA256SUMS` file. The manifest's `entrypoint` map names the binary per platform, and `descriptor.Name` must equal the manifest `id`. See [Package and release](../PLUGINS.md#package-and-release-a-plugin).

## Implementation Checklist

- Declare accurate package-manager support, evidence patterns, and discovery metadata.
- Report missing toolchains through `Ready` with a clear reason; hand off to the chain instead of failing.
- Honor context cancellation in probing, parsing, and subprocesses.
- Prefer canonical PURLs and filled `Coordinates`.
- Keep remediation hints read-only and within the advertised capabilities.
- Wrap errors with useful context; avoid panics.
- Do not log secrets, tokens, or credentials.
- Keep network calls explicit and document them in the plugin README.
- Add unit tests for parsing and graph construction, plus `conformance.Test`.
