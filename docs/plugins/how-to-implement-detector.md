# How to implement a detector plugin

A detector plugin turns project evidence into a Bomly dependency graph. Write one when Bomly needs a new way to read dependency data: a new package manager, a specialized manifest format, or an internal dependency source.

[Plugin authoring](authoring.md) covers the module model, repository layout, configuration, testing, packaging, and protocol rules shared by every role. This guide covers only what is specific to detectors. The SDK reference for the types used below is the [`plugin`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/plugin) and [`model`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/model) packages.

## Start from the template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository. It ships a working matcher. To turn it into a detector, change the module kind, the descriptor, and the role method; the layout, manifest, tests, and release workflow stay the same, with `"kind": "detector"` in `bomly-plugin.json`.

## The module

The component lives in an importable `plugin/` package that exports `Module()`:

```go
package plugin

import (
    "context"
    "fmt"

    "github.com/bomly-dev/bomly-sdk/model"
    sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Name must equal the "id" field in bomly-plugin.json.
const Name = "com.example.bun-lock-detector"

// Config is the detector's typed configuration block.
type Config struct {
    IncludeDev bool `json:"includeDev" doc:"Include devDependencies in the graph" default:"false"`
}

// Detector reads bun.lock evidence and returns a dependency graph.
// sdkplugin.BaseDetector supplies default Ready/Applicable implementations
// (always ready, always applicable).
type Detector struct {
    sdkplugin.BaseDetector
    config Config
}

func descriptor() sdkplugin.DetectorDescriptor {
    return sdkplugin.DetectorDescriptor{
        Name:        Name,
        DisplayName: "Bun Lock Detector",
        Aliases:     []string{"bun-lock"},
        Tags:        []string{"dependency-detection", "bun"},
        // Directories recursive discovery must never descend into for this
        // ecosystem (see "Discovery metadata" below).
        IgnoredDirectories: []string{"node_modules"},
        ConfigSchema:       sdkplugin.MustConfigSchemaFor(Config{}),
    }
}

func support() []sdkplugin.PackageManagerSupport {
    return []sdkplugin.PackageManagerSupport{
        sdkplugin.Support(model.PackageManagerOther, "bun.lock", "bun.lockb", "package.json"),
    }
}

func (d *Detector) Descriptor() sdkplugin.DetectorDescriptor { return descriptor() }

func (d *Detector) PackageManagerSupport() []sdkplugin.PackageManagerSupport { return support() }

// ResolveGraph reads the request and returns one or more manifest-scoped graphs.
func (d *Detector) ResolveGraph(ctx context.Context, req sdkplugin.DetectionRequest) (sdkplugin.DetectionResult, error) {
    graph := model.New()
    // The constructor is the only mint for a node's identity: it derives the
    // ID from the canonical package URL, so never assemble one by hand.
    dep, err := model.NewDependencyNode(model.Coordinates{
        Ecosystem: model.EcosystemNPM,
        Name:      "is-odd",
        Version:   "3.0.1",
        PURL:      "pkg:npm/is-odd@3.0.1",
    })
    if err != nil {
        return sdkplugin.DetectionResult{}, fmt.Errorf("build node: %w", err)
    }
    dep.FoundBy = Name
    if err := graph.AddNode(dep); err != nil {
        return sdkplugin.DetectionResult{}, fmt.Errorf("add node: %w", err)
    }
    return sdkplugin.DetectionResult{
        SubprojectInfo:      req.Subproject,
        RootExecutionTarget: req.ExecutionTarget,
        Graphs: model.SingleGraphContainer(graph, model.ManifestMetadata{
            Path: "bun.lock",
        }),
    }, nil
}

// Module packages the detector for both execution modes.
func Module() sdkplugin.Module {
    return sdkplugin.Module{
        Kind: sdkplugin.PluginKindDetector,
        Detector: &sdkplugin.DetectorModule{
            Descriptor: descriptor(),
            Support:    support(),
            New: func(_ context.Context, host sdkplugin.HostContext) (sdkplugin.Detector, error) {
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
    "github.com/bomly-dev/bomly-sdk/runtime"

    "example.com/bomly-plugin-bun-lock/plugin"
)

func main() { runtime.ServeModule(plugin.Module()) }
```

## What each part does

- `Descriptor` is the detector's static registration: name (must equal the manifest `id`), display name, aliases, tags, supported ecosystems and managers, discovery metadata, and config schema.
- `Support` (or the `PackageManagerSupport` method) tells Bomly which package managers and evidence files can plan this detector — declared on the module so Bomly can plan without constructing the component.
- `New` constructs the detector once per execution, with a `plugin.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the detector can run right now. Return `nil` when ready; return an error whose message explains the reason (for example `fmt.Errorf("bun executable not found on PATH")`) when it cannot. `plugin.BaseDetector` embeds an always-ready default.
- `Applicable(ctx, req) (bool, error)` reports whether the detector should run for this request (right project shape, right evidence present).
- `ResolveGraph` does the work: read evidence, build graphs, return them.

Honor the context in every method: probing, parsing, and subprocess work should stop promptly when the scan is cancelled.

## Detector chains and hand-off

Bomly plans detector chains per package manager and runs them first-success: when the planned primary detector reports not ready or not applicable, or fails, the next detector in the chain gets the request. Syft is typically the last fallback for ecosystems it covers.

Hand off gracefully instead of failing hard:

- Report a missing toolchain through `Ready` with a clear reason, not through a `ResolveGraph` error. The reason appears in scan output when a fallback is used (`FallbackReason` on the result the fallback produces).
- Report "this project is not for me" through `Applicable`, not through an empty graph.
- Reserve `ResolveGraph` errors for real failures on projects the detector should have handled.

## Discovery metadata

Detector plugins participate in subproject discovery and scan planning through descriptor fields, aggregated across every registered detector exactly like the built-ins:

- `PackageManagerSupport.EvidencePatterns` — file names (such as `bun.lock`) whose presence plans this detector for a directory.
- `DetectorDescriptor.IgnoredDirectories` — directory basename globs recursive discovery (`--recursive`) must not descend into (a Node detector declares `node_modules`, a Maven detector declares `target`).
- `DetectorDescriptor.IgnoredDirectoryMarkers` — file names that mark a directory as ignored regardless of its name (`pyvenv.cfg` marks a Python virtualenv).
- `plugin.Support(...).WithMultiModule()` — declares that the detector natively expands nested workspace or reactor modules from a root manifest, so recursive discovery does not scan the same modules twice.

All of these are optional; older plugins that omit them keep working.

## Build the graph

Use SDK graph helpers instead of constructing graph internals by hand:

```go
parent, err := model.NewDependencyNode(model.Coordinates{Name: "app", Version: "0.0.0", PURL: "pkg:generic/app@0.0.0"})
if err != nil {
    return sdkplugin.DetectionResult{}, err
}
child, err := model.NewDependencyNode(model.Coordinates{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"})
if err != nil {
    return sdkplugin.DetectionResult{}, err
}

graph := model.New()
if err := graph.AddNode(parent); err != nil {
    return sdkplugin.DetectionResult{}, err
}
if err := graph.AddNode(child); err != nil {
    return sdkplugin.DetectionResult{}, err
}
// Edges join node IDs, which only the constructors mint.
if err := graph.AddEdge(parent.NodeID(), child.NodeID()); err != nil {
    return sdkplugin.DetectionResult{}, err
}
```

Prefer canonical PURLs and fill `Coordinates` where possible — matchers enrich packages by PURL, and findings reference them the same way. Return `req.Subproject` and `req.ExecutionTarget` in the result so Bomly keeps it tied to the planned scan target. Use `DetectionResult.Warnings` for non-fatal problems worth surfacing (the graph is usable, but something about the project will degrade an install elsewhere).

## Optional capabilities

**Install-first.** A detector that must prepare dependencies before reading them (for example, running a resolving install) implements `plugin.InstallFirstDetector` (`Install(ctx, req) error`) and sets `SupportsInstallFirst` in its descriptor. Do not install package managers themselves; Bomly assumes required package managers already exist.

**Remediation hints.** A detector that understands package-manager fix strategies can advertise them and contribute read-only evidence after vulnerability enrichment:

```go
// In the descriptor:
RemediationCapabilities: []sdkplugin.RemediationCapability{{
    SupportedManagers: []model.PackageManager{model.PackageManagerNPM},
    Actions: []model.RemediationAction{
        model.RemediationActionDirectBump,
        model.RemediationActionTransitiveOverride,
    },
}},
```

Then implement `plugin.DetectorRemediationProvider` on the detector:

```go
func (d *Detector) RemediationHints(ctx context.Context, req sdkplugin.RemediationHintRequest) (sdkplugin.RemediationHintResponse, error)
```

Return hints only for dependency IDs and manifest paths this detector produced. Hints may name supported strategies and give plain-language package-manager advice. They must not choose a fix version, edit files, run commands, or make network calls — Bomly validates every hint and the central remediation component chooses the final action. Detectors without the capability are simply never asked.

## Configuration

Declare a typed `Config` struct, advertise it with `ConfigSchema`, and decode it in `New` as described in [Plugin authoring](authoring.md#configuration). Users set the block under `plugins.detectors.<name>`:

```yaml
plugins:
  detectors:
    com.example.bun-lock-detector:
      includeDev: true
```

## Test it

Unit-test parsing and graph construction against `testdata/` fixtures, then run the conformance suite and the local loop described in [Plugin authoring](authoring.md#test-a-plugin). Select the detector with `--detectors <name>` to run only it, or `--detectors +<name>` to add it to the default chain:

```bash
bomly scan --path ./my-project --detectors com.example.bun-lock-detector --json
```

## Checklist

In addition to the [checklist for every plugin](authoring.md#checklist-for-every-plugin):

- Declare accurate package-manager support, evidence patterns, and discovery metadata.
- Report a missing toolchain through `Ready` with a clear reason, so the chain can hand off.
- Build nodes with the SDK constructors and prefer canonical PURLs with filled `Coordinates`.
- Keep remediation hints read-only and within the advertised capabilities.
