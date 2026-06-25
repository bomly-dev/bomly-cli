# How To Implement A Detector Plugin

A detector plugin turns project evidence into a Bomly dependency graph. Use a detector when Bomly needs a new way to read dependency data, such as a new package manager, a specialized manifest format, or an internal dependency source.

External detector plugins are served with `sdk.ServeDetector`.

The [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-cli/sdk) documents the `sdk.ServeDetector` entrypoint, `sdk.ServedDetector` interface, `sdk.DetectionRequest`, `sdk.DetectionResult`, graph helpers, coordinates, and package-manager support types used below.

## Minimum Shape

Create a Go `main` package that imports the Bomly SDK:

```go
package main

import (
    "context"

    "github.com/bomly-dev/bomly-cli/sdk"
)

const pluginID = "bomly.examples.detector.bun-lock"

type detector struct{}


func (d *detector) Descriptor(context.Context) (*sdk.DetectorDescriptor, error) {
    return &sdk.DetectorDescriptor{
        Name:        pluginID,
        DisplayName: "Bun Lock Detector",
        Aliases:     []string{"bun-lock"},
        Tags:        []string{"dependency-detection", "bun"},
    }, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error) {
    return []sdk.PackageManagerSupport{
        sdk.Support(sdk.PackageManagerOther, "bun.lock", "bun.lockb", "package.json"),
    }, nil
}

func (d *detector) Ready(context.Context, *sdk.DetectRequest) (*sdk.ReadyResponse, error) {
    return &sdk.ReadyResponse{Ready: true}, nil
}

func (d *detector) Applicable(context.Context, *sdk.DetectRequest) (*sdk.ApplicableResponse, error) {
    return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (d *detector) Detect(ctx context.Context, req *sdk.DetectRequest) (*sdk.DetectResponse, error) {
    graph := sdk.New()
    dep := sdk.NewDependency(sdk.Dependency{
        Coordinates: sdk.Coordinates{
            Ecosystem: sdk.EcosystemNPM,
            Name:      "is-odd",
            Version:   "3.0.1",
            PURL:      "pkg:npm/is-odd@3.0.1",
        },
        FoundBy: pluginID,
    })
    if err := graph.AddNode(dep); err != nil {
        return nil, err
    }
    return &sdk.DetectResponse{
        SubprojectInfo:      req.Subproject,
        RootExecutionTarget: req.ExecutionTarget,
        Graphs: &sdk.GraphContainer{
            Entries: []sdk.GraphEntry{{
                Manifest: sdk.ManifestMetadata{Path: "package.json", Kind: sdk.ManifestKind("package.json")},
                Graph:    graph,
            }},
        },
    }, nil
}

func main() {
    sdk.ServeDetector(&detector{})
}
```

The working example repo is [bomly-plugin-bun-lock-detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector). It demonstrates `sdk.PackageManagerOther` for a package manager Bomly does not model directly yet.

## What Each Hook Does

- `Descriptor` describes the component identity, display name, aliases, tags, support, and detector behavior.
- `PackageManagerSupport` tells Bomly which package managers and evidence patterns can plan this detector.
- `Ready` reports whether the plugin can run in the current environment.
- `Applicable` reports whether the plugin should run for the current request.
- `Detect` reads the request and returns a `sdk.DetectResponse` containing one or more manifest-scoped graphs.

Detector plugins may also implement:

```go
func (d *detector) Install(context.Context, *sdk.DetectRequest) (*sdk.InstallResponse, error)
```

Use `Install` only for install-first detectors that prepare dependencies before graph resolution. Do not install package managers themselves; Bomly assumes required package managers already exist.

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
    return nil, err
}
if err := graph.AddNode(child); err != nil {
    return nil, err
}
if err := graph.AddEdge(parent.ID, child.ID); err != nil {
    return nil, err
}
```

Return `req.Subproject` and `req.ExecutionTarget` in the response so Bomly can keep the result tied to the planned scan target.

## Package And Install

For development, build and install the binary directly:

```bash
go build -o ./bin/bomly-plugin-bun-lock-detector .
bomly plugin install ./bin/bomly-plugin-bun-lock-detector --dev
bomly plugin enable bomly.examples.detector.bun-lock
```

For distribution, package a package-only `bomly-plugin.json` manifest with the binary:

```text
bomly-plugin.json
bin/
  bomly-plugin-bun-lock-detector
README.md
```

The manifest contains package and install fields only: ID, kind, version, runtime, API version, Bomly version constraint, entrypoint, source, homepage, description, and license. Bomly probes the binary at install time, verifies `descriptor.name == manifest.id`, and writes its own internal descriptor snapshot for plugin list, selectors, verification, and runtime registration.

## Test It

Check installation and runtime readiness:

```bash
bomly plugin verify bomly.examples.detector.bun-lock
bomly plugin test bomly.examples.detector.bun-lock
bomly plugin doctor bomly.examples.detector.bun-lock
```

Run only this detector:

```bash
bomly scan --path ./my-project --detectors bomly.examples.detector.bun-lock --json
```

Or add it to the default detector set:

```bash
bomly scan --path ./my-project --detectors +bomly.examples.detector.bun-lock
```

## Implementation Checklist

- Declare accurate package-manager support and evidence patterns.
- Wrap errors with useful context.
- Avoid panics in normal flow.
- Do not log secrets, tokens, or credentials.
- Keep network calls explicit and explain them in the plugin README.
- Add local unit tests for parsing and graph construction.
