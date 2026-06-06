# How To Implement A Detector Plugin

A detector plugin turns project evidence into a Bomly dependency graph. Use a detector when Bomly needs a new way to read dependency data, such as a new package manager, a specialized manifest format, or an internal dependency source.

External detector plugins are served with `sdk.ServeDetector`.

## Minimum Shape

Create a Go `main` package that imports the Bomly SDK:

```go
package main

import (
    "context"

    "github.com/bomly-dev/bomly-cli/sdk"
)

const pluginID = "security-team.detector.gomod"

type detector struct{}

func (d *detector) Metadata(context.Context) (*sdk.PluginMetadata, error) {
    return &sdk.PluginMetadata{
        ID:               pluginID,
        Name:             "Security Team Go Module Detector",
        Version:          "0.1.0",
        Kind:             sdk.PluginKindDetector,
        PluginAPIVersion: sdk.PluginAPIVersion,
    }, nil
}

func (d *detector) Descriptor(context.Context) (*sdk.DetectorDescriptor, error) {
    return &sdk.DetectorDescriptor{
        Name:         pluginID,
        Enabled:      true,
        Origin:       sdk.ExternalOrigin,
        Capabilities: []string{"dependency-detection"},
    }, nil
}

func (d *detector) PackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error) {
    return []sdk.PackageManagerSupport{
        sdk.Support(sdk.PackageManagerGoMod, "go.mod"),
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
        Ecosystem: string(sdk.EcosystemGo),
        Name:      "example.com/app",
        Version:   "v0.0.0",
        PURL:      "pkg:golang/example.com/app@v0.0.0",
        FoundBy:   pluginID,
    })
    if err := graph.AddNode(dep); err != nil {
        return nil, err
    }
    return &sdk.DetectResponse{
        SubprojectInfo:      req.Subproject,
        RootExecutionTarget: req.ExecutionTarget,
        DetectorName:        pluginID,
        Origin:              sdk.ExternalOrigin,
        Graphs: &sdk.GraphContainer{
            Entries: []sdk.GraphEntry{{
                Manifest: sdk.ManifestMetadata{Path: "go.mod", Kind: sdk.ManifestKind("go.mod")},
                Graph:    graph,
            }},
        },
    }, nil
}

func main() {
    sdk.ServeDetector(&detector{})
}
```

The working example in this repository is [`examples/plugins/go-module-detector`](../../examples/plugins/go-module-detector).

## What Each Hook Does

- `Metadata` returns the plugin identity. The ID, version, kind, and API version must match the installed manifest.
- `Descriptor` describes the detector registration. Use `sdk.ExternalOrigin` for external plugins.
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
parent := sdk.NewDependency(sdk.Dependency{Name: "app", Version: "0.0.0", PURL: "pkg:generic/app@0.0.0"})
child := sdk.NewDependency(sdk.Dependency{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"})

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
go build -o ./bin/security-team-gomod-detector ./cmd/security-team-gomod-detector
bomly plugin install ./bin/security-team-gomod-detector --dev
bomly plugin enable security-team.detector.gomod
```

For distribution, package a `bomly-plugin.json` manifest with the binary:

```text
bomly-plugin.json
bin/
  security-team-gomod-detector
README.md
LICENSE
```

The detector manifest must include `detectorDescriptor.packageManagerSupport`; Bomly uses it for subproject discovery and scan planning.

## Test It

Check installation and runtime readiness:

```bash
bomly plugin verify security-team.detector.gomod
bomly plugin test security-team.detector.gomod
bomly plugin doctor security-team.detector.gomod
```

Run only this detector:

```bash
bomly scan --path ./my-project --detectors security-team.detector.gomod --json
```

Or add it to the default detector set:

```bash
bomly scan --path ./my-project --detectors +security-team.detector.gomod
```

## Implementation Checklist

- Return stable `PluginMetadata` and keep it in sync with the manifest.
- Declare accurate package-manager support and evidence patterns.
- Wrap errors with useful context.
- Avoid panics in normal flow.
- Do not log secrets, tokens, or credentials.
- Keep network calls explicit and explain them in the plugin README.
- Add local unit tests for parsing and graph construction.
