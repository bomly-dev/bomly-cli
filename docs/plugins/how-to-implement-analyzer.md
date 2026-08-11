# How To Implement An Analyzer Plugin

An analyzer plugin runs code analysis after enrichment. Use an analyzer when you want to annotate vulnerabilities with reachability data — whether the scanned project can actually reach the vulnerable package or symbol — for a language the built-in analyzers do not cover, or with a technique they do not use.

External analyzer plugins are served with `sdk.ServeAnalyzer`. They run when a scan passes `--analyze` (which requires `--enrich`), after matchers and before auditors.

The [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk) documents the `sdk.ServeAnalyzer` entrypoint, `sdk.ServedAnalyzer` interface, `sdk.AnalyzeRequest`, `sdk.AnalyzeResponse`, PURL-keyed package registry, and the `sdk.Reachability` annotation used below.

## Repository Layout

An analyzer plugin is an independent Go module that pins a released SDK version:

```text
go.mod                      module example.com/bomly-plugin-myreach
                            require github.com/bomly-dev/bomly-sdk v0.1.0
analyzer/                   implementation package (analysis logic, tests)
cmd/bomly-plugin-myreach/
  main.go                   thin entrypoint calling sdk.ServeAnalyzer
bomly-plugin.json           package manifest
README.md
```

Keep the analysis logic in a normal library package so it is unit-testable without the plugin runtime, and keep `main.go` minimal:

```go
package main

import (
    "example.com/bomly-plugin-myreach/analyzer"

    "github.com/bomly-dev/bomly-sdk"
)

func main() {
    sdk.ServeAnalyzer(analyzer.New())
}
```

## Minimum Shape

The implementation satisfies `sdk.ServedAnalyzer`:

```go
package analyzer

import (
    "context"

    "github.com/bomly-dev/bomly-sdk"
)

const pluginID = "myreach-analyzer"

// Config is the plugin's configuration block. Advertising it through
// ConfigSchema lets `bomly plugins info` document it.
type Config struct {
    MaxDepth int `json:"max_depth" doc:"Maximum call-graph depth to explore" default:"10"`
}

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Descriptor(context.Context) (*sdk.AnalyzerDescriptor, error) {
    return &sdk.AnalyzerDescriptor{
        Name:        pluginID,
        DisplayName: "MyReach Analyzer",
        // SupportedLanguages is the analyzer's primary dispatch axis: Bomly
        // only runs the analyzer when the request's language matches (an
        // empty list reads as "all languages").
        SupportedLanguages: []sdk.Language{sdk.LanguageGo},
        // SupportedTiers communicates the precision you can deliver:
        // TierSymbol (call-path level) or TierPackage (import level).
        SupportedTiers: []sdk.ReachabilityTier{sdk.TierPackage},
        // Advertise optional protocol features. CapabilityPackageUpdates
        // enables the registry-delta response contract described below.
        Capabilities: []string{sdk.CapabilityPackageUpdates},
        ConfigSchema: sdk.MustConfigSchemaFor(Config{}),
    }, nil
}

func (a *Analyzer) Ready(context.Context, *sdk.AnalyzeRequest) (*sdk.ReadyResponse, error) {
    return &sdk.ReadyResponse{Ready: true}, nil
}

func (a *Analyzer) Applicable(context.Context, *sdk.AnalyzeRequest) (*sdk.ApplicableResponse, error) {
    return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (a *Analyzer) Analyze(ctx context.Context, req *sdk.AnalyzeRequest) (*sdk.AnalyzeResponse, error) {
    updated := annotateReachability(ctx, req) // your analysis; returns []*sdk.Package
    stats := map[string]sdk.ReachabilityStats{pluginID: {Reachable: len(updated)}}

    if req.AcceptPackageUpdates {
        // Modern hosts merge deltas: return only the packages you touched.
        return &sdk.AnalyzeResponse{PackageUpdates: updated, AnalyzerStats: stats}, nil
    }

    // Older hosts expect the full registry back.
    registry := sdk.ApplyPackageUpdates(req.Registry, updated)
    return &sdk.AnalyzeResponse{Registry: registry, AnalyzerStats: stats}, nil
}
```

## What Each Hook Does

- `Descriptor` describes the component identity, supported languages, tiers, capabilities, and configuration schema.
- `Ready` reports whether the analyzer can run in the current environment (toolchain present, source readable). Return `Ready: false` with a `Reason` instead of an error when the environment is simply missing something.
- `Applicable` reports whether the analyzer should run for the current request (right language, project shape).
- `Analyze` reads `sdk.AnalyzeRequest` and returns reachability annotations.

All hooks receive a context. Honor cancellation: analysis can be expensive, and a cancelled scan should stop the analyzer promptly. Check `ctx.Err()` between phases and pass the context into any subprocess or HTTP call.

## Reachability Semantics

Analyzers annotate `Vulnerability.Reachability` on packages in the PURL-keyed registry (`req.Registry`). They must not add or remove dependency nodes, rewrite graph identity, or alter vulnerability identity — only attach reachability:

```go
pkg, ok := req.Registry.Get("pkg:golang/example.com/mod@v1.2.3")
if !ok {
    return nil // nothing to annotate
}
for i := range pkg.Vulnerabilities {
    pkg.Vulnerabilities[i].Reachability = &sdk.Reachability{
        Status:   sdk.ReachabilityReachable,
        Tier:     sdk.TierPackage,
        Analyzer: pluginID,
    }
}
```

Use the four statuses honestly: `reachable` when you found evidence, `unreachable` when the analysis completed and found none (state your tier — package-tier unreachable does not mean safe), `unknown` with a `Reason` when the analysis could not complete, and leave the annotation absent when the vulnerability is outside your scope.

**Never fail the scan.** Analyzer failures degrade: if your toolchain is missing, a file does not parse, or an internal step errors, report `unknown` with a reason (or return an error, which Bomly downgrades to a pipeline warning) — but prefer returning partial results over returning an error. The scan must complete either way.

## Registry Deltas (`package-updates-v1`)

Analyzers can return results in two shapes:

- **Full registry** (protocol v1 baseline): return `Registry` with every package, annotated or not. Always works.
- **Deltas**: return `PackageUpdates` containing only the packages you touched. The host merges them into its registry by PURL. Cheaper on the wire for large projects.

The rules:

1. Advertise `sdk.CapabilityPackageUpdates` (`"package-updates-v1"`) in `Descriptor.Capabilities`.
2. Return `PackageUpdates` **only when** `req.AcceptPackageUpdates` is true — that is the host telling you it understands deltas. Older hosts never set it, and you must fall back to returning the full registry for them.
3. When `Registry` is non-nil in the response, it wins and `PackageUpdates` is ignored, so return one or the other.

`sdk.ApplyPackageUpdates` implements the same merge the host uses, which makes the legacy fallback a one-liner (see the `Analyze` example above) and is handy in tests.

## Configuration

Per-analyzer config lives under the kind-scoped `plugins.analyzers.<name>` block:

```yaml
plugins:
  analyzers:
    myreach-analyzer:
      max_depth: 10
```

(The deprecated flat `plugins.<name>` form still works but emits a deprecation warning.)

Read it with:

```go
var cfg Config
if err := sdk.DecodePluginConfigFromEnv(&cfg); err != nil {
    return nil, err
}
```

Declare the same struct in `Descriptor.ConfigSchema` via `sdk.ConfigSchemaFor` (or `MustConfigSchemaFor`) so `bomly plugins info <name>` can render the configuration keys, docs, and defaults.

If the analyzer calls an external service, use Bomly's SDK HTTP provider so proxy settings work consistently:

```go
provider, err := sdk.NewHTTPClientProviderFromEnv()
if err != nil {
    return nil, err
}
client := provider.Client(20 * time.Second)
```

If the analysis is deterministic for a fixed input (lockfile hash, toolchain version), add caching inside the plugin. Cache failures should be non-fatal: log a warning and continue without cached data.

## Package And Install

For development, build and install the binary directly:

```bash
go build -o ./bin/bomly-plugin-myreach ./cmd/bomly-plugin-myreach
bomly plugins install ./bin/bomly-plugin-myreach --dev
bomly plugins enable myreach-analyzer
```

For distribution, package a package-only `bomly-plugin.json` manifest (with `"kind": "analyzer"`) alongside per-platform binaries:

```text
bomly-plugin.json
bin/
  bomly-plugin-myreach
README.md
```

Publish one archive per platform (for example `bomly-plugin-myreach_linux_amd64.tar.gz`) plus a `SHA256SUMS` file so `github:owner/repo@tag` installs verify checksums automatically. The manifest contains package and install fields only. Bomly probes the binary at install time, verifies `descriptor.name == manifest.id`, and writes its own internal descriptor snapshot for plugin list, selectors, verification, and runtime registration.

## Test It

Check installation and runtime readiness:

```bash
bomly plugins verify myreach-analyzer
bomly plugins test myreach-analyzer
bomly plugins doctor myreach-analyzer
```

Run only this analyzer during a scan:

```bash
bomly scan --path ./my-project --enrich --analyze --analyzers myreach-analyzer --json
```

Or add it to the default analyzer set:

```bash
bomly scan --path ./my-project --enrich --analyze --analyzers +myreach-analyzer
```

The scan JSON records the analyzer under `metadata.analyzer_runs`, and annotated vulnerabilities carry your `reachability` block.

## Implementation Checklist

- Annotate `Vulnerability.Reachability` on registry packages; do not rewrite graph or vulnerability identity.
- Never abort the scan: degrade to `unknown` (with a reason) or partial results on any failure.
- Advertise `SupportedLanguages`, `SupportedTiers`, and `Capabilities` accurately.
- Return `PackageUpdates` only when `req.AcceptPackageUpdates` is true; otherwise return the full registry.
- Honor context cancellation in long-running analysis.
- Document configuration through `ConfigSchema` and read it with `DecodePluginConfigFromEnv`.
- Be explicit in your README about any network calls the analyzer makes; keep them behind configuration where possible.
- Honor proxy settings through `sdk.NewHTTPClientProviderFromEnv`.
- Wrap errors with useful context and avoid panics.
- Do not log secrets, tokens, or credentials.
- Add unit tests for the analysis logic and the delta/full-registry response paths.
