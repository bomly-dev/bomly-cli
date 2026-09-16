# How To Implement An Analyzer Plugin

An analyzer plugin runs code analysis after enrichment. Use an analyzer when you want to annotate vulnerabilities with reachability data — whether the scanned project can actually reach the vulnerable package or symbol — for a language the built-in analyzers do not cover, or with a technique they do not use.

An analyzer is one `plugin.Module` with `Kind: plugin.PluginKindAnalyzer`. The same module can be compiled into a host build (embedded) or served as a managed plugin binary with `runtime.ServeModule` — you write the component once. Analyzers run when a scan passes `--analyze` (which requires `--enrich`), after matchers and before auditors. [Plugin basics](../PLUGINS.md#write-a-plugin) covers the module model, repository contract, configuration, testing, and release flow shared by every role; this guide covers what is specific to analyzers.

The [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk) documents `plugin.Module`, `plugin.AnalyzerModule`, the `plugin.Analyzer` interface, `plugin.AnalyzeRequest`, `plugin.AnalyzeResult`, the PURL-keyed package registry, and the `model.Reachability` annotation used below.

## Start From The Template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository ("Use this template" on GitHub). It ships a working matcher; turning it into an analyzer means changing the module kind, the descriptor, and the role method — the layout, manifest, tests, and release workflow stay the same:

```text
plugin/                  importable package: descriptor, Config, Analyzer, Module()
cmd/<binary-name>/
  main.go                one line: runtime.ServeModule(plugin.Module())
bomly-plugin.json        package manifest ("kind": "analyzer")
testdata/                fixtures for unit tests
.github/workflows/       CI and the release workflow
go.mod                   pins a released github.com/bomly-dev/bomly-sdk version
```

## The Module

```go
package plugin

import (
    "context"
    "fmt"

    "github.com/bomly-dev/bomly-sdk/model"
    sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Name must equal the "id" field in bomly-plugin.json.
const Name = "com.example.myreach-analyzer"

// Config is the analyzer's typed configuration block.
type Config struct {
    MaxDepth int `json:"maxDepth" doc:"Maximum call-graph depth to explore" default:"10"`
}

// Analyzer annotates vulnerabilities with reachability. sdkplugin.BaseAnalyzer
// supplies default Ready/Applicable implementations. Override Ready when the
// analysis needs a toolchain that can be missing.
type Analyzer struct {
    sdkplugin.BaseAnalyzer
    config Config
}

func descriptor() sdkplugin.AnalyzerDescriptor {
    return sdkplugin.AnalyzerDescriptor{
        Name:        Name,
        DisplayName: "MyReach Analyzer",
        // SupportedLanguages is the analyzer's primary dispatch axis: Bomly
        // only runs the analyzer when the request's language matches (an
        // empty list reads as "all languages").
        SupportedLanguages: []model.Language{model.LanguageGo},
        // SupportedTiers communicates the precision you can deliver:
        // model.TierSymbol (call-path level) or model.TierPackage (import level).
        SupportedTiers: []model.ReachabilityTier{model.TierPackage},
        // The analyzer can return package-update deltas (see below).
        Capabilities: []string{sdkplugin.CapabilityPackageUpdates},
        ConfigSchema: sdkplugin.MustConfigSchemaFor(Config{}),
    }
}

func (a *Analyzer) Descriptor() sdkplugin.AnalyzerDescriptor { return descriptor() }

// Analyze annotates registry vulnerabilities with reachability.
func (a *Analyzer) Analyze(ctx context.Context, req sdkplugin.AnalyzeRequest) (sdkplugin.AnalyzeResult, error) {
    updated := annotateReachability(ctx, req) // your analysis; returns []*model.Package
    stats := map[string]sdkplugin.ReachabilityStats{Name: {Reachable: len(updated)}}

    if req.AcceptPackageUpdates {
        // Delta path: return only the packages you touched.
        return sdkplugin.AnalyzeResult{
            PackageUpdates: updated,
            AnalyzerRuns:   []string{Name},
            AnalyzerStats:  stats,
        }, nil
    }

    // Baseline path (protocol v1): return the full registry.
    registry := model.ApplyPackageUpdates(req.Registry, updated)
    return sdkplugin.AnalyzeResult{
        Registry:      registry,
        AnalyzerRuns:  []string{Name},
        AnalyzerStats: stats,
    }, nil
}

// Module packages the analyzer for both execution modes.
func Module() sdkplugin.Module {
    return sdkplugin.Module{
        Kind: sdkplugin.PluginKindAnalyzer,
        Analyzer: &sdkplugin.AnalyzerModule{
            Descriptor: descriptor(),
            New: func(_ context.Context, host sdkplugin.HostContext) (sdkplugin.Analyzer, error) {
                analyzer := &Analyzer{}
                if err := host.DecodeConfig(&analyzer.config); err != nil {
                    return nil, fmt.Errorf("decode %s config: %w", Name, err)
                }
                return analyzer, nil
            },
        },
    }
}
```

The binary entrypoint stays one line:

```go
func main() { runtime.ServeModule(plugin.Module()) }
```

## What Each Part Does

- `Descriptor` is the analyzer's static registration: name (must equal the manifest `id`), supported languages, tiers, capabilities, and config schema.
- `New` constructs the analyzer once per execution, with a `plugin.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the analyzer can run right now — return `nil` when ready, or an error whose message explains the reason (toolchain missing, source unreadable). `plugin.BaseAnalyzer` embeds an always-ready default.
- `Applicable(ctx, req) (bool, error)` reports whether the analyzer should run for this request (right language, right project shape).
- `Analyze` does the work: run the analysis and return reachability annotations.

All methods receive a context. Honor cancellation: analysis can be expensive, and a cancelled scan should stop the analyzer promptly. Check `ctx.Err()` between phases and pass the context into any subprocess or HTTP call.

## Reachability Semantics

Analyzers annotate `Vulnerability.Reachability` on packages in the PURL-keyed registry (`req.Registry`). They must not add or remove dependency nodes, rewrite graph identity, or alter vulnerability identity — only attach reachability:

```go
pkg, ok := req.Registry.Get("pkg:golang/example.com/mod@v1.2.3")
if !ok {
    return // nothing to annotate
}
for i := range pkg.Vulnerabilities {
    pkg.Vulnerabilities[i].Reachability = &model.Reachability{
        Status:   model.ReachabilityReachable,
        Tier:     model.TierPackage,
        Analyzer: Name,
    }
}
```

Use the statuses honestly: `model.ReachabilityReachable` when you found evidence, `model.ReachabilityUnreachable` when the analysis completed and found none (state your tier — package-tier unreachable does not mean safe), `model.ReachabilityUnknown` with a `Reason` when the analysis could not complete, and leave the annotation absent when the vulnerability is outside your scope.

**Never fail the scan.** Analyzer failures degrade: if your toolchain is missing, a file does not parse, or an internal step errors, report `unknown` with a reason (or return an error, which Bomly downgrades to a pipeline warning) — but prefer returning partial results over returning an error. The scan must complete either way.

## Registry Deltas (`package-updates-v1`)

Analyzers can respond in two shapes:

- **Full registry** (protocol v1 baseline): return `Registry` with every package, annotated or not. Always works.
- **Deltas**: return `PackageUpdates` containing only the packages you touched. The host merges them into its registry by PURL. Cheaper on the wire for large projects.

The rules:

1. Advertise `plugin.CapabilityPackageUpdates` (`"package-updates-v1"`) in `Descriptor.Capabilities`.
2. Return `PackageUpdates` **only when** `req.AcceptPackageUpdates` is true — that is the host telling you it understands deltas. Older hosts never set it, and you must fall back to returning the full registry for them.
3. When `Registry` is non-nil in the result, it wins and `PackageUpdates` is ignored — return one or the other.

`model.ApplyPackageUpdates` implements the same merge the host uses, which makes the legacy fallback a one-liner (see the `Analyze` example above) and is handy in tests.

## Configuration, HTTP, And Cache

Declare a typed `Config` struct with `json`, `doc:`, and `default:` tags, advertise it with `ConfigSchema: plugin.MustConfigSchemaFor(Config{})`, and decode it in `New` with `host.DecodeConfig(&cfg)`. Users set the block under `plugins.analyzers.<name>`:

```yaml
plugins:
  analyzers:
    com.example.myreach-analyzer:
      maxDepth: 10
```

The same block reaches the component in both execution modes. See [Configuration in the plugin guide](../PLUGINS.md#configuration-and-proxy-support) for details and the deprecated flat form.

If the analyzer calls an external service, use `HostContext.HTTPClient()` so proxy settings work consistently, and document every endpoint in the README. If the analysis is deterministic for a fixed input (lockfile hash, toolchain version), add caching inside the plugin; cache failures are non-fatal — log a warning and continue.

## Test It

Unit-test the analysis logic and both response shapes, and run the SDK conformance suite (it exercises the package-updates contract for modules that advertise the capability):

```go
func TestConformance(t *testing.T) {
    conformance.Test(t, conformance.Config{
        Module:       Module(),
        ManifestPath: filepath.Join("..", "bomly-plugin.json"),
        SampleConfig: json.RawMessage(`{"maxDepth":5}`),
    })
}
```

Local development loop:

```bash
go build -o ./bin/bomly-plugin-myreach ./cmd/bomly-plugin-myreach
bomly plugins install ./bin/bomly-plugin-myreach --dev
bomly plugins enable com.example.myreach-analyzer
bomly scan --path ./my-project --enrich --analyze --analyzers +com.example.myreach-analyzer --json
bomly plugins verify com.example.myreach-analyzer
bomly plugins test com.example.myreach-analyzer
bomly plugins doctor com.example.myreach-analyzer
```

`--analyzers +<name>` adds the analyzer to the default set; `--analyzers <name>` runs only it. The scan JSON records the analyzer under `metadata.analyzer_runs`, and annotated vulnerabilities carry your `reachability` block. See [Testing a plugin](../PLUGINS.md#test-a-plugin) for the shared workflow, including `conformance.ProbeBinary`.

## Package And Release

Follow the template's release workflow: one archive per platform named `<name>_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) containing the binary, `bomly-plugin.json`, `README.md`, and `LICENSE`, plus a `SHA256SUMS` file. The manifest's `entrypoint` map names the binary per platform, and `descriptor.Name` must equal the manifest `id`. See [Package and release](../PLUGINS.md#package-and-release-a-plugin).

## Implementation Checklist

- Annotate `Vulnerability.Reachability` on registry packages; do not rewrite graph or vulnerability identity.
- Never abort the scan: degrade to `unknown` (with a reason) or partial results on any failure.
- Advertise `SupportedLanguages`, `SupportedTiers`, and `Capabilities` accurately.
- Return `PackageUpdates` only when `req.AcceptPackageUpdates` is true; otherwise return the full registry.
- Honor context cancellation in long-running analysis.
- Make network calls through `HostContext.HTTPClient()` and document every endpoint.
- Wrap errors with useful context; avoid panics.
- Do not log secrets, tokens, or credentials.
- Add unit tests for the analysis logic and both response shapes, plus `conformance.Test`.
