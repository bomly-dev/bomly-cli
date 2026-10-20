# How to implement an analyzer plugin

An analyzer plugin runs code analysis after enrichment and marks each vulnerability as reachable or not from the scanned project. Write one for a language the built-in analyzers do not cover, or for a technique they do not use. Analyzers run when a scan passes `--analyze` (which requires `--enrich`), after matchers and before auditors.

[Plugin authoring](authoring.md) covers the module model, repository layout, configuration, testing, packaging, and protocol rules shared by every role. This guide covers only what is specific to analyzers. The SDK reference for the types used below is the [`plugin`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/plugin) and [`model`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/model) packages.

## Start from the template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository. It ships a working matcher. To turn it into an analyzer, change the module kind, the descriptor, and the role method; the layout, manifest, tests, and release workflow stay the same, with `"kind": "analyzer"` in `bomly-plugin.json`.

## The module

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

## What each part does

- `Descriptor` is the analyzer's static registration: name (must equal the manifest `id`), supported languages, tiers, capabilities, and config schema.
- `New` constructs the analyzer once per execution, with a `plugin.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the analyzer can run right now — return `nil` when ready, or an error whose message explains the reason (toolchain missing, source unreadable). `plugin.BaseAnalyzer` embeds an always-ready default.
- `Applicable(ctx, req) (bool, error)` reports whether the analyzer should run for this request (right language, right project shape).
- `Analyze` does the work: run the analysis and return reachability annotations.

All methods receive a context. Honor cancellation: analysis can be expensive, and a cancelled scan should stop the analyzer promptly. Check `ctx.Err()` between phases and pass the context into any subprocess or HTTP call.

## Reachability semantics

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

## Registry deltas (`package-updates-v1`)

Analyzers can respond in two shapes:

- **Full registry** (protocol v1 baseline): return `Registry` with every package, annotated or not. Always works.
- **Deltas**: return `PackageUpdates` containing only the packages you touched. The host merges them into its registry by PURL. Cheaper on the wire for large projects.

The rules:

1. Advertise `plugin.CapabilityPackageUpdates` (`"package-updates-v1"`) in `Descriptor.Capabilities`.
2. Return `PackageUpdates` **only when** `req.AcceptPackageUpdates` is true — that is the host telling you it understands deltas. Older hosts never set it, and you must fall back to returning the full registry for them.
3. When `Registry` is non-nil in the result, it wins and `PackageUpdates` is ignored — return one or the other.

`model.ApplyPackageUpdates` implements the same merge the host uses, which makes the legacy fallback a one-liner (see the `Analyze` example above) and is handy in tests.

## Configuration

Declare a typed `Config` struct, advertise it with `ConfigSchema`, and decode it in `New` as described in [Plugin authoring](authoring.md#configuration). Users set the block under `plugins.analyzers.<name>`:

```yaml
plugins:
  analyzers:
    com.example.myreach-analyzer:
      maxDepth: 10
```

If the analyzer calls an external service, use `HostContext.HTTPClient()` and document every endpoint in the README. If the analysis is deterministic for a fixed input (lockfile hash, toolchain version), cache it inside the plugin; a cache failure is a warning, not an error.

## Test it

Unit-test the analysis logic and both response shapes, then run the conformance suite and the local loop described in [Plugin authoring](authoring.md#test-a-plugin). `--analyzers +<name>` adds the analyzer to the default set; `--analyzers <name>` runs only it. The scan JSON records the analyzer under `metadata.analyzer_runs`, and annotated vulnerabilities carry your `reachability` block:

```bash
bomly scan --path ./my-project --enrich --analyze --analyzers +com.example.myreach-analyzer --json
```

## Checklist

In addition to the [checklist for every plugin](authoring.md#checklist-for-every-plugin):

- Annotate `Vulnerability.Reachability` on registry packages; do not rewrite graph or vulnerability identity.
- Never abort the scan: degrade to `unknown` with a reason, or to partial results.
- Advertise `SupportedLanguages`, `SupportedTiers`, and `Capabilities` accurately.
- Return `PackageUpdates` only when `req.AcceptPackageUpdates` is true; otherwise return the full registry.
