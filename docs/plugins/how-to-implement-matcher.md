# How to implement a matcher plugin

A matcher plugin enriches packages after detection. Write one when you want to add vulnerability data, license data, lifecycle information, health signals, or other metadata to Bomly's package registry.

[Plugin authoring](authoring.md) covers the module model, repository layout, configuration, testing, packaging, and protocol rules shared by every role. This guide covers only what is specific to matchers. The SDK reference for the types used below is the [`plugin`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/plugin) and [`model`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/model) packages.

## Start from the template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository. It ships a working matcher. Replace its `Match` logic and work through its rename checklist.

## The module

This is the template's matcher, trimmed to the essentials:

```go
package plugin

import (
    "context"
    "fmt"

    "github.com/bomly-dev/bomly-sdk/model"
    sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Name must equal the "id" field in bomly-plugin.json.
const Name = "com.example.license-matcher"

// Config is the matcher's typed configuration block.
type Config struct {
    APIBase string `json:"apiBase" doc:"Service endpoint override" default:"https://api.example.com"`
}

// Matcher enriches registry packages. sdkplugin.BaseMatcher supplies default
// Ready/Applicable implementations (always ready, always applicable).
type Matcher struct {
    sdkplugin.BaseMatcher
    config Config
    host   sdkplugin.HostContext
}

func descriptor() sdkplugin.MatcherDescriptor {
    return sdkplugin.MatcherDescriptor{
        Name:        Name,
        DisplayName: "Example License Matcher",
        Aliases:     []string{"example-licenses"},
        Tags:        []string{"license-enrichment", "http"},
        // Declare the ecosystems the matcher can actually enrich. An empty
        // list reads as "all ecosystems".
        SupportedEcosystems: []model.Ecosystem{model.EcosystemNPM, model.EcosystemGo},
        // The matcher can return package-update deltas (see below).
        Capabilities: []string{sdkplugin.CapabilityPackageUpdates},
        ConfigSchema: sdkplugin.MustConfigSchemaFor(Config{}),
    }
}

func (m *Matcher) Descriptor() sdkplugin.MatcherDescriptor { return descriptor() }

// Match runs once per scan with the full package registry.
func (m *Matcher) Match(ctx context.Context, req sdkplugin.MatchRequest) (sdkplugin.MatchResult, error) {
    stats := sdkplugin.MatcherStats{Name: Name, DisplayName: "Example License Matcher"}
    if req.Registry == nil {
        return sdkplugin.MatchResult{MatcherStats: stats}, nil
    }

    if req.AcceptPackageUpdates {
        // Delta path: return only the packages we touched. Each update is a
        // sparse Package carrying the PURL (the merge key) plus the new data.
        var updates []*model.Package
        for _, pkg := range req.Registry.All() {
            update := &model.Package{Coordinates: model.Coordinates{PURL: pkg.PURL}}
            update.Licenses = []model.PackageLicense{{SPDXExpression: "MIT"}}
            updates = append(updates, update)
        }
        stats.MatchedPackages = len(updates)
        stats.Licenses = len(updates)
        return sdkplugin.MatchResult{PackageUpdates: updates, MatcherStats: stats}, nil
    }

    // Baseline path (protocol v1): enrich in place, echo the full registry.
    for _, pkg := range req.Registry.All() {
        pkg.Licenses = append(pkg.Licenses, model.PackageLicense{SPDXExpression: "MIT"})
        stats.MatchedPackages++
        stats.Licenses++
    }
    return sdkplugin.MatchResult{Registry: req.Registry, MatcherStats: stats}, nil
}

// Module packages the matcher for both execution modes.
func Module() sdkplugin.Module {
    return sdkplugin.Module{
        Kind: sdkplugin.PluginKindMatcher,
        Matcher: &sdkplugin.MatcherModule{
            Descriptor: descriptor(),
            New: func(_ context.Context, host sdkplugin.HostContext) (sdkplugin.Matcher, error) {
                matcher := &Matcher{host: host}
                if err := host.DecodeConfig(&matcher.config); err != nil {
                    return nil, fmt.Errorf("decode %s config: %w", Name, err)
                }
                return matcher, nil
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

- `Descriptor` is the matcher's static registration: name (must equal the manifest `id`), display name, aliases, tags, supported ecosystems, capabilities, and config schema.
- `New` constructs the matcher once per execution, with a `plugin.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the matcher can run right now — return `nil` when ready, or an error explaining the reason (a missing token, an unreachable endpoint). `plugin.BaseMatcher` embeds an always-ready default; override it when your matcher depends on something that can be absent.
- `Applicable(ctx, req) (bool, error)` reports whether the matcher should run for this request (for example, only certain ecosystems).
- `Match` does the work: enrich registry packages and return the result with `MatcherStats`.

Matchers only run during explicit enrichment (`--enrich`). Honor the context: pass it into every HTTP call so a cancelled scan stops promptly.

## Use the registry

Bomly separates dependency instances from package records:

- `req.Graph` contains dependency nodes and edges — identity and structure.
- `req.Registry` contains canonical package records keyed by PURL. Matchers enrich each package once per PURL, no matter how many dependency instances point at it.

Use `Ensure` when a package may already exist:

```go
pkg := req.Registry.Ensure("pkg:npm/lodash@4.17.21")
pkg.Licenses = append(pkg.Licenses, model.PackageLicense{SPDXExpression: "MIT"})
pkg.Vulnerabilities = append(pkg.Vulnerabilities, model.Vulnerability{
    ID:     "GHSA-example",
    Source: "example-feed",
})
```

Prefer canonical PURLs. Auditors and output rendering use PURLs to connect findings, vulnerabilities, and packages. Enrich packages; do not rewrite graph identity.

## Registry deltas (`package-updates-v1`)

Matchers can respond in two shapes:

- **Full registry** (protocol v1 baseline): return `Registry` with every package, enriched or not. Always works.
- **Deltas**: return `PackageUpdates` containing only the packages you touched. The host merges them into its registry by PURL. Cheaper on the wire for large projects.

The rules:

1. Advertise `plugin.CapabilityPackageUpdates` in `Descriptor.Capabilities`.
2. Return `PackageUpdates` **only when** `req.AcceptPackageUpdates` is true — that is the host telling you it understands deltas. Older hosts never set it, and you must fall back to the full-registry shape for them.
3. When `Registry` is non-nil in the result, it wins and `PackageUpdates` is ignored — return one or the other.

`model.ApplyPackageUpdates` implements the same merge the host uses; it is handy in tests and for building a full-registry fallback from the delta path.

## Degrade, do not fail

Enrichment failures should not sink a scan. If the upstream service is down or a response does not parse, prefer returning partial results — the packages you did enrich, with `UnmatchedPackages` counted in `MatcherStats` — over returning an error. Report a completely unavailable dependency (missing token, unreachable endpoint) through `Ready` with a clear reason instead of failing mid-`Match`. Cache lookups that fail are non-fatal: log a warning and continue without the cache.

## Configuration

Declare a typed `Config` struct, advertise it with `ConfigSchema`, and decode it in `New` as described in [Plugin authoring](authoring.md#configuration). Users set the block under `plugins.matchers.<name>`:

```yaml
plugins:
  matchers:
    com.example.license-matcher:
      apiBase: https://api.example.com
```

Make outbound calls through `HostContext.HTTPClient()` so Bomly's proxy and CA settings apply. Document every endpoint the matcher talks to in its README. If the output is deterministic for a fixed input and service version, cache it inside the plugin; a cache failure is a warning, not an error.

## Test it

Unit-test the mapping from service responses into package data, cover both the full-registry and delta paths, then run the conformance suite and the local loop described in [Plugin authoring](authoring.md#test-a-plugin). `--matchers +<name>` adds the matcher to the default set; `--matchers <name>` runs only it:

```bash
bomly scan --path ./my-project --enrich --matchers +com.example.license-matcher --json
```

## Checklist

In addition to the [checklist for every plugin](authoring.md#checklist-for-every-plugin):

- Enrich `req.Registry` by PURL; do not rewrite graph identity.
- Return `MatcherStats` with the matcher name and useful counts.
- Advertise `SupportedEcosystems` and `Capabilities` accurately.
- Return `PackageUpdates` only when `req.AcceptPackageUpdates` is true; otherwise return the full registry.
- Degrade to partial results on upstream failures; report hard unavailability through `Ready`.
