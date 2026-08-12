# How To Implement A Matcher Plugin

A matcher plugin enriches packages after detection. Use a matcher when you want to add vulnerability data, license data, lifecycle information, health signals, or other package metadata to Bomly's package registry.

A matcher is one `sdk.Module` with `Kind: sdk.PluginKindMatcher`. The same module can be compiled into a host build (embedded) or served as a managed plugin binary with `sdk.ServeModule` — you write the component once. [Plugin basics](../PLUGINS.md#write-a-plugin) covers the module model, repository contract, configuration, testing, and release flow shared by every role; this guide covers what is specific to matchers.

The [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk) documents `sdk.Module`, `sdk.MatcherModule`, the `sdk.Matcher` interface, `sdk.MatchRequest`, `sdk.MatchResult`, the PURL-keyed package registry, and the enrichment types used below.

## Start From The Template

The [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository *is* a matcher — a complete, working one that annotates every package with a configurable greeting. Click "Use this template" on GitHub, work through its rename checklist, and replace the `Match` logic. The layout:

```text
plugin/                  importable package: descriptor, Config, Matcher, Module()
cmd/<binary-name>/
  main.go                one line: sdk.ServeModule(plugin.Module())
bomly-plugin.json        package manifest ("kind": "matcher")
testdata/                fixture registry for unit tests
.github/workflows/       CI and the release workflow
go.mod                   pins a released github.com/bomly-dev/bomly-sdk version
```

## The Module

This is the template's matcher, trimmed to the essentials:

```go
package plugin

import (
    "context"
    "fmt"

    sdk "github.com/bomly-dev/bomly-sdk"
)

// Name must equal the "id" field in bomly-plugin.json.
const Name = "com.example.license-matcher"

// Config is the matcher's typed configuration block.
type Config struct {
    APIBase string `json:"apiBase" doc:"Service endpoint override" default:"https://api.example.com"`
}

// Matcher enriches registry packages. sdk.BaseMatcher supplies default
// Ready/Applicable implementations (always ready, always applicable).
type Matcher struct {
    sdk.BaseMatcher
    config Config
    host   sdk.HostContext
}

func descriptor() sdk.MatcherDescriptor {
    return sdk.MatcherDescriptor{
        Name:        Name,
        DisplayName: "Example License Matcher",
        Aliases:     []string{"example-licenses"},
        Tags:        []string{"license-enrichment", "http"},
        // Declare the ecosystems the matcher can actually enrich. An empty
        // list reads as "all ecosystems".
        SupportedEcosystems: []sdk.Ecosystem{sdk.EcosystemNPM, sdk.EcosystemGo},
        // The matcher can return package-update deltas (see below).
        Capabilities: []string{sdk.CapabilityPackageUpdates},
        ConfigSchema: sdk.MustConfigSchemaFor(Config{}),
    }
}

func (m *Matcher) Descriptor() sdk.MatcherDescriptor { return descriptor() }

// Match runs once per scan with the full package registry.
func (m *Matcher) Match(ctx context.Context, req sdk.MatchRequest) (sdk.MatchResult, error) {
    stats := sdk.MatcherStats{Name: Name, DisplayName: "Example License Matcher"}
    if req.Registry == nil {
        return sdk.MatchResult{MatcherStats: stats}, nil
    }

    if req.AcceptPackageUpdates {
        // Delta path: return only the packages we touched. Each update is a
        // sparse Package carrying the PURL (the merge key) plus the new data.
        var updates []*sdk.Package
        for _, pkg := range req.Registry.All() {
            update := &sdk.Package{Coordinates: sdk.Coordinates{PURL: pkg.PURL}}
            update.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
            updates = append(updates, update)
        }
        stats.MatchedPackages = len(updates)
        stats.Licenses = len(updates)
        return sdk.MatchResult{PackageUpdates: updates, MatcherStats: stats}, nil
    }

    // Baseline path (protocol v1): enrich in place, echo the full registry.
    for _, pkg := range req.Registry.All() {
        pkg.Licenses = append(pkg.Licenses, sdk.PackageLicense{SPDXExpression: "MIT"})
        stats.MatchedPackages++
        stats.Licenses++
    }
    return sdk.MatchResult{Registry: req.Registry, MatcherStats: stats}, nil
}

// Module packages the matcher for both execution modes.
func Module() sdk.Module {
    return sdk.Module{
        Kind: sdk.PluginKindMatcher,
        Matcher: &sdk.MatcherModule{
            Descriptor: descriptor(),
            New: func(_ context.Context, host sdk.HostContext) (sdk.Matcher, error) {
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
func main() { sdk.ServeModule(plugin.Module()) }
```

## What Each Part Does

- `Descriptor` is the matcher's static registration: name (must equal the manifest `id`), display name, aliases, tags, supported ecosystems, capabilities, and config schema.
- `New` constructs the matcher once per execution, with a `sdk.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the matcher can run right now — return `nil` when ready, or an error explaining the reason (a missing token, an unreachable endpoint). `sdk.BaseMatcher` embeds an always-ready default; override it when your matcher depends on something that can be absent.
- `Applicable(ctx, req) (bool, error)` reports whether the matcher should run for this request (for example, only certain ecosystems).
- `Match` does the work: enrich registry packages and return the result with `MatcherStats`.

Matchers only run during explicit enrichment (`--enrich`). Honor the context: pass it into every HTTP call so a cancelled scan stops promptly.

## Use The Registry

Bomly separates dependency instances from package records:

- `req.Graph` contains dependency nodes and edges — identity and structure.
- `req.Registry` contains canonical package records keyed by PURL. Matchers enrich each package once per PURL, no matter how many dependency instances point at it.

Use `Ensure` when a package may already exist:

```go
pkg := req.Registry.Ensure("pkg:npm/lodash@4.17.21")
pkg.Licenses = append(pkg.Licenses, sdk.PackageLicense{SPDXExpression: "MIT"})
pkg.Vulnerabilities = append(pkg.Vulnerabilities, sdk.Vulnerability{
    ID:     "GHSA-example",
    Source: "example-feed",
})
```

Prefer canonical PURLs. Auditors and output rendering use PURLs to connect findings, vulnerabilities, and packages. Enrich packages; do not rewrite graph identity.

## Registry Deltas (`package-updates-v1`)

Matchers can respond in two shapes:

- **Full registry** (protocol v1 baseline): return `Registry` with every package, enriched or not. Always works.
- **Deltas**: return `PackageUpdates` containing only the packages you touched. The host merges them into its registry by PURL. Cheaper on the wire for large projects.

The rules:

1. Advertise `sdk.CapabilityPackageUpdates` in `Descriptor.Capabilities`.
2. Return `PackageUpdates` **only when** `req.AcceptPackageUpdates` is true — that is the host telling you it understands deltas. Older hosts never set it, and you must fall back to the full-registry shape for them.
3. When `Registry` is non-nil in the result, it wins and `PackageUpdates` is ignored — return one or the other.

`sdk.ApplyPackageUpdates` implements the same merge the host uses; it is handy in tests and for building a full-registry fallback from the delta path.

## Degrade, Don't Fail

Enrichment failures should not sink a scan. If the upstream service is down or a response does not parse, prefer returning partial results — the packages you did enrich, with `UnmatchedPackages` counted in `MatcherStats` — over returning an error. Report a completely unavailable dependency (missing token, unreachable endpoint) through `Ready` with a clear reason instead of failing mid-`Match`. Cache lookups that fail are non-fatal: log a warning and continue without the cache.

## Configuration, HTTP, And Cache

Declare a typed `Config` struct with `json`, `doc:`, and `default:` tags, advertise it with `ConfigSchema: sdk.MustConfigSchemaFor(Config{})`, and decode it in `New` with `host.DecodeConfig(&cfg)`. Users set the block under `plugins.matchers.<name>`:

```yaml
plugins:
  matchers:
    com.example.license-matcher:
      apiBase: https://api.example.com
```

The same block reaches the component in both execution modes. See [Configuration in the plugin guide](../PLUGINS.md#configuration-and-proxy-support) for details and the deprecated flat form.

Make outbound calls through `HostContext.HTTPClient()` so Bomly's proxy, no-proxy, and CA settings apply consistently:

```go
client := m.host.HTTPClient().Client(20 * time.Second)
```

Document every endpoint the matcher talks to in its README. If the matcher produces deterministic output for a fixed input and service version, add caching inside the plugin; cache failures are non-fatal.

## Test It

Unit-test the mapping from service responses into registry package data, cover both the full-registry and delta paths, and run the SDK conformance suite:

```go
func TestConformance(t *testing.T) {
    conformance.Test(t, conformance.Config{
        Module:       Module(),
        ManifestPath: filepath.Join("..", "bomly-plugin.json"),
        SampleConfig: json.RawMessage(`{"apiBase":"https://example.test"}`),
    })
}
```

The template's `plugin/plugin_test.go` shows a minimal test `HostContext` stub and fixture-registry loading.

Local development loop:

```bash
go build -o ./bin/bomly-plugin-example ./cmd/bomly-plugin-example
bomly plugins install ./bin/bomly-plugin-example --dev
bomly plugins enable com.example.license-matcher
bomly scan --path ./my-project --enrich --matchers +com.example.license-matcher --json
bomly plugins verify com.example.license-matcher
bomly plugins test com.example.license-matcher
bomly plugins doctor com.example.license-matcher
```

`--matchers +<name>` adds the matcher to the default set; `--matchers <name>` runs only it. See [Testing a plugin](../PLUGINS.md#test-a-plugin) for the shared workflow, including `conformance.ProbeBinary`.

## Package And Release

Follow the template's release workflow: one archive per platform named `<name>_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) containing the binary, `bomly-plugin.json`, `README.md`, and `LICENSE`, plus a `SHA256SUMS` file. The manifest's `entrypoint` map names the binary per platform, and `descriptor.Name` must equal the manifest `id`. See [Package and release](../PLUGINS.md#package-and-release-a-plugin).

## Implementation Checklist

- Enrich `req.Registry` by PURL; do not rewrite graph identity.
- Return `MatcherStats` with the matcher name and useful counts.
- Advertise `SupportedEcosystems` and `Capabilities` accurately.
- Return `PackageUpdates` only when `req.AcceptPackageUpdates` is true; otherwise return the full registry.
- Degrade to partial results on upstream failures; report hard unavailability through `Ready`.
- Make network calls through `HostContext.HTTPClient()` and document every endpoint.
- Honor context cancellation in HTTP calls and long loops.
- Wrap errors with useful context; avoid panics.
- Do not log secrets, tokens, or credentials.
- Add unit tests for response mapping plus both response shapes, and `conformance.Test`.
