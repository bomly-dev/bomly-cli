# How To Implement A Matcher Plugin

A matcher plugin enriches packages after detection. Use a matcher when you want to add vulnerability data, license data, lifecycle information, health signals, or other package metadata to Bomly's package registry.

External matcher plugins are served with `sdk.ServeMatcher`.

The [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-cli/sdk) documents the `sdk.ServeMatcher` entrypoint, `sdk.ServedMatcher` interface, `sdk.MatchRequest`, `sdk.MatchResult`, PURL-keyed package registry, and enrichment types used below.

## Minimum Shape

Create a Go `main` package that imports the Bomly SDK:

```go
package main

import (
    "context"

    "github.com/bomly-dev/bomly-cli/sdk"
)

const pluginID = "clearlydefined-license-matcher"

type matcher struct{}


func (m *matcher) Descriptor(context.Context) (*sdk.MatcherDescriptor, error) {
    return &sdk.MatcherDescriptor{
        Name:        pluginID,
        DisplayName: "ClearlyDefined License Matcher",
        Aliases:     []string{"clearlydefined", "licenses"},
        Tags:        []string{"license-enrichment", "http", "cache"},
    }, nil
}

func (m *matcher) Ready(context.Context, *sdk.MatchRequest) (*sdk.ReadyResponse, error) {
    return &sdk.ReadyResponse{Ready: true}, nil
}

func (m *matcher) Applicable(context.Context, *sdk.MatchRequest) (*sdk.ApplicableResponse, error) {
    return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (m *matcher) Match(ctx context.Context, req *sdk.MatchRequest) (*sdk.MatchResponse, error) {
    registry := req.Registry
    if registry == nil {
        registry = sdk.NewPackageRegistry()
    }

    pkg := registry.Ensure("pkg:npm/lodash@4.17.21")
    pkg.Licenses = []sdk.PackageLicense{{SPDXExpression: "MIT"}}
    pkg.Vulnerabilities = append(pkg.Vulnerabilities, sdk.Vulnerability{
        ID:     "GHSA-example",
        Source: "example-feed",
    })

    return &sdk.MatchResponse{
        Registry: registry,
        MatcherStats: sdk.MatcherStats{
            Name: pluginID,
            DisplayName: "ClearlyDefined License Matcher",
            MatchedPackages: 1,
            Licenses: 1,
            Vulnerabilities: 1,
        },
    }, nil
}

func main() {
    sdk.ServeMatcher(&matcher{})
}
```

The working example repo is [bomly-plugin-clearlydefined-matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher). It shows a standalone HTTP matcher with plugin-local cache and proxy-aware SDK HTTP clients.

## What Each Hook Does

- `Descriptor` describes the component identity, display name, aliases, tags, and support.
- `Ready` reports whether the plugin can run in the current environment.
- `Applicable` reports whether the matcher should run for the current request.
- `Match` reads `sdk.MatchRequest` and returns a `sdk.MatchResponse` with the enriched registry.

## Use The Registry

Bomly separates dependency instances from package records:

- `req.Graph` contains dependency nodes and edges.
- `req.Registry` contains canonical package records keyed by PURL.
- Matchers enrich registry packages and return the updated registry.

Use `Ensure` when a package may already exist:

```go
pkg := req.Registry.Ensure("pkg:npm/lodash@4.17.21")
pkg.Licenses = append(pkg.Licenses, sdk.PackageLicense{SPDXExpression: "MIT"})
pkg.Vulnerabilities = append(pkg.Vulnerabilities, sdk.Vulnerability{
    ID:     "GHSA-example",
    Source: "security-team",
})
```

Prefer canonical PURLs. Auditors and output rendering use PURLs to connect findings, vulnerabilities, and packages.

## Configuration, HTTP, And Cache

Per-plugin config lives under `plugins.<plugin-id>`:

```yaml
plugins:
  clearlydefined-license-matcher:
    api_base: https://api.clearlydefined.io
```

Read it with:

```go
type config struct {
    APIBase string `json:"api_base"`
}

var cfg config
if err := sdk.DecodePluginConfigFromEnv(&cfg); err != nil {
    return nil, err
}
```

If the matcher calls an external service, use Bomly's SDK HTTP provider so proxy settings work consistently:

```go
provider, err := sdk.NewHTTPClientProviderFromEnv()
if err != nil {
    return nil, err
}
client := provider.Client(20 * time.Second)
_ = client
```

If the matcher produces deterministic output for a fixed input and service version, add caching inside the plugin. Cache failures should be non-fatal: log a warning and continue without cached data.

## Package And Install

For development, build and install the binary directly:

```bash
go build -o ./bin/bomly-plugin-clearlydefined-matcher .
bomly plugin install ./bin/bomly-plugin-clearlydefined-matcher --dev
bomly plugin enable clearlydefined-license-matcher
```

For distribution, package a package-only `bomly-plugin.json` manifest with the binary:

```text
bomly-plugin.json
bin/
  bomly-plugin-clearlydefined-matcher
README.md
```

The manifest contains package and install fields only. Bomly probes the binary at install time, verifies `descriptor.name == manifest.id`, and writes its own internal descriptor snapshot for plugin list, selectors, verification, and runtime registration.

## Test It

Check installation and runtime readiness:

```bash
bomly plugin verify clearlydefined-license-matcher
bomly plugin test clearlydefined-license-matcher
bomly plugin doctor clearlydefined-license-matcher
```

Run only this matcher during enrichment:

```bash
bomly scan --path ./my-project --enrich --matchers clearlydefined-license-matcher --json
```

Or add it to the default matcher set:

```bash
bomly scan --path ./my-project --enrich --matchers +clearlydefined-license-matcher
```

## Implementation Checklist

- Enrich `req.Registry`; do not replace graph identity.
- Return `MatcherStats` with the matcher ID and useful counts.
- Keep external network calls behind explicit enrichment.
- Honor proxy settings through the SDK HTTP provider.
- Wrap errors with useful context and avoid panics.
- Do not log secrets, tokens, or credentials.
- Add unit tests for mapping service responses into registry package data.
