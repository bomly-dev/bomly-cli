# Managed Plugins

Bomly supports managed external plugins for detectors, matchers, and auditors.

This document covers the current workflow for building, installing, verifying, and running them.

## What Managed Plugins Are

Managed plugins are Go binaries that use the Bomly plugin SDK and run in a separate process through HashiCorp `go-plugin`.

The SDK contract is also the source of truth for built-in detectors, matchers, and auditors. Built-ins run in-process and skip installation, enable/disable state, and verification, but they use the same metadata and execution contract as external plugins.

Bomly owns:

- installation
- manifest validation
- checksum enforcement for direct URL installs
- plugin store layout
- enable and disable state
- runtime loading during scan preparation

Plugins do not get install hooks, post-install scripts, or automatic execution from repository checkouts.

## Runtime Policy

Installed external plugins are disabled by default. They do not participate in scans until you enable them with `bomly plugin enable <id>`.

Enabled plugins are loaded during runtime preparation in local and CI workflows. Treat `bomly plugin enable` as the trust decision for running that external binary.

## Configuration And Proxy Support

Bomly passes the active plugin API version, the explicit `BOMLY_CONFIG` path when one was provided, proxy settings, and the enabled plugin's own config to managed plugin subprocesses.

Proxy settings can be configured with a direct proxy URL:

```yaml
http_proxy: http://proxy.example:8080
http_no_proxy: localhost,127.0.0.1,.corp.example
```

For environments that manage proxy details separately, Bomly also accepts decomposed proxy settings:

```yaml
http_proxy_type: http # http, https, or socks5
http_proxy_host: proxy.example
http_proxy_port: 8080
http_proxy_username: my-user
http_proxy_password: my-password
http_no_proxy: localhost,127.0.0.1,.corp.example
http_ca_cert_file: /path/to/proxy-ca-chain.pem
```

Equivalent environment variables are `BOMLY_HTTP_PROXY`, `BOMLY_HTTP_NO_PROXY`, `BOMLY_HTTP_PROXY_TYPE`, `BOMLY_HTTP_PROXY_HOST`, `BOMLY_HTTP_PROXY_PORT`, `BOMLY_HTTP_PROXY_USERNAME`, `BOMLY_HTTP_PROXY_PASSWORD`, and `BOMLY_HTTP_CA_CERT_FILE`. When Bomly proxy fields are not set, Bomly's SDK HTTP client still honors standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables. For compatibility with non-SDK plugin code, Bomly also forwards the effective proxy values to plugin subprocesses using the standard proxy environment variable names.

Per-plugin configuration lives under `plugins.<plugin-id>`:

```yaml
plugins:
  acme.matcher:
    api_base: https://api.example.com
```

External plugins can read only their own config through the SDK:

```go
type config struct {
    APIBase string `json:"api_base"`
}

var cfg config
if err := sdk.DecodePluginConfigFromEnv(&cfg); err != nil {
    return err
}
```

Plugins that make outbound HTTP calls should create one process-local provider with `sdk.NewHTTPClientProviderFromEnv()` and reuse it for timeout-specific clients. This keeps proxy settings consistent while preserving Go's HTTP connection pooling:

```go
provider, err := sdk.NewHTTPClientProviderFromEnv()
if err != nil {
    return err
}
client := provider.Client(20 * time.Second)
```

## Plugin Layout

External plugin packages include a `bomly-plugin.json` manifest and a platform entrypoint binary.

Typical layout:

```text
bomly-plugin.json
bin/
  bomly-plugin-example
README.md
LICENSE
```

Installed plugins are stored under:

```text
~/.bomly/plugins/
  installed.json
  store/
    <plugin-id>/
      <version>/
```

## Discovery Patterns

Detector plugin manifests declare package-manager support inside `detectorDescriptor.packageManagerSupport`. Each support entry names a package manager and can include evidence patterns such as `go.mod`; Bomly derives ecosystem and manager planning data from those entries.

Bomly uses those patterns during runtime preparation:

- matching files can create or augment the normal package-manager subproject plan
- pattern-driven support can still plan a standalone detector subproject when it does not map to a built-in package-manager pattern

That keeps external detectors inside the same scan-planning flow as built-ins instead of dispatching them ad hoc from CLI commands.

## Getting Started

The repo includes a working example detector plugin at:

[`examples/plugins/go-module-detector`](../examples/plugins/go-module-detector)

Build it from the repository root:

```bash
go build -o ./bin/bomly-example-gomod-detector ./examples/plugins/go-module-detector
```

On Windows, the built file is `./bin/bomly-example-gomod-detector.exe`. `bomly plugin install --dev` accepts either the extensionless path or the explicit `.exe` path.

Install it in development mode:

```bash
bomly plugin install ./bin/bomly-example-gomod-detector --dev
bomly plugin enable bomly.example.gomod-detector
```

List installed plugins:

```bash
bomly plugin list --external --json
```

Verify the installation:

```bash
bomly plugin verify bomly.example.gomod-detector
```

Test runtime readiness (without running verify):

```bash
bomly plugin test bomly.example.gomod-detector
```

Run a full health check (verify + test):

```bash
bomly plugin doctor bomly.example.gomod-detector
```

Run a scan with the plugin selected explicitly:

```bash
bomly scan \
  --path ./my-go-project \
  --detectors bomly.example.gomod-detector \
  --format json
```

Disable or uninstall it later:

```bash
bomly plugin disable bomly.example.gomod-detector
bomly plugin uninstall bomly.example.gomod-detector
```

## Authoring Model

Plugin authors import:

```text
github.com/bomly-dev/bomly-cli/sdk
```

Minimal detector example:

```go
package main

import (
    "context"

    "github.com/bomly-dev/bomly-cli/sdk"
)

type Detector struct{}

func (d *Detector) Metadata(ctx context.Context) (*sdk.PluginMetadata, error) {
    return &sdk.PluginMetadata{
        ID:               "acme.detector.example",
        Name:             "Acme Example Detector",
        Version:          "1.0.0",
        Kind:             sdk.PluginKindDetector,
        PluginAPIVersion: sdk.PluginAPIVersion,
    }, nil
}

func (d *Detector) Descriptor(ctx context.Context) (*sdk.DetectorDescriptor, error) {
    return &sdk.DetectorDescriptor{
        Name:           "acme.detector.example",
        Enabled:        true,
        Origin:         sdk.ExternalOrigin,
        SupportedModes: []sdk.TargetMode{sdk.TargetModeFullGraph, sdk.TargetModeComponent},
        Capabilities:   []string{"dependency-detection"},
    }, nil
}

func (d *Detector) PackageManagerSupport(context.Context) ([]sdk.PackageManagerSupport, error) {
    return []sdk.PackageManagerSupport{sdk.Support(sdk.PackageManagerGoMod, "go.mod")}, nil
}

func (d *Detector) Ready(context.Context, *sdk.DetectRequest) (*sdk.ReadyResponse, error) {
    return &sdk.ReadyResponse{Ready: true}, nil
}

func (d *Detector) Applicable(context.Context, *sdk.DetectRequest) (*sdk.ApplicableResponse, error) {
    return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (d *Detector) Detect(ctx context.Context, req *sdk.DetectRequest) (*sdk.DetectResponse, error) {
    return &sdk.DetectResponse{}, nil
}

func main() {
    sdk.ServeDetector(&Detector{})
}
```

Required SDK hooks:

- detectors must implement `Descriptor`, `PackageManagerSupport`, `Ready`, `Applicable`, and `Detect`
- matchers must implement `Descriptor`, `Ready`, `Applicable`, and `Match`
- auditors must implement `Descriptor`, `Ready`, `Applicable`, and `Audit`

Detector plugins may additionally implement `Install` when they support install-first execution.

## Supported Install Sources

Current supported sources are:

- local archive
- local binary with `--dev`
- direct URL with checksum
- GitHub Release via `github:owner/repo@tag`

Examples:

```bash
bomly plugin install ./dist/bomly-plugin-example.tar.gz
bomly plugin install ./bin/bomly-example-gomod-detector --dev
bomly plugin install https://example.com/bomly-plugin-example.tar.gz --checksum sha256:...
bomly plugin install github:acme/bomly-plugin-example@v1.2.0
```

For GitHub Release installs, Bomly resolves the release metadata, selects the asset matching the current OS and architecture, and uses a `SHA256SUMS` asset when present to verify the archive automatically.

## Security Model

Bomly validates plugin manifests before execution and rejects unsafe archive paths.

Important constraints:

- direct URL installs require `--checksum` unless you explicitly bypass it
- runtime metadata must match manifest identity, version, kind, and API version
- plugin metadata is treated as untrusted input
- enabled state is host-owned and stored in Bomly's installed plugin database
- plugin execution uses context cancellation
- repository-declared plugins are not executed automatically

Managed plugins are isolated by process boundary, but they are still external binaries. Treat install and execution as a trust decision.
