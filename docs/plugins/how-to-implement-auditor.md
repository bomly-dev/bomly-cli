# How To Implement An Auditor Plugin

An auditor plugin evaluates the dependency graph and package registry after detection and optional enrichment. Use an auditor when you want to produce findings, risk scores, or policy-style decisions from data Bomly already has.

External auditor plugins are served with `sdk.ServeAuditor`.

## Minimum Shape

Create a Go `main` package that imports the Bomly SDK:

```go
package main

import (
    "context"

    "github.com/bomly-dev/bomly-cli/sdk"
)

const pluginID = "acme.auditor.example"

type auditor struct{}

func (a *auditor) Metadata(context.Context) (*sdk.PluginMetadata, error) {
    return &sdk.PluginMetadata{
        ID:               pluginID,
        Name:             "Acme Example Auditor",
        Version:          "0.1.0",
        Kind:             sdk.PluginKindAuditor,
        PluginAPIVersion: sdk.PluginAPIVersion,
    }, nil
}

func (a *auditor) Descriptor(context.Context) (*sdk.AuditorDescriptor, error) {
    return &sdk.AuditorDescriptor{
        Name:    pluginID,
        Enabled: true,
        Origin:  sdk.ExternalOrigin,
    }, nil
}

func (a *auditor) Ready(context.Context, *sdk.AuditRequest) (*sdk.ReadyResponse, error) {
    return &sdk.ReadyResponse{Ready: true}, nil
}

func (a *auditor) Applicable(context.Context, *sdk.AuditRequest) (*sdk.ApplicableResponse, error) {
    return &sdk.ApplicableResponse{Applicable: true}, nil
}

func (a *auditor) Audit(ctx context.Context, req *sdk.AuditRequest) (*sdk.AuditResponse, error) {
    finding := sdk.Finding{
        ID:          "acme-policy-example",
        Kind:        sdk.FindingKindPackage,
        PackageRef:  "pkg:npm/lodash@4.17.21",
        Disposition: sdk.FindingDispositionFail,
        Title:       "Example policy finding",
        Source:      pluginID,
    }

    return &sdk.AuditResponse{
        Findings:        []sdk.Finding{finding},
        AuditorRuns:     []string{pluginID},
        AuditorFindings: map[string]int{pluginID: 1},
    }, nil
}

func main() {
    sdk.ServeAuditor(&auditor{})
}
```

## What Each Hook Does

- `Metadata` returns the plugin identity. The ID, version, kind, and API version must match the installed manifest.
- `Descriptor` describes the auditor registration. Use `sdk.ExternalOrigin` for external plugins.
- `Ready` reports whether the plugin can run in the current environment.
- `Applicable` reports whether the auditor should run for the current request.
- `Audit` reads `sdk.AuditRequest` and returns findings, risk scores, and run metadata.

## Read Graph And Registry Data

Bomly gives auditors the same core scan data used by built-in auditors:

- `req.Graph` contains dependency nodes and edges.
- `req.Registry` contains package records keyed by PURL.
- `req.BaselineGraph` may be present for diff-style workflows.
- `req.Target` may be present when a command focuses on one dependency.

Auditors should emit reference-style findings that point at registry packages by PURL:

```go
finding := sdk.Finding{
    ID:              "GHSA-example",
    Kind:            sdk.FindingKindVulnerability,
    PackageRef:      "pkg:npm/lodash@4.17.21",
    VulnerabilityID: "GHSA-example",
    Disposition:     sdk.FindingDispositionFail,
    Source:          pluginID,
}
```

Do not copy full package or vulnerability records into findings. Keep the finding focused on the decision and references.

## Configuration And HTTP

Per-plugin config lives under `plugins.<plugin-id>`:

```yaml
plugins:
  acme.auditor.example:
    policy_file: ./bomly-policy.yaml
```

Read it with:

```go
type config struct {
    PolicyFile string `json:"policy_file"`
}

var cfg config
if err := sdk.DecodePluginConfigFromEnv(&cfg); err != nil {
    return nil, err
}
```

Auditors should normally evaluate data already present in `req.Graph` and `req.Registry`. If an auditor intentionally calls an external service, document that behavior and use Bomly's SDK HTTP provider so proxy settings work consistently:

```go
provider, err := sdk.NewHTTPClientProviderFromEnv()
if err != nil {
    return nil, err
}
client := provider.Client(20 * time.Second)
_ = client
```

## Package And Install

For development, build and install the binary directly:

```bash
go build -o ./bin/acme-auditor ./cmd/acme-auditor
bomly plugin install ./bin/acme-auditor --dev
bomly plugin enable acme.auditor.example
```

For distribution, package a `bomly-plugin.json` manifest with the binary:

```text
bomly-plugin.json
bin/
  acme-auditor
README.md
LICENSE
```

## Test It

Check installation and runtime readiness:

```bash
bomly plugin verify acme.auditor.example
bomly plugin test acme.auditor.example
bomly plugin doctor acme.auditor.example
```

Run only this auditor:

```bash
bomly scan --path ./my-project --audit --auditors acme.auditor.example --json
```

Or add it to the default auditor set:

```bash
bomly scan --path ./my-project --audit --auditors +acme.auditor.example
```

## Implementation Checklist

- Return stable `PluginMetadata` and keep it in sync with the manifest.
- Read `req.Graph` and `req.Registry`; emit reference-style findings.
- Return `AuditorRuns` with the auditor ID.
- Use actionable finding summaries and dispositions.
- Avoid external network calls unless the plugin explicitly documents them.
- Wrap errors with useful context and avoid panics.
- Do not log secrets, tokens, or credentials.
- Add unit tests for policy evaluation and finding construction.
