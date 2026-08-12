# How To Implement An Auditor Plugin

An auditor plugin evaluates the dependency graph and package registry after detection and optional enrichment. Use an auditor when you want to produce findings, risk scores, or policy-style decisions from data Bomly already has.

An auditor is one `sdk.Module` with `Kind: sdk.PluginKindAuditor`. The same module can be compiled into a host build (embedded) or served as a managed plugin binary with `sdk.ServeModule` — you write the component once. [Plugin basics](../PLUGINS.md#write-a-plugin) covers the module model, repository contract, configuration, testing, and release flow shared by every role; this guide covers what is specific to auditors.

The [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk) documents `sdk.Module`, `sdk.AuditorModule`, the `sdk.Auditor` interface, `sdk.AuditRequest`, `sdk.AuditResult`, reference-style findings, and the risk-score types used below.

## Start From The Template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository ("Use this template" on GitHub). It ships a working matcher; turning it into an auditor means changing the module kind, the descriptor, and the role method — the layout, manifest, tests, and release workflow stay the same:

```text
plugin/                  importable package: descriptor, Config, Auditor, Module()
cmd/<binary-name>/
  main.go                one line: sdk.ServeModule(plugin.Module())
bomly-plugin.json        package manifest ("kind": "auditor")
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

    sdk "github.com/bomly-dev/bomly-sdk"
)

// Name must equal the "id" field in bomly-plugin.json.
const Name = "com.example.policy-auditor"

// Config is the auditor's typed configuration block.
type Config struct {
    DeniedPackages []string `json:"deniedPackages" doc:"Package names that always fail policy"`
}

// Auditor evaluates scan data and emits findings. sdk.BaseAuditor supplies
// default Ready/Applicable implementations (always ready, always applicable).
type Auditor struct {
    sdk.BaseAuditor
    config Config
}

func descriptor() sdk.AuditorDescriptor {
    return sdk.AuditorDescriptor{
        Name:         Name,
        DisplayName:  "Example Policy Auditor",
        Aliases:      []string{"example-policy"},
        Tags:         []string{"policy"},
        ConfigSchema: sdk.MustConfigSchemaFor(Config{}),
    }
}

func (a *Auditor) Descriptor() sdk.AuditorDescriptor { return descriptor() }

// Audit reads the graph and registry and returns findings and run metadata.
func (a *Auditor) Audit(ctx context.Context, req sdk.AuditRequest) (sdk.AuditResult, error) {
    finding := sdk.Finding{
        ID:           "example-policy:pkg:npm/lodash@4.17.21",
        RuleID:       "example-policy/denied-package",
        Kind:         sdk.FindingKindPackage,
        PackageRef:   "pkg:npm/lodash@4.17.21",
        PolicyStatus: sdk.FindingPolicyStatusWarn,
        Title:        "Package is on the internal deny list",
        Source:       Name,
    }
    return sdk.AuditResult{
        Findings:        []sdk.Finding{finding},
        AuditorRuns:     []string{Name},
        AuditorFindings: map[string]int{Name: 1},
    }, nil
}

// Module packages the auditor for both execution modes.
func Module() sdk.Module {
    return sdk.Module{
        Kind: sdk.PluginKindAuditor,
        Auditor: &sdk.AuditorModule{
            Descriptor: descriptor(),
            New: func(_ context.Context, host sdk.HostContext) (sdk.Auditor, error) {
                auditor := &Auditor{}
                if err := host.DecodeConfig(&auditor.config); err != nil {
                    return nil, fmt.Errorf("decode %s config: %w", Name, err)
                }
                return auditor, nil
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

- `Descriptor` is the auditor's static registration: name (must equal the manifest `id`), display name, aliases, tags, support, and config schema.
- `New` constructs the auditor once per execution, with a `sdk.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the auditor can run right now — return `nil` when ready, or an error explaining the reason (for example, a missing policy file). `sdk.BaseAuditor` embeds an always-ready default.
- `Applicable(ctx, req) (bool, error)` reports whether the auditor should run for this request.
- `Audit` does the work: evaluate the data and return findings, risk scores, and run metadata.

Auditors run during `--audit`, which evaluates existing data. Do not make network calls from an auditor unless the plugin explicitly documents that behavior. Honor the context in long evaluations.

## Read Graph And Registry Data

Bomly gives auditors the same core scan data used by built-in auditors:

- `req.Graph` contains dependency nodes and edges.
- `req.Registry` contains package records keyed by PURL.
- `req.BaselineGraph` may be present for diff-style workflows.
- `req.Target` may be present when a command focuses on one dependency.
- `req.DependencyDetailChanges` contains the canonical head-side dependency detail transitions during a diff audit. It is empty for scans, explains, and the base side of a diff. This optional protocol-v1 field may be absent when an older core calls the plugin.

## The Findings Contract

Auditors emit **reference-style** findings that point at registry packages by PURL — they never copy full package or vulnerability records:

```go
finding := sdk.Finding{
    ID:              "GHSA-example@pkg:npm/lodash@4.17.21",
    RuleID:          "example-policy/known-vulnerability",
    Kind:            sdk.FindingKindVulnerability,
    PackageRef:      "pkg:npm/lodash@4.17.21",
    VulnerabilityID: "GHSA-example",
    PolicyStatus:    sdk.FindingPolicyStatusFail,
    Source:          Name,
}
```

- `Kind` categorizes the concern: `sdk.FindingKindVulnerability`, `sdk.FindingKindLicense`, `sdk.FindingKindPackage` — plugins may introduce new kinds, and consumers treat the list as open.
- `PackageRef` is the offending package's PURL; `VulnerabilityID` names the advisory inside that package for vulnerability findings.
- `RuleID` is the stable rule that produced the finding. Unlike `ID`, it must not contain package versions or project-specific occurrence data — baselines and suppressions key off it.
- `PolicyStatus` drives evaluation: `sdk.FindingPolicyStatusFail` fails the policy gate, `sdk.FindingPolicyStatusWarn` is a visible warning, and `sdk.FindingPolicyStatusSuppressed` keeps a finding visible while excluding it from failure evaluation. Bomly's baseline and policy machinery may later resolve statuses on top of what the auditor emitted.
- Use clear, actionable titles and `Reasons`.

Auditors may also return `RiskScores` — normalized per-package scores referenced by PURL — and should always fill `AuditorRuns` and `AuditorFindings` so run metadata shows up in scan output.

## Configuration

Declare a typed `Config` struct with `json`, `doc:`, and `default:` tags, advertise it with `ConfigSchema: sdk.MustConfigSchemaFor(Config{})`, and decode it in `New` with `host.DecodeConfig(&cfg)`. Users set the block under `plugins.auditors.<name>`:

```yaml
plugins:
  auditors:
    com.example.policy-auditor:
      deniedPackages:
        - totally-not-suspicious
```

The same block reaches the component in both execution modes. See [Configuration in the plugin guide](../PLUGINS.md#configuration-and-proxy-support) for details and the deprecated flat form.

## Test It

Unit-test policy evaluation and finding construction, and run the SDK conformance suite:

```go
func TestConformance(t *testing.T) {
    conformance.Test(t, conformance.Config{
        Module:       Module(),
        ManifestPath: filepath.Join("..", "bomly-plugin.json"),
        SampleConfig: json.RawMessage(`{"deniedPackages":["left-pad"]}`),
    })
}
```

Local development loop:

```bash
go build -o ./bin/bomly-plugin-policy ./cmd/bomly-plugin-policy
bomly plugins install ./bin/bomly-plugin-policy --dev
bomly plugins enable com.example.policy-auditor
bomly scan --path ./my-project --audit --auditors +com.example.policy-auditor --json
bomly plugins verify com.example.policy-auditor
bomly plugins test com.example.policy-auditor
bomly plugins doctor com.example.policy-auditor
```

`--auditors +<name>` adds the auditor to the default set; `--auditors <name>` runs only it. See [Testing a plugin](../PLUGINS.md#test-a-plugin) for the shared workflow, including `conformance.ProbeBinary`.

## Package And Release

Follow the template's release workflow: one archive per platform named `<name>_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) containing the binary, `bomly-plugin.json`, `README.md`, and `LICENSE`, plus a `SHA256SUMS` file. The manifest's `entrypoint` map names the binary per platform, and `descriptor.Name` must equal the manifest `id`. See [Package and release](../PLUGINS.md#package-and-release-a-plugin).

## Implementation Checklist

- Read `req.Graph` and `req.Registry`; emit reference-style findings — never inline package or vulnerability payloads.
- Give every finding a stable `RuleID` free of versions and occurrence data.
- Use actionable titles and clear policy statuses.
- Return `AuditorRuns` and `AuditorFindings` with the auditor name.
- Avoid external network calls unless the plugin explicitly documents them.
- Honor context cancellation in long evaluations.
- Wrap errors with useful context; avoid panics.
- Do not log secrets, tokens, or credentials.
- Add unit tests for policy evaluation and finding construction, plus `conformance.Test`.
