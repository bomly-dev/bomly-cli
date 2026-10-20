# How to implement an auditor plugin

An auditor plugin checks the dependency graph and package data after detection and optional enrichment, and reports findings. Write one when you want findings, risk scores, or policy decisions from data Bomly already has.

[Plugin authoring](authoring.md) covers the module model, repository layout, configuration, testing, packaging, and protocol rules shared by every role. This guide covers only what is specific to auditors. The SDK reference for the types used below is the [`plugin`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/plugin) and [`model`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/model) packages.

## Start from the template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository. It ships a working matcher. To turn it into an auditor, change the module kind, the descriptor, and the role method; the layout, manifest, tests, and release workflow stay the same, with `"kind": "auditor"` in `bomly-plugin.json`.

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
const Name = "com.example.policy-auditor"

// Config is the auditor's typed configuration block.
type Config struct {
    DeniedPackages []string `json:"deniedPackages" doc:"Package names that always fail policy"`
}

// Auditor evaluates scan data and emits findings. sdkplugin.BaseAuditor supplies
// default Ready/Applicable implementations (always ready, always applicable).
type Auditor struct {
    sdkplugin.BaseAuditor
    config Config
}

func descriptor() sdkplugin.AuditorDescriptor {
    return sdkplugin.AuditorDescriptor{
        Name:         Name,
        DisplayName:  "Example Policy Auditor",
        Aliases:      []string{"example-policy"},
        Tags:         []string{"policy"},
        ConfigSchema: sdkplugin.MustConfigSchemaFor(Config{}),
    }
}

func (a *Auditor) Descriptor() sdkplugin.AuditorDescriptor { return descriptor() }

// Audit reads the graph and registry and returns findings and run metadata.
func (a *Auditor) Audit(ctx context.Context, req sdkplugin.AuditRequest) (sdkplugin.AuditResult, error) {
    finding := model.Finding{
        ID:           "example-policy:pkg:npm/lodash@4.17.21",
        RuleID:       "example-policy/denied-package",
        Kind:         model.FindingKindPackage,
        PackageRef:   "pkg:npm/lodash@4.17.21",
        PolicyStatus: model.FindingPolicyStatusWarn,
        Title:        "Package is on the internal deny list",
        Source:       Name,
    }
    return sdkplugin.AuditResult{
        Findings:        []model.Finding{finding},
        AuditorRuns:     []string{Name},
        AuditorFindings: map[string]int{Name: 1},
    }, nil
}

// Module packages the auditor for both execution modes.
func Module() sdkplugin.Module {
    return sdkplugin.Module{
        Kind: sdkplugin.PluginKindAuditor,
        Auditor: &sdkplugin.AuditorModule{
            Descriptor: descriptor(),
            New: func(_ context.Context, host sdkplugin.HostContext) (sdkplugin.Auditor, error) {
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
func main() { runtime.ServeModule(plugin.Module()) }
```

## What each part does

- `Descriptor` is the auditor's static registration: name (must equal the manifest `id`), display name, aliases, tags, support, and config schema.
- `New` constructs the auditor once per execution, with a `plugin.HostContext` for the logger, HTTP client, runtime info, and configuration.
- `Ready(ctx, req) error` reports whether the auditor can run right now — return `nil` when ready, or an error explaining the reason (for example, a missing policy file). `plugin.BaseAuditor` embeds an always-ready default.
- `Applicable(ctx, req) (bool, error)` reports whether the auditor should run for this request.
- `Audit` does the work: evaluate the data and return findings, risk scores, and run metadata.

Auditors run during `--audit`, which evaluates existing data. Do not make network calls from an auditor unless the plugin explicitly documents that behavior. Honor the context in long evaluations.

## Read graph and registry data

Bomly gives auditors the same core scan data used by built-in auditors:

- `req.Graph` contains dependency nodes and edges.
- `req.Registry` contains package records keyed by PURL.
- `req.BaselineGraph` may be present for diff-style workflows.
- `req.Target` may be present when a command focuses on one dependency.
- `req.DependencyDetailChanges` contains the canonical head-side dependency detail transitions during a diff audit. It is empty for scans, explains, and the base side of a diff. This optional protocol-v1 field may be absent when an older core calls the plugin.

## The findings contract

Auditors emit **reference-style** findings that point at registry packages by PURL — they never copy full package or vulnerability records:

```go
finding := model.Finding{
    ID:              "GHSA-example@pkg:npm/lodash@4.17.21",
    RuleID:          "example-policy/known-vulnerability",
    Kind:            model.FindingKindVulnerability,
    PackageRef:      "pkg:npm/lodash@4.17.21",
    VulnerabilityID: "GHSA-example",
    PolicyStatus:    model.FindingPolicyStatusFail,
    Source:          Name,
}
```

- `Kind` categorizes the concern: `model.FindingKindVulnerability`, `model.FindingKindLicense`, `model.FindingKindPackage` — plugins may introduce new kinds, and consumers treat the list as open.
- `PackageRef` is the offending package's PURL; `VulnerabilityID` names the advisory inside that package for vulnerability findings.
- `RuleID` is the stable rule that produced the finding. Unlike `ID`, it must not contain package versions or project-specific occurrence data — baselines and suppressions key off it.
- `PolicyStatus` drives evaluation: `model.FindingPolicyStatusFail` fails the policy gate, `model.FindingPolicyStatusWarn` is a visible warning, and `model.FindingPolicyStatusSuppressed` keeps a finding visible while excluding it from failure evaluation. Bomly's baseline and policy machinery may later resolve statuses on top of what the auditor emitted.
- Use clear, actionable titles and `Reasons`.

Auditors may also return `RiskScores` — normalized per-package scores referenced by PURL — and should always fill `AuditorRuns` and `AuditorFindings` so run metadata shows up in scan output.

## Configuration

Declare a typed `Config` struct, advertise it with `ConfigSchema`, and decode it in `New` as described in [Plugin authoring](authoring.md#configuration). Users set the block under `plugins.auditors.<name>`:

```yaml
plugins:
  auditors:
    com.example.policy-auditor:
      deniedPackages:
        - totally-not-suspicious
```

## Test it

Unit-test policy evaluation and finding construction, then run the conformance suite and the local loop described in [Plugin authoring](authoring.md#test-a-plugin). `--auditors +<name>` adds the auditor to the default set; `--auditors <name>` runs only it:

```bash
bomly scan --path ./my-project --audit --auditors +com.example.policy-auditor --json
```

## Checklist

In addition to the [checklist for every plugin](authoring.md#checklist-for-every-plugin):

- Read `req.Graph` and `req.Registry`; emit reference-style findings, never inline package or vulnerability payloads.
- Give every finding a stable `RuleID` free of versions and occurrence data.
- Use actionable titles and clear policy statuses.
- Return `AuditorRuns` and `AuditorFindings` with the auditor name.
