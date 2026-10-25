# Plugin authoring

This page covers what every plugin author needs regardless of role: the module model, the repository layout, configuration, testing, packaging, and the protocol rules. The four role guides ([detector](how-to-implement-detector.md), [matcher](how-to-implement-matcher.md), [auditor](how-to-implement-auditor.md), [analyzer](how-to-implement-analyzer.md)) cover only what differs per role. Installing and running plugins is on [Plugins](../PLUGINS.md).

## Start from the template

Start from the [bomly-plugin-template](https://github.com/bomly-dev/bomly-plugin-template) repository ("Use this template" on GitHub). It is a complete, working plugin with typed configuration, tests, the SDK conformance suite, CI, and a release workflow Bomly can install from. The example repositories show one finished plugin per role:

- [Bun lock detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector): a detector for a package manager Bomly does not model directly
- [ClearlyDefined license matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher): license enrichment
- [EOL lifecycle matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher): lifecycle metadata
- [Meme dependency auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor): an auditor that emits warning findings

The SDK API reference is split by package:

| Package | What it documents |
| --- | --- |
| [`plugin`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/plugin) | Component interfaces, descriptors, request and response payloads |
| [`model`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/model) | The graph, the package registry, and the finding contract |
| [`runtime`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/runtime) | The plugin entrypoints |
| [`httpkit`](https://pkg.go.dev/github.com/bomly-dev/bomly-sdk/httpkit) | Outbound HTTP, reached through `plugin.HostContext` |

## The module

A plugin is written once as a **module**: one component packaged so that it can run either compiled into a Bomly build or as a separate plugin process. The component code is the same in both cases.

```go
plugin.Module{
    Kind: plugin.PluginKindMatcher, // or Detector / Auditor / Analyzer
    Matcher: &plugin.MatcherModule{
        Descriptor: descriptor(), // static registration data
        New: func(ctx context.Context, host plugin.HostContext) (plugin.Matcher, error) {
            // construct the component; decode config from host
        },
    },
}
```

`plugin.HostContext` is the only way the component reaches host services, and both execution modes provide the same four:

| Method | What it gives you |
| --- | --- |
| `Logger()` | A zap logger wired to the host's verbosity. Never log secrets |
| `HTTPClient()` | An HTTP client provider that honors Bomly's proxy, no-proxy, and CA certificate settings |
| `Runtime()` | The host version and whether execution is embedded or managed |
| `DecodeConfig(v)` | Unmarshals the component's own `plugins.<kind>.<name>` block |

Every role embeds a default-lifecycle helper (`plugin.BaseDetector`, `plugin.BaseMatcher`, `plugin.BaseAuditor`, `plugin.BaseAnalyzer`) that answers "ready" and "applicable" by default. Override `Ready` to report a missing prerequisite with a clear reason. Override `Applicable` to skip requests the component should not handle. Honor the context everywhere.

## Plugin identity

A plugin's identity lives in three places:

| Place | Holds | Written by |
| --- | --- | --- |
| `bomly-plugin.json` (the manifest) | Package facts: ID, name, version, description, homepage, license, source, Bomly version constraint, runtime, plugin API version, entrypoint, and an optional `access` block | You |
| The descriptor the binary returns | Component facts: name, display name, aliases, tags, supported ecosystems and package managers, optional `requires` list, role-specific behavior | You, in code |
| Bomly's installed-plugin database | Checksum, enabled state, install path, and a snapshot of the descriptor | Bomly, at install time |

The descriptor's `requires` list names the inputs the component needs, such as `source-tree-v1`. Bomly checks it before the component runs. When every requirement is met, `Ready` and `Applicable` run as usual. When one is not, Bomly skips the component or stops the command, as [Component prerequisites](../PLUGINS.md#component-prerequisites) describes.

A Go descriptor declares the list with the SDK's constants:

```go
plugin.AnalyzerDescriptor{Name: "my-reach-analyzer", Requires: plugin.Requirements{plugin.RequirementSourceTree}}
```

The manifest's `access` block discloses the files, network destinations, environment variables, and commands the plugin uses. Bomly shows it to users before they enable the plugin and does not enforce it. Leave a list empty only when the plugin needs none of that access. An omitted list means the same as an empty one, and users see it as `none declared`. Without the block, users see the plugin's access as unknown. [Declared access](../PLUGINS.md#declared-access) describes how users see it.

The `access` block has five optional lists. Bomly sorts each list and removes duplicates when it reads the manifest:

| Key | Entries |
| --- | --- |
| `filesystemRead`, `filesystemWrite` | Areas, not paths: `project` (the scan target), `temp`, `cache`, `home`, or `any` |
| `network` | Host names (`api.osv.dev`), a host and its subdomains (`*.github.com`), or `*` |
| `environment` | Variable names (`GITHUB_TOKEN`), a prefix (`BOMLY_HTTP_*`), or `*` |
| `subprocesses` | Command names without a path (`go`, `npm`), or `*` |

This manifest fragment declares a matcher that reads the project and its cache, writes the cache, and calls one API:

```json
"access": {
  "filesystemRead": ["project", "cache"],
  "filesystemWrite": ["cache"],
  "network": ["api.osv.dev"]
}
```

The descriptor `name` must equal the manifest `id`. For a packaged plugin, Bomly reads `id`, `kind`, and `pluginApiVersion` from the manifest, starts the binary, fetches the matching descriptor, and checks the names agree. For a `--dev` install without a manifest, Bomly asks for every role's descriptor and accepts the binary only when exactly one role answers.

## Repository layout

Follow the template's shape:

```text
plugin/                  importable package exporting Module()
cmd/<binary-name>/
  main.go                one line: runtime.ServeModule(plugin.Module())
bomly-plugin.json        package manifest; "id" must equal the descriptor name
testdata/                fixtures for unit tests
.github/workflows/       CI plus a release workflow producing platform archives
go.mod                   pins a released github.com/bomly-dev/bomly-sdk version
```

Keep the component in an importable `plugin/` package, not `package main`. That is what makes the module reusable: the binary serves it, tests construct it directly, and a Bomly build can embed it.

`runtime.ServeModule` is the plugin entrypoint. It validates the module, builds the host context (a stderr logger, an HTTP client provider from Bomly's environment, config decoding from the file Bomly passes), constructs the component on first use, and speaks the plugin protocol. The per-role entrypoints `runtime.ServeDetector`, `ServeMatcher`, `ServeAuditor`, and `ServeAnalyzer` exist for plugins that need the low-level wire surface; most plugins never need them.

## Configuration

Declare a typed `Config` struct with `json`, `doc:`, and `default:` tags, advertise it with `ConfigSchema: plugin.MustConfigSchemaFor(Config{})`, and decode it in `New`:

```go
type Config struct {
    APIBase string `json:"apiBase" doc:"Service endpoint override" default:"https://api.example.com"`
}

New: func(_ context.Context, host plugin.HostContext) (plugin.Matcher, error) {
    matcher := &Matcher{}
    if err := host.DecodeConfig(&matcher.config); err != nil {
        return nil, fmt.Errorf("decode config: %w", err)
    }
    return matcher, nil
},
```

Users set the block under `plugins.<kind>.<name>`, and `bomly plugins info` renders the schema's keys, descriptions, and defaults. `DecodeConfig` behaves the same in both execution modes: embedded execution reads the block from the host config, and managed execution reads it from the config file Bomly passes to the process. Plugins written against the low-level served style read the same payload with `runtime.DecodePluginConfigFromEnv`.

Bomly passes the plugin API version, the `BOMLY_CONFIG` path when one was given, and the proxy settings to every plugin process. A plugin that makes HTTP calls should create one process-local provider and reuse it:

```go
provider, err := httpkit.NewClientProviderFromEnv()
if err != nil {
    return err
}
client := provider.Client(20 * time.Second)
```

The provider honors Bomly's `network.proxy` and `network.ca_cert_file` settings and, when those are unset, the standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` variables. Bomly also forwards the effective proxy values under those standard names for plugin code that does not use the SDK client.

## Registry deltas

Matchers and analyzers can answer in two shapes. The baseline is the **full registry**: the plugin returns every package, changed or not. A plugin that advertises the `package-updates-v1` capability may instead return **deltas**, only the packages it changed, when the request's `AcceptPackageUpdates` field says the host understands them. Bomly merges deltas into its registry by package URL (PURL). Always fall back to the full-registry shape when the host does not opt in; that keeps old hosts and new plugins compatible in both directions. The matcher and analyzer guides show the code.

## Test a plugin

Unit-test the component logic by constructing it through the role module's constructor, `Module().Matcher.New(ctx, host)` for a matcher (`Detector`, `Auditor`, or `Analyzer` for the other roles), with a small `HostContext` stub (the template's `plugin/plugin_test.go` has one). Then run the SDK conformance suite:

```go
func TestConformance(t *testing.T) {
    conformance.Test(t, conformance.Config{
        Module:       plugin.Module(),
        ManifestPath: "../bomly-plugin.json",
        SampleConfig: json.RawMessage(`{"greeting":"hi"}`),
    })
}
```

The suite checks module and descriptor validity, JSON round-trip stability, construction through a `HostContext`, the Ready and Applicable contract (including prompt return on a cancelled context), role capabilities such as the delta protocol, and, when `ManifestPath` is set, that the manifest and descriptor agree. To probe a built binary over the real plugin transport, add `conformance.ProbeBinary(t, "bin/<name>", conformance.WithModule(plugin.Module()))`.

Then run it against Bomly:

```bash
go build -o ./bin/<binary-name> ./cmd/<binary-name>
bomly plugins install ./bin/<binary-name> --dev
bomly plugins enable <plugin-id>
bomly scan ...                     # with the role's selector flag
bomly plugins doctor <plugin-id>   # verify (manifest, checksum, binary, descriptor) + test (readiness)
```

## Package and release

A plugin package holds the manifest and one binary per platform:

```text
bomly-plugin.json
bin/
  bomly-plugin-example
README.md
```

The manifest's `entrypoint` field maps each `os/arch` to its binary name (Windows entries end in `.exe`). Keep the manifest `version` equal to the release tag.

The template's release workflow does the rest:

1. Build each platform.
2. Package one archive per platform named `<name>_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) holding the binary, `bomly-plugin.json`, `README.md`, and `LICENSE`.
3. Write a `SHA256SUMS` file over the archives.
4. Publish everything as a GitHub release.

Users then install with `bomly plugins install github:<owner>/<repo>@v<version>`, and Bomly verifies the archive against `SHA256SUMS`.

## Protocol evolution

Compatibility has two independent parts. The Go API your plugin compiles against follows the SDK module's semantic version, and only matters when you rebuild. The wire protocol between a built plugin and a Bomly binary is versioned separately (`bomly.plugin.v1`) and is what keeps a shipped plugin working as users upgrade Bomly.

Within protocol v1, changes are additive only:

- New request and response fields are optional JSON fields. Receivers ignore unknown fields, so old plugins and old hosts are unaffected.
- New calls are optional. A peer that does not implement one answers `Unimplemented`, and the caller falls back to the previous behavior.
- Existing fields and calls are never removed, renamed, or given a new meaning.
- Features that need both sides are negotiated through **capabilities**: the plugin advertises the feature in its descriptor (for example `package-updates-v1`) and the host signals acceptance per request. Neither side may assume a capability that was not advertised.

A change that cannot be made additively is a breaking change. It would ship as a new protocol major version negotiated alongside v1, and existing v1 plugins would keep running.

## Checklist for every plugin

- The descriptor name equals the manifest `id`.
- `Ready` reports missing prerequisites with a clear reason instead of failing the scan.
- Every operation honors context cancellation.
- Errors are wrapped with context; nothing panics.
- No secrets, tokens, or credentials are logged.
- The conformance suite passes and the release workflow publishes `SHA256SUMS`.
