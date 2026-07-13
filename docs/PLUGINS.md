# Managed Plugins

Bomly plugins let you extend scans without changing the Bomly binary. Today, managed external plugins can add:

- **detectors** that turn project files into dependency graphs
- **matchers** that enrich packages with vulnerabilities, licenses, lifecycle data, or other package metadata
- **auditors** that turn graph and registry data into findings or risk scores

External analyzer plugins are not supported yet. `bomly plugins list --analyzers` can show built-in reachability analyzers, but the external plugin runtime currently serves only detectors, matchers, and auditors through `sdk.ServeDetector`, `sdk.ServeMatcher`, and `sdk.ServeAuditor`.

## Start Here

Use this page when you want to install, trust, configure, package, or troubleshoot a managed plugin.

Use the implementation guides when you are writing one:

- [How To Implement A Detector Plugin](plugins/how-to-implement-detector.md)
- [How To Implement A Matcher Plugin](plugins/how-to-implement-matcher.md)
- [How To Implement An Auditor Plugin](plugins/how-to-implement-auditor.md)

Use the [Bomly SDK API reference](https://pkg.go.dev/github.com/bomly-dev/bomly-cli/sdk) for the Go types, runtime entrypoints, request/response payloads, graph model, package registry, and finding contract those guides use.

Example plugin repositories live outside this repo so each plugin type can show a realistic package, release, and README:

- [Bun Lock Detector](https://github.com/bomly-dev/bomly-plugin-bun-lock-detector) — detector example using `PackageManagerOther`
- [ClearlyDefined License Matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher) — matcher example for license enrichment
- [EOL Lifecycle Matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher) — matcher example for lifecycle metadata
- [Meme Dependency Auditor](https://github.com/bomly-dev/bomly-plugin-meme-auditor) — auditor example that emits warning findings

## How Plugins Run

Managed plugins are Go binaries that use Bomly's public `sdk` package. Bomly starts each enabled external plugin as a separate native OS subprocess through HashiCorp `go-plugin` in gRPC mode.

Plugin identity is split into three clear places:

- **Manifest = package.** `bomly-plugin.json` records install and package fields: ID, name, version, description, homepage, license, source, Bomly version constraint, runtime, plugin API version, and entrypoint.
- **Descriptor = component.** The plugin binary returns one role descriptor: detector, matcher, or auditor. The descriptor owns the component name, display name, aliases, tags, supported ecosystems, supported package managers, and role-specific behavior.
- **Installed DB = trust and state.** Bomly records checksum, enabled/disabled state, install path, and an internal descriptor snapshot when a plugin is installed. Plugin authors do not write that snapshot.

There is no `Metadata()` hook. For packaged plugins, Bomly reads `id`, `kind`, and `pluginApiVersion` from `bomly-plugin.json`, launches the binary, fetches the matching descriptor, and requires `descriptor.name == manifest.id`. For dev-binary installs without a manifest, Bomly probes detector, matcher, and auditor descriptors and accepts the binary only when exactly one role responds.

Bomly owns:

- installing plugin packages
- validating `bomly-plugin.json`
- checking recorded checksums
- storing plugins under `~/.bomly/plugins`
- enabling and disabling plugins
- loading enabled plugins during scan runtime preparation

Plugins do not get install hooks, post-install scripts, or automatic execution from repository checkouts.

## Trust And Enablement

Installed external plugins are disabled by default. They do not participate in scans until you enable them:

```bash
bomly plugins enable <plugin-id>
```

Treat `bomly plugins enable` as the trust decision. When enabled, a plugin runs with the same user-level privileges as the Bomly process. It can read and write files, make network connections, spawn child processes, and access environment variables available to that user.

Repository-declared plugins are never executed automatically. The host must explicitly install and enable the plugin before it can run.

## Try The Example Plugins

Each example repo has a `bomly-plugin.json`, a small Go implementation, tests, and packaging notes.

```bash
git clone git@github.com:bomly-dev/bomly-plugin-bun-lock-detector.git
cd bomly-plugin-bun-lock-detector
go test ./...
go build -o ./bin/bomly-plugin-bun-lock-detector .
bomly plugins install ./bin/bomly-plugin-bun-lock-detector --dev
bomly plugins enable bomly.examples.detector.bun-lock
bomly scan --path ./my-bun-project --detectors bomly.examples.detector.bun-lock
```

The matcher and auditor examples use the same workflow:

```bash
bomly plugins enable clearlydefined-license-matcher
bomly scan --enrich --matchers +clearlydefined-license-matcher

bomly plugins enable bomly.examples.auditor.meme-deps
bomly scan --audit --auditors +bomly.examples.auditor.meme-deps
```

Check that Bomly can see any installed plugin:

```bash
bomly plugins list --external
bomly plugins info <plugin-id>
bomly plugins verify <plugin-id>
bomly plugins test <plugin-id>
bomly plugins doctor <plugin-id>
```

Disable or uninstall it later:

```bash
bomly plugins disable <plugin-id>
bomly plugins uninstall <plugin-id>
```

## Common Commands

List plugins:

```bash
bomly plugins list
bomly plugins list --external
bomly plugins list --detectors
bomly plugins list --matchers --json
bomly plugins list --auditors
```

Show one plugin:

```bash
bomly plugins info <plugin-id>
bomly plugins info <plugin-id> --json
```

Install a plugin:

```bash
bomly plugins install ./dist/bomly-plugin-example.tar.gz
bomly plugins install ./bin/bomly-plugin-example --dev
bomly plugins install https://example.com/bomly-plugin-example.tar.gz --checksum sha256:...
bomly plugins install https://example.com/bomly-plugin-example.tar.gz --insecure-skip-checksum
bomly plugins install github:bomly-dev/bomly-plugin-bun-lock-detector@v0.1.0
```

Check a plugin:

```bash
bomly plugins verify <plugin-id> # manifest, checksum, binary, runtime descriptor
bomly plugins test <plugin-id>   # runtime readiness
bomly plugins doctor <plugin-id> # verify + test
```

Enable, disable, or remove a plugin:

```bash
bomly plugins enable <plugin-id>
bomly plugins disable <plugin-id>
bomly plugins uninstall <plugin-id>
```

## Select Plugins During A Scan

Plugin selectors use the same `+/-` grammar as built-in components:

```bash
# Use only this detector.
bomly scan --detectors bomly.examples.detector.bun-lock

# Add an external matcher to the default matcher set.
bomly scan --enrich --matchers +clearlydefined-license-matcher

# Use one auditor explicitly.
bomly scan --audit --auditors bomly.examples.auditor.meme-deps
```

Detector plugins can participate in subproject discovery. Their runtime descriptor and `PackageManagerSupport` response record package-manager support and evidence patterns such as `go.mod`. Bomly stores that verified descriptor snapshot during install so external detectors can join the same scan-planning flow as built-ins.

Detector plugins can also shape recursive discovery (`--recursive`) through three optional descriptor fields, all aggregated across every registered detector exactly like the built-ins' declarations:

- `DetectorDescriptor.DiscoveryIgnoredDirectories` — directory basename globs the recursive walk must not descend into (a Node detector declares `node_modules`, a Maven detector declares `target`).
- `DetectorDescriptor.DiscoveryIgnoredDirectoryMarkers` — file names whose presence marks a directory as ignored regardless of its name (the Python detectors declare `pyvenv.cfg` to skip virtualenvs).
- `PackageManagerSupport.NativeMultiModule` (set via `sdk.Support(...).WithNativeMultiModule()`) — declares that the detector natively expands nested workspace/reactor modules from a root manifest, so recursive discovery prunes nested subprojects for the same package manager below a detected root instead of scanning the modules twice.

All three are optional and older plugins that omit them keep working unchanged.

## Configuration And Proxy Support

Bomly passes the active plugin API version, the explicit `BOMLY_CONFIG` path when one was provided, proxy settings, and the enabled plugin's own config to managed plugin subprocesses.

Per-plugin configuration lives under `plugins.<plugin-id>`:

```yaml
plugins:
  clearlydefined-license-matcher:
    api_base: https://api.clearlydefined.io
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

Proxy settings can be configured with a direct proxy URL:

```yaml
network:
  proxy:
    url: http://proxy.example:8080
    no_proxy: localhost,127.0.0.1,.corp.example
```

Bomly also accepts decomposed proxy settings:

```yaml
network:
  proxy:
    type: http # http, https, or socks5
    host: proxy.example
    port: 8080
    username: my-user
    password: my-password
    no_proxy: localhost,127.0.0.1,.corp.example
  ca_cert_file: /path/to/proxy-ca-chain.pem
```

Equivalent environment variables are `BOMLY_HTTP_PROXY`, `BOMLY_HTTP_NO_PROXY`, `BOMLY_HTTP_PROXY_TYPE`, `BOMLY_HTTP_PROXY_HOST`, `BOMLY_HTTP_PROXY_PORT`, `BOMLY_HTTP_PROXY_USERNAME`, `BOMLY_HTTP_PROXY_PASSWORD`, and `BOMLY_HTTP_CA_CERT_FILE`.

When Bomly proxy fields are not set, Bomly's SDK HTTP client still honors standard `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` environment variables. For compatibility with non-SDK plugin code, Bomly also forwards the effective proxy values using the standard proxy environment variable names.

Plugins that make outbound HTTP calls should create one process-local provider with `sdk.NewHTTPClientProviderFromEnv()` and reuse it for timeout-specific clients:

```go
provider, err := sdk.NewHTTPClientProviderFromEnv()
if err != nil {
    return err
}
client := provider.Client(20 * time.Second)
```

## Package Layout

An external plugin package includes a `bomly-plugin.json` manifest and one or more platform entrypoint binaries:

```text
bomly-plugin.json
bin/
  bomly-plugin-example
README.md
```

Installed plugins are stored under:

```text
~/.bomly/plugins/
  installed.json
  store/
    <plugin-id>/
      <version>/
```

The manifest identity must match the runtime descriptor returned by the plugin binary. A detector plugin must also return package-manager support so Bomly can plan when the detector should run.

## Supported Install Sources

Current supported sources are:

- local archive
- local binary with `--dev`
- direct URL with checksum
- GitHub Release via `github:owner/repo@tag`

For GitHub Release installs, Bomly resolves release metadata, selects the asset matching the current OS and architecture, and uses a `SHA256SUMS` asset when present to verify the archive automatically.

For private GitHub Releases, set one of these environment variables before installing:

```bash
export BOMLY_GITHUB_TOKEN=<token-with-release-access>
# Also accepted: GITHUB_TOKEN, GH_TOKEN, GITHUB_AUTH_TOKEN
bomly plugins install github:bomly-dev/bomly-plugin-bun-lock-detector@v0.1.0
```

Bomly attaches the token only to `github:owner/repo@tag` metadata, checksum, and asset downloads. Direct URL installs do not receive GitHub auth headers.

## Security Model

External plugins are native OS subprocesses. They are not sandboxed, not containerized, and not restricted by Bomly beyond the operating system's standard user-level privilege boundary.

**What Bomly validates before executing a plugin:**

- Manifest schema and required fields: ID, version, kind, runtime, API version
- Plugin API version compatibility with the running core version
- Entrypoint binary exists at the recorded path
- SHA256 checksum matches the installed record, when a checksum was recorded
- Runtime descriptor matches the manifest identity, kind, API version, and installed descriptor snapshot

**What Bomly cannot enforce:**

- Restricting the plugin's filesystem or network access
- Preventing the plugin from reading environment variables or credentials on the host
- Preventing the plugin from spawning additional child processes
- Guaranteeing that the installed binary matches the declared source if no checksum was recorded

**Installation mode risk:**

| Source | Integrity guarantee |
| --- | --- |
| Local archive with `--checksum sha256:...` | Strongest: checksum ties the installed binary to the declared archive |
| GitHub Release with `SHA256SUMS` | Release asset is verified automatically when checksums are present |
| Direct URL with `--checksum` | Checksum ties the download to the declared identity |
| Direct URL with `--insecure-skip-checksum` | None: the downloaded binary may differ from the declared source |
| Local binary with `--dev` | None: appropriate only for binaries you built locally |

**Recommended practices:**

- Always supply `--checksum` for direct URL installs.
- Run `bomly plugins verify <id>` before enabling any plugin installed from an external source.
- Treat `bomly plugins enable` as the explicit trust decision for granting execution privileges.
- Prefer `github:owner/repo@tag` installs when releases publish `SHA256SUMS`.
- Do not enable plugins you did not build or obtain from a source you control.
