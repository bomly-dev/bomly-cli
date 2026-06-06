# Managed Plugins

Bomly plugins let you extend scans without changing the Bomly binary. Today, managed external plugins can add:

- **detectors** that turn project files into dependency graphs
- **matchers** that enrich packages with vulnerabilities, licenses, lifecycle data, or other package metadata
- **auditors** that turn graph and registry data into findings or risk scores

External analyzer plugins are not supported yet. `bomly plugin list --analyzers` can show built-in reachability analyzers, but the external plugin runtime currently serves only detectors, matchers, and auditors through `sdk.ServeDetector`, `sdk.ServeMatcher`, and `sdk.ServeAuditor`.

## Start Here

Use this page when you want to install, trust, configure, package, or troubleshoot a managed plugin.

Use the implementation guides when you are writing one:

- [How To Implement A Detector Plugin](plugins/how-to-implement-detector.md)
- [How To Implement A Matcher Plugin](plugins/how-to-implement-matcher.md)
- [How To Implement An Auditor Plugin](plugins/how-to-implement-auditor.md)

The repository also includes a working detector example at [`examples/plugins/go-module-detector`](../examples/plugins/go-module-detector).

## How Plugins Run

Managed plugins are Go binaries that use Bomly's public `sdk` package. Bomly starts each enabled external plugin as a separate native OS subprocess through HashiCorp `go-plugin` in gRPC mode.

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
bomly plugin enable <plugin-id>
```

Treat `bomly plugin enable` as the trust decision. When enabled, a plugin runs with the same user-level privileges as the Bomly process. It can read and write files, make network connections, spawn child processes, and access environment variables available to that user.

Repository-declared plugins are never executed automatically. The host must explicitly install and enable the plugin before it can run.

## Try The Example Plugin

Build the example detector from the repository root:

```bash
go build -o ./bin/bomly-example-gomod-detector ./examples/plugins/go-module-detector
```

On Windows, Go writes `./bin/bomly-example-gomod-detector.exe`. `bomly plugin install --dev` accepts either the extensionless path or the explicit `.exe` path.

Install and enable it for local development:

```bash
bomly plugin install ./bin/bomly-example-gomod-detector --dev
bomly plugin enable bomly.example.gomod-detector
```

Check that Bomly can see it:

```bash
bomly plugin list --external
bomly plugin info bomly.example.gomod-detector
```

Run verification and readiness checks:

```bash
bomly plugin verify bomly.example.gomod-detector
bomly plugin test bomly.example.gomod-detector
bomly plugin doctor bomly.example.gomod-detector
```

Select it explicitly during a scan:

```bash
bomly scan \
  --path ./my-go-project \
  --detectors bomly.example.gomod-detector \
  --json
```

Disable or uninstall it later:

```bash
bomly plugin disable bomly.example.gomod-detector
bomly plugin uninstall bomly.example.gomod-detector
```

## Common Commands

List plugins:

```bash
bomly plugin list
bomly plugin list --external
bomly plugin list --detectors
bomly plugin list --matchers --json
bomly plugin list --auditors
```

Show one plugin:

```bash
bomly plugin info <plugin-id>
bomly plugin info <plugin-id> --json
```

Install a plugin:

```bash
bomly plugin install ./dist/bomly-plugin-example.tar.gz
bomly plugin install ./bin/bomly-example-gomod-detector --dev
bomly plugin install https://example.com/bomly-plugin-example.tar.gz --checksum sha256:...
bomly plugin install github:security-team/bomly-plugin-gomod@v1.2.0
```

Check a plugin:

```bash
bomly plugin verify <plugin-id> # manifest, checksum, binary, runtime metadata
bomly plugin test <plugin-id>   # runtime readiness
bomly plugin doctor <plugin-id> # verify + test
```

Enable, disable, or remove a plugin:

```bash
bomly plugin enable <plugin-id>
bomly plugin disable <plugin-id>
bomly plugin uninstall <plugin-id>
```

## Select Plugins During A Scan

Plugin selectors use the same `+/-` grammar as built-in components:

```bash
# Use only this detector.
bomly scan --detectors security-team.detector.gomod

# Add an external matcher to the default matcher set.
bomly scan --enrich --matchers +security-team.matcher.vulnfeed

# Use one auditor explicitly.
bomly scan --audit --auditors security-team.auditor.policy
```

Detector plugins can participate in subproject discovery. Their manifest records `detectorDescriptor.packageManagerSupport`, and each support entry names a package manager plus evidence patterns such as `go.mod`. Bomly uses those patterns during runtime preparation so external detectors can join the same scan-planning flow as built-ins.

## Configuration And Proxy Support

Bomly passes the active plugin API version, the explicit `BOMLY_CONFIG` path when one was provided, proxy settings, and the enabled plugin's own config to managed plugin subprocesses.

Per-plugin configuration lives under `plugins.<plugin-id>`:

```yaml
plugins:
  security-team.matcher.vulnfeed:
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

The manifest identity must match the runtime metadata returned by the plugin binary. A detector manifest must also include package-manager support so Bomly can plan when the detector should run.

## Supported Install Sources

Current supported sources are:

- local archive
- local binary with `--dev`
- direct URL with checksum
- GitHub Release via `github:owner/repo@tag`

For GitHub Release installs, Bomly resolves release metadata, selects the asset matching the current OS and architecture, and uses a `SHA256SUMS` asset when present to verify the archive automatically.

## Security Model

External plugins are native OS subprocesses. They are not sandboxed, not containerized, and not restricted by Bomly beyond the operating system's standard user-level privilege boundary.

**What Bomly validates before executing a plugin:**

- Manifest schema and required fields: ID, version, kind, runtime, API version
- Plugin API version compatibility with the running core version
- Entrypoint binary exists at the recorded path
- SHA256 checksum matches the installed record, when a checksum was recorded
- Runtime-reported metadata matches the manifest identity, version, kind, and API version

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
- Run `bomly plugin verify <id>` before enabling any plugin installed from an external source.
- Treat `bomly plugin enable` as the explicit trust decision for granting execution privileges.
- Prefer `github:owner/repo@tag` installs when releases publish `SHA256SUMS`.
- Do not enable plugins you did not build or obtain from a source you control.
