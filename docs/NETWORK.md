# Network and privacy

Bomly contacts no vulnerability or license service, sends no telemetry, and checks for no updates unless you ask it to. This page is the complete list of what can make Bomly reach the network, what it sends, and how to keep a run offline. Read it when you need to approve Bomly for a restricted environment.

A plain `bomly scan` of a local directory with committed lockfiles reads files and exits. There is one exception. When a lockfile detector cannot resolve a project, the detector chain may fall back to a detector that runs your build tool (Maven, Gradle, Go, and others). That tool may download dependencies under its own configuration. The table and the offline recipe below cover it.

## What triggers network access

| You pass | Bomly contacts | What is sent |
| --- | --- | --- |
| *(nothing)* | Nothing, when lockfile detectors resolve the graph. A fallback to a build-tool detector is covered by the last row | — |
| `--enrich` (default matchers) | `api.deps.dev` for licenses. The Grype database service (`grype.anchore.io/databases` and the archive URL it returns) on first use, and at most every two hours to check for a newer database; `matchers.grype.db_auto_update: false` turns the check off | Package name, version, and ecosystem (the PURL coordinates). The Grype database is a bulk download, so no per-package data is sent. Never source code |
| `--enrich --matchers +osv` | `api.osv.dev`, and `www.cisa.gov` for the Known Exploited Vulnerabilities (KEV) catalog | Package coordinates to OSV. The KEV catalog is a bulk download |
| `--enrich --matchers +scorecard` | `api.scorecard.dev` | The package's source repository URL |
| `--enrich` with an enabled external matcher plugin | The plugin's documented services (for example ClearlyDefined, endoflife.date) | Package coordinates, per the plugin's own documentation |
| `--url` | The Git host you named | A `git clone` of that repository. The clone has a 10-minute deadline and checkout limits; see [Security and trust boundaries](SECURITY.md#files-and-resource-limits) |
| `--image` | The container registry for the reference | An image pull by the built-in Syft (or your `syft` in the lite build) |
| `--install-first` | Your package manager's registries | Whatever `npm install`, `pip install`, and the like send. The package manager owns this traffic and its credentials |
| `bomly plugins install` | The install source you named, such as GitHub | A plugin package download, checked against size and archive limits |
| A build-tool detector | The build tool's registries | Some detectors run a build tool when the files alone cannot resolve the graph. The tool may download dependencies under its own configuration |

Two flags never trigger network access on their own: `--audit` evaluates data already on the packages, and `--analyze` runs local code analysis. MCP requests follow the same rules as the matching CLI flags.

## What Bomly never sends

- **Telemetry.** No usage data, crash reports, install IDs, or update checks. There is no endpoint for them.
- **Source code.** Enrichment sends package coordinates, not file contents.
- **Credentials to built-in services.** Built-in matcher requests are unauthenticated. Errors and logs never include configured endpoint or proxy credentials.

## Keeping a run offline

For an air-gapped or restricted pipeline:

1. Do not pass `--enrich`, `--url`, `--image`, or `--install-first`. Scan a local checkout.
2. Commit lockfiles, so the lockfile detectors resolve the graph and no build tool runs. In CI, pin `--detectors` to the lockfile detectors, so an unexpected fallback to a build-tool detector fails the job instead of running the tool. See [CI-readiness warnings](CI_READINESS.md).
3. If you do rely on a build-tool detector, that tool's own offline settings (Go module proxy settings, Maven offline mode, a local registry mirror) decide whether it downloads anything.
4. Enrichment responses are cached under `~/.bomly/cache/` with a lifetime per matcher, so a previously enriched environment keeps working through an outage. Offline, an expired entry is a miss, not stale data. See [Matchers](MATCHERS.md#cache).

## Proxies, custom endpoints, and CAs

Bomly's built-in HTTP clients honor the configured proxy, no-proxy rules, and extra CA certificates, and accept custom OSV and Scorecard endpoints, including private addresses. These are trusted settings: set them in the user config, in a file you select with `--config` or `BOMLY_CONFIG`, or in environment variables. A config file inside a repository is never loaded on its own. Redirects follow Go's standard rules, and Bomly does not block private addresses, so self-hosted mirrors work. [Security and trust boundaries](SECURITY.md#network-trust) explains the trade-offs of that choice, and the [Config reference](CONFIG_REFERENCE.md) lists the keys.

## See also

- [Security and trust boundaries](SECURITY.md) — the full permission model and residual risks
- [Matchers](MATCHERS.md) — per-service endpoints, cache, and failure behavior
- [Detectors](DETECTORS.md) — which detectors run a build tool
