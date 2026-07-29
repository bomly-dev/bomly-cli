# Network and Privacy

Bomly's rule is simple: **matcher services, telemetry, and version checks are never contacted on their own — network-backed enrichment requires `--enrich`, and telemetry doesn't exist.** This page is the audit surface for that claim — every network trigger, what it contacts, what it transmits, and how to keep a run fully offline.

A plain `bomly scan` of a local directory with committed lockfiles reads files and exits. No matcher calls, no version checks, no usage pings, no account. The one nuance is dependency *resolution* itself: when a lockfile parser can't resolve a project, the detector chain may fall through to a build-tool-backed detector that runs your package manager (Maven, Gradle, Go, …), and that tool may download dependencies under its own configuration — see the table below and the offline recipe for how to prevent it.

## What triggers network access

| You pass | Bomly contacts | What is transmitted |
| --- | --- | --- |
| *(nothing)* | Nothing, when lockfile detectors resolve the graph. If the chain falls through to a build-tool-backed detector, that tool may contact its registries (see the build-tool row) | — |
| `--enrich` | `api.osv.dev`, `api.cisa.gov` (CISA Known Exploited Vulnerabilities — KEV — catalog), `api.deps.dev`; `api.scorecard.dev` (Scorecard matcher); Grype database service (`grype.anchore.io/databases`, plus the archive URL it returns) on first use | Package identifiers: name, version, and ecosystem — the package URL (PURL) coordinates. Scorecard queries use the package's source repository URL. The KEV catalog and Grype database are bulk downloads — no per-package data is sent. Never source code. |
| `--url` | The Git host you named | A `git clone` of that repository (10-minute deadline; checkout size, path, and symlink limits apply) |
| `--image` | The container registry for the reference | An image pull via the embedded Syft (or your external `syft` in the lite build) |
| `--install-first` | Your package manager's configured registries | Whatever `npm install`, `pip install`, etc. transmit — the package manager owns this traffic and its credentials |
| Build-tool-backed detectors | The build tool's configured registries | Some detectors run a build tool (Maven, Gradle, Go, …) when file evidence alone can't resolve the graph; that tool may download dependencies under its own configuration |
| `bomly plugins install` | The install source you named (e.g. GitHub) | A plugin package download, verified against size and archive-safety limits |
| Enabled external matcher plugins + `--enrich` | Their documented services (e.g. ClearlyDefined, endoflife.date) | Package identifiers, per the plugin's own documentation |

Two flags never trigger network access on their own: `--audit` evaluates data already present on packages, and `--analyze` runs local code analysis. MCP requests follow exactly the same gates as the equivalent CLI flags.

## What Bomly never sends

- **Telemetry** — no usage data, crash reports, install IDs, or update checks. There is no endpoint for them.
- **Source code** — enrichment sends package coordinates, not file contents.
- **Credentials to built-in services** — built-in matcher requests are unauthenticated. Errors and logs never include configured endpoint or proxy credentials.

## Keeping a run offline

For an air-gapped or network-restricted pipeline:

1. Don't pass `--enrich`, `--url`, `--image`, or `--install-first`; scan a local checkout.
2. Commit lockfiles, so lockfile detectors resolve the graph without a build tool ever running. Pin `--detectors` to the lockfile detectors in CI so an unexpected fall-through to a build-tool-backed detector fails loudly instead of silently invoking the tool — see [CI-readiness warnings](CI_READINESS.md). If you do rely on a build-tool-backed detector, the tool's own offline configuration (Go module proxy settings, Maven offline mode, a local registry mirror) governs whether it downloads anything.
3. Matcher responses are cached under `~/.bomly/cache/` with per-matcher TTLs, so a previously enriched environment keeps working through upstream outages — but an expired cache entry on an offline host is a miss, not stale data. See [Matchers → Cache](MATCHERS.md#cache).

## Proxies, custom endpoints, and CAs

Built-in HTTP clients honor configured proxies, no-proxy rules, and additional CA certificates, and support custom OSV/Scorecard endpoints — including private-network destinations — via trusted configuration (user config, `--config`, `BOMLY_CONFIG`, or environment variables; repository config is never loaded automatically). Redirects follow Go's standard rules, and Bomly deliberately does not block private addresses so self-hosted mirrors work. The trade-offs of that choice are documented in [Security → Network Trust](SECURITY.md#network-trust); the keys live in the [Config Reference](CONFIG_REFERENCE.md).

## See also

- [Architecture → Network behavior](ARCHITECTURE.md#network-behavior) — the same boundaries in pipeline context
- [Security and Trust Boundaries](SECURITY.md) — the full permission model and residual risks
- [Matchers](MATCHERS.md) — per-service endpoints, cache, and failure semantics
