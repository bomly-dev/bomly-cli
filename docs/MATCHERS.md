# Matchers

Matchers enrich packages after Bomly has built a dependency graph. They attach vulnerabilities, license metadata, and lifecycle signals to packages already in the graph.

Bomly is **offline-safe by default**. Matchers that use the network only run when you opt in with `--enrich`. A scan without `--enrich` makes zero outbound HTTP calls.

## Categories

| Kind | Examples | What it adds |
| --- | --- | --- |
| Vulnerability | `osv`, `grype` | CVE / GHSA / OSV IDs, severity, CVSS, aliases, fixed versions, references, KEV signal |
| License | `depsdev-license-matcher` | SPDX expression, declared/discovered split, license source |
| Lifecycle | External plugin | End-of-life status from a plugin such as the [eol-lifecycle-matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher) |

The full live list lives in the CLI:

```bash
bomly plugins list --matchers
bomly plugins list --matchers --json
```

## Running matchers

Pass `--enrich` to run all default network matchers:

```bash
bomly scan --enrich
```

Use `--matchers` to restrict or extend the set with the standard `+/-` selector grammar:

```bash
# Only OSV
bomly scan --enrich --matchers osv

# Default set minus the built-in license matcher
bomly scan --enrich --matchers -depsdev-license-matcher

# Add an external plugin matcher
bomly scan --enrich --matchers +clearlydefined-license-matcher
```

External matchers are published as plugins — see the [ClearlyDefined License Matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher) and [EOL Lifecycle Matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher) for worked examples, and [PLUGINS.md](PLUGINS.md) to install and enable them.

## Network endpoints

When `--enrich` is set, Bomly may call:

- `api.osv.dev` — OSV vulnerability database
- `api.cisa.gov` — CISA Known Exploited Vulnerabilities catalog
- `api.deps.dev` — Google's deps.dev package metadata

These are the **only** hosts Bomly's built-in matchers contact during enrichment. No telemetry. No data exfiltration. No credentials sent. External plugin matchers may contact their own documented services after you install and enable them. See [docs/ARCHITECTURE.md](ARCHITECTURE.md) for the full network model.

## Cache

Every matcher caches its responses on disk so repeated scans are fast and resilient to upstream outages.

| | Default |
| --- | --- |
| Cache root (Unix/macOS) | `$HOME/.bomly/cache/` |
| Cache root (Windows) | `%USERPROFILE%\.bomly\cache\` |
| Fallback when no home dir | `./.bomly-cache/` |

Per-matcher subdirectories and TTLs:

| Matcher | Subdirectory | Default TTL |
| --- | --- | --- |
| OSV (queries) | `osv/` | 24h |
| OSV (vulnerability details) | `osv-vulns/` | 7d |
| CISA KEV | `kev/` | 6h |
| deps.dev | `licenses/depsdev/` | 24h |

To clear the cache, delete the directory:

```bash
rm -rf ~/.bomly/cache    # Unix/macOS
Remove-Item -Recurse $env:USERPROFILE\.bomly\cache  # PowerShell
```

Override cache locations with matcher-specific keys such as `matchers.osv.cache_dir` and `matchers.scorecard.cache_dir`; see [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md). External plugins may expose their own cache config under `plugins.<plugin-id>`. Cache failures are **always non-fatal** — Bomly logs a warning and continues.

## Failure semantics

Matchers degrade rather than abort. A failed enrichment never fails the scan:

- **Network error** — the package is left unannotated; a warning is logged.
- **Cache write error** — the response is still applied; a warning is logged.
- **Rate-limit / 5xx** — Bomly retries with backoff inside the matcher, then degrades.

This means a scan with `--enrich` always succeeds (exit 0) on a healthy graph, even if some enrichment lookups failed. To enforce that enrichment data must be present, combine `--enrich` with `--audit --fail-on <severity>` — see [Auditors](AUDITORS.md).

## See also

- [Per-matcher reference](matchers/) — descriptors, cache shape, output fields, ecosystem coverage
- [Auditors](AUDITORS.md) — how matcher output is evaluated against policy
- [Reachability](REACHABILITY.md) — narrowing matcher findings to symbols actually called
