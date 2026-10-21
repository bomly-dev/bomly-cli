# Matchers

Matchers enrich packages after Bomly has built a dependency graph. They attach vulnerabilities, license metadata, and lifecycle signals to packages already in the graph.

Matchers only call out when you pass `--enrich`, but a build-tool detector may still download dependencies during a plain scan, as [Network and privacy](NETWORK.md) explains.

## Categories

| Kind | Examples | What it adds |
| --- | --- | --- |
| Vulnerability | `osv`, `grype` | CVE / GHSA / OSV IDs, severity, CVSS, aliases, fixed versions, references, KEV signal |
| License | `depsdev-license-matcher` | SPDX expression, declared/discovered split, license source |
| Lifecycle | External plugin | End-of-life status from a plugin such as the [EOL lifecycle matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher) |

The CLI prints the live list:

```bash
bomly plugins list --matchers
bomly plugins list --matchers --json
```

## Running matchers

Pass `--enrich` to run the default matchers:

```bash
bomly scan --enrich
```

With no `--matchers` selection, `--enrich` runs the built-in matchers `depsdev-license-matcher`, `grype`, plus any installed external matcher plugin you have enabled. `osv`, `scorecard` are opt-in: add one with `--matchers +<name>`. Vulnerabilities come from Grype's database by default. OSV and Grype can run together. Advisories both return are merged by identity and reported once.

Use `--matchers` to restrict or extend the set with the standard [selector grammar](COMMANDS.md#selector-grammar):

```bash
# Only OSV
bomly scan --enrich --matchers osv

# Default set minus the built-in license matcher
bomly scan --enrich --matchers -depsdev-license-matcher

# Add an external plugin matcher
bomly scan --enrich --matchers +clearlydefined-license-matcher
```

External matchers are published as plugins. The [ClearlyDefined license matcher](https://github.com/bomly-dev/bomly-plugin-clearlydefined-matcher) and the [EOL lifecycle matcher](https://github.com/bomly-dev/bomly-plugin-eol-matcher) are worked examples. See [PLUGINS.md](PLUGINS.md) to install and enable them.

## Network endpoints

With the default matcher set, `--enrich` may call:

- `api.deps.dev`: Google's deps.dev package metadata.
- `grype.anchore.io/databases`, plus the archive URL it returns: the bundled Grype downloads its vulnerability database on first use. It then checks for a newer build at most every two hours. Set `matchers.grype.db_auto_update: false` to turn the check off.

Selecting `osv` adds `api.osv.dev` (the OSV vulnerability database) and `www.cisa.gov` (the CISA Known Exploited Vulnerabilities catalog). Selecting `scorecard` adds `api.scorecard.dev`. The lite build leaves Grype database management to the external `grype` command. Bomly sends no telemetry or credentials to its built-in matcher services. External plugin matchers may contact other services after you install and enable them. [Network and privacy](NETWORK.md) lists every trigger and what is transmitted.

## Cache

Every matcher caches its responses on disk, so repeated scans are fast and survive upstream outages.

| | Default |
| --- | --- |
| Cache root (Unix/macOS) | `$HOME/.bomly/cache/` |
| Cache root (Windows) | `%USERPROFILE%\.bomly\cache\` |
| Fallback when no home dir | `./.bomly-cache/` |

Each matcher uses its own subdirectory and time to live (TTL):

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

Override cache locations with matcher-specific keys such as `matchers.osv.cache_dir` and `matchers.scorecard.cache_dir`; see [CONFIG_REFERENCE.md](CONFIG_REFERENCE.md). External plugins may expose their own cache config under `plugins.<plugin-id>`. A cache failure never fails a scan. Bomly logs a warning and continues.

## Failure semantics

Matchers degrade rather than abort. A failed enrichment never fails the scan:

- **Network error**: the package is left without the data, and a warning is logged.
- **Cache write error**: the response is still applied, and a warning is logged.
- **Rate limit or server error**: Bomly retries with backoff inside the matcher, then degrades.

So a scan with `--enrich` exits 0 on a healthy graph even when some lookups failed. A policy gate only sees the data that did arrive, so it cannot tell a clean package from one whose lookup failed. Run with `-v` to see the warning for each failed lookup. To fail CI on the findings enrichment does return, add `--audit --fail-on <severity>`; see [Auditors](AUDITORS.md).

## See also

- [Per-matcher reference](matchers/): descriptors, cache shape, output fields, ecosystem coverage
- [Auditors](AUDITORS.md): how matcher output is evaluated against policy
- [Reachability](REACHABILITY.md): narrowing matcher findings to symbols actually called
