## What `osv` does

`osv` queries the [OSV.dev](https://osv.dev) API for every package in the resolved graph. It attaches every advisory whose affected version range matches the resolved version. OSV combines GitHub Security Advisories (GHSA), distribution advisories, language-ecosystem databases (Go, npm, PyPI, RubyGems, Maven, NuGet, crates.io, and more), and direct CNA submissions. One OSV query usually covers what several per-ecosystem feeds would.

After a successful OSV match, the matcher also checks the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (KEV) catalog. A matching advisory gets `kev_exploited: true` so you can prioritize it.

## When it runs

`osv` is opt-in. It requires `--enrich`, and it is not in the default matcher set, where `grype` covers vulnerabilities. Add it next to the defaults, or run it on its own:

```bash
bomly scan --enrich --matchers +osv   # the default set plus OSV
bomly scan --enrich --matchers osv    # OSV only
```

Advisories that both OSV and Grype return are merged by identity and reported once.

## Network

| Endpoint | Used for | Cache TTL |
| --- | --- | --- |
| `api.osv.dev/v1/query` | Per-package advisory lookup | 24h |
| `api.osv.dev/v1/vulns/<id>` | Full advisory detail for matched IDs | 7 days |
| `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA KEV catalog | 6h |

The cache directory on Unix and macOS is `~/.bomly/cache/{osv,osv-vulns,kev}/`. A cache failure is logged as a warning and never stops the scan.

Response sizes are capped: 64 MiB for an OSV batch response, 4 MiB for one advisory, and 32 MiB for the KEV catalog. A larger response fails with a clear size error. A failed HTTP response reports the status code without copying the remote response body into errors or logs.

## Output fields

Each `vulnerabilities[]` entry on a package carries:

- `id`: the OSV ID, usually a CVE or GHSA identifier
- `aliases`: every cross-reference OSV knows (CVE, GHSA, distribution IDs)
- `parsed_severity`: the severity bucket (`critical`, `high`, `medium`, `low`, or `unknown`)
- `cvss`: CVSS scores when available
- `fixed_in` and `fixed_versions`: the best upgrade target and every fixed version per affected range
- `references`: links to upstream advisories and patches
- `kev_exploited`: `true` when the CISA KEV catalog lists this vulnerability
- `published` and `modified`: timestamps from the advisory

## Examples

### Fail CI on any high or critical vulnerability

The simplest gate:

```bash
bomly scan --enrich --matchers +osv --audit --fail-on high
```

### Fail CI on known-exploited vulnerabilities at any severity

The `exploitable` token matches the KEV signal, so this gate catches a KEV-listed advisory even when its severity is low or unknown:

```bash
bomly scan --enrich --matchers +osv --audit --fail-on exploitable
```

See [Auditors](../AUDITORS.md) for the full `--fail-on` grammar.

### Change the gate without new network calls

After a first `--enrich` run, the cache holds OSV responses for 24 hours. A second run reads from the cache, so you can try a stricter gate without waiting on the network:

```bash
bomly scan --enrich --matchers +osv --audit \
  --fail-on critical --fail-on exploitable
```

A package whose cache entry is older than 24 hours is queried again. The others stay cached.

## Limitations

- **Affected version-range matching is OSV's**, not Bomly's. A false positive at a pre-release version boundary is an OSV upstream issue; report it at <https://github.com/google/osv.dev>.
- **Ecosystem labels matter.** OSV expects ecosystem-correct package names, for example `groupId:artifactId` for Maven. Native detectors emit these correctly. An ingested SBOM with a non-standard ecosystem label may produce no match.
- **Private advisories** (a GHSA in a private repository) are not in OSV's public dataset.
- **The KEV signal is one advisory field.** It changes the exit code only through `--fail-on exploitable`, which you can combine with a severity token.
- **Rate limits apply.** The cache keeps repeated runs cheap, but a cold-start enrichment on a large monorepo can take minutes.
