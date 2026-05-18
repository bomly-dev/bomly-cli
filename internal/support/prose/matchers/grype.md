## What `grype` does

`grype` runs Anchore's Grype vulnerability matcher against the resolved dependency graph. Grype carries its own offline vulnerability database, so it complements `osv` rather than duplicating it — Grype is the right matcher when you need consistent results across runs and full offline operation after the first DB sync.

In the full `bomly` binary, Grype is linked in as a library and runs in-process. In `bomly-lite`, Bomly shells out to a `grype` binary on `PATH`.

## When it runs

`grype` requires `--enrich`. It does not run by default.

```bash
bomly scan --enrich --matchers grype     # Grype only
bomly scan --enrich --matchers grype,osv # Grype + OSV (recommended)
```

Run alongside `osv` for the highest coverage: the two databases overlap heavily but each catches advisories the other lags on.

## Network

Grype reads from a local vulnerability database that it syncs on first use and refreshes on a schedule.

| Mode | DB sync source | DB location |
| --- | --- | --- |
| Full `bomly` binary | Anchore's database service | Managed by the linked Grype library; default `~/.cache/grype/db/` |
| `bomly-lite` | External `grype` binary on `PATH` | Wherever the external `grype` stores it |

The DB sync is the only network call Grype makes. Once synced, matching is local. Bomly's enrichment cache does not wrap Grype calls — Grype manages its own cache.

## Output fields

Each `vulnerabilities[]` entry on a package carries:

- `id` — Grype's primary ID (CVE / GHSA / vendor ID)
- `severity` — Grype's normalized severity bucket
- `cvss` — CVSS vector when available
- `fixed_version` — earliest fixed version per affected range
- `references` — upstream advisory and patch links

## Examples

### Combine Grype with OSV for the highest coverage

```bash
bomly scan --enrich --audit --fail-on high
```

Both `osv` and `grype` are in the default matcher set when `--enrich` is set. Duplicate advisories (same CVE found by both) are merged on the package.

### Pin to a specific Grype DB

When reproducibility matters (e.g. nightly compliance runs), pin the DB version through Grype's own config and call Bomly with the matching binary:

```bash
GRYPE_DB_AUTO_UPDATE=false bomly-lite scan --enrich
```

## Limitations

- **Grype's container-image strength does not transfer to source scans.** Grype was designed to scan container images; on source trees, OSV-class matching is usually equal or better.
- **Linux distro matching** (Alpine apk, Debian dpkg, RHEL rpm) is Grype's strongest suit and a primary reason to keep it in the default matcher set for container scans.
- **`bomly-lite` requires the right `grype` version on `PATH`.** The full `bomly` binary pins a known-compatible version; the lite binary uses whatever is installed and may exhibit different behavior.
- **DB freshness is your responsibility in offline environments.** A multi-day-old DB will miss new advisories.
