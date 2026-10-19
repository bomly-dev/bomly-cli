## What `grype` does

`grype` runs Anchore's Grype vulnerability matcher against the resolved dependency graph. Grype carries its own offline vulnerability database, so it complements `osv` rather than duplicating it -- Grype is the right matcher when you need consistent results across runs and full offline operation after the first DB sync.

In the full `bomly` binary, Grype is linked in as a library and runs in-process. In `bomly-lite`, Bomly shells out to a `grype` binary on `PATH`.

## When it runs

`grype` requires `--enrich`. A plain scan never runs it. With `--enrich` and no `--matchers` selection, `grype` is the default vulnerability matcher; `--matchers grype` runs Grype and nothing else.

```bash
bomly scan --enrich --matchers grype     # Grype only
bomly scan --enrich --matchers grype,osv # Grype + OSV (recommended)
```

Run alongside `osv` for the highest coverage: the two databases overlap heavily but each catches advisories the other lags on.

## Network

Grype reads from a local vulnerability database. The full `bomly` binary downloads it on first use and, on every later enriched run, asks Anchore's database service for a newer build at most once every two hours, installing it when there is one. If that check fails, the run matches against the local copy and logs a warning. Once the local copy is older than five days, the run warns, without `-v`, that advisories published since are missing until a newer database downloads; `-v` shows the build date on every run.

| Mode | DB sync source | DB location |
| --- | --- | --- |
| Full `bomly` binary | Anchore's database service | Managed by the linked Grype library; default `~/.cache/grype/db/` |
| `bomly-lite` | External `grype` binary on `PATH` | Wherever the external `grype` stores it |

The DB sync is the only network call Grype makes. Once synced, matching is local. Bomly's enrichment cache does not wrap Grype calls -- Grype manages its own cache.

Three settings control the refresh in the full binary; see the [Config Reference](../CONFIG_REFERENCE.md):

| Key | Default | Meaning |
| --- | --- | --- |
| `matchers.grype.db_auto_update` | `true` | Check for and download a newer database; `false` uses the local copy as it is and fails when there is none |
| `matchers.grype.db_max_age` | `120h` | Age past which the run warns that the database is stale |
| `matchers.grype.db_update_check_interval` | `2h` | Minimum time between update checks |

## OS packages (apk / dpkg / rpm)

Grype matches OS packages through per-distro advisory namespaces, so a package only matches when Bomly can tell Grype which distro it came from. Bomly reads that from the `distro=` PURL qualifier Syft records while cataloguing the image (plus the `upstream=` qualifier, so advisories filed against a source package -- an Alpine origin package, a Debian source package, a source RPM -- match the binary packages built from it).

```bash
bomly scan --image alpine:3.20 --enrich --matchers grype
```

That qualifier is present for container-image scans and for SBOMs generated from an image. A hand-written PURL without it (`pkg:apk/openssl@3.0.8-r0`) has no distro to match against and reports nothing -- there is no distro-independent advisory feed for OS packages to fall back on.

## Output fields

Each `vulnerabilities[]` entry on a package carries:

- `id` -- Grype's primary ID (CVE / GHSA / vendor ID)
- `severity` -- Grype's normalized severity bucket
- `cvss` -- CVSS vector when available
- `fixed_in` -- best single upgrade target; `fixed_versions` carries every fixed version Grype reported
- `fix_state` and `fix_available` -- Grype's fix status and dated fix-availability records when available
- `epss`, `cwes`, `known_exploited`, and `risk_score` -- exploitation and weakness triage signals from the Grype database
- `data_source`, `namespace`, and `cpes` -- source and matcher context for debugging or downstream correlation
- `references` -- upstream advisory and patch links

## Examples

### Combine Grype with OSV for the highest coverage

```bash
bomly scan --enrich --matchers +osv --audit --fail-on high
```

`grype` is in the default matcher set; `osv` is opt-in, and `--matchers +osv` adds it. Duplicate advisories (same CVE found by both) are merged on the package.

### Pin to a specific Grype DB

When reproducibility matters (e.g. nightly compliance runs), pin the DB version through Grype's own config and call Bomly with the matching binary:

```bash
GRYPE_DB_AUTO_UPDATE=false bomly-lite scan --enrich          # lite: the external grype's own switch
BOMLY_GRYPE_DB_AUTO_UPDATE=false bomly scan --enrich         # full: keep the local database as it is
```

With updates off, the full binary still warns once the database is older than `matchers.grype.db_max_age`; delete `~/.cache/grype/db` to download a current one.

## Limitations

- **Grype's container-image strength does not transfer to source scans.** Grype was designed to scan container images; on source trees, OSV-class matching is usually equal or better.
- **Linux distro matching** (Alpine apk, Debian dpkg, RHEL rpm) is Grype's strongest suit and a primary reason to keep it in the default matcher set for container scans. It needs the distro the package came from; see [OS packages](#os-packages-apk--dpkg--rpm) for when that is available.
- **`bomly-lite` requires the right `grype` version on `PATH`.** The full `bomly` binary pins a known-compatible version; the lite binary uses whatever is installed and may exhibit different behavior.
- **DB freshness is your responsibility in offline environments.** A multi-day-old DB will miss new advisories.
