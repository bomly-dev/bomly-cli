## What `clearlydefined-license-checker` does

`clearlydefined-license-checker` fetches license metadata from [ClearlyDefined](https://clearlydefined.io), an open project that curates license and copyright data for open-source components. ClearlyDefined often has license data when deps.dev and registry metadata do not, especially for older packages and ecosystems with weak registry-level license fields.

Run it alongside `depsdev-license-checker` for the highest coverage.

## When it runs

Requires `--enrich`. Does not run by default.

```bash
bomly scan --enrich
bomly scan --enrich --matchers clearlydefined-license-checker  # this matcher only
```

## Network

| Endpoint | Used for | Cache TTL |
| --- | --- | --- |
| `api.clearlydefined.io/definitions/<type>/<provider>/<namespace>/<name>/<revision>` | Per-package license definition | 24h |

Cache directory: `~/.bomly/cache/licenses/clearlydefined/`. Cache failures are non-fatal.

## Output fields

Each package gains:

- `license` — SPDX expression from the ClearlyDefined definition
- `license_source` — set to `clearlydefined`
- `matched_package` — `true` flag indicating the matcher resolved data for this package

## Examples

### Combine both license matchers

```bash
bomly scan --enrich \
  --matchers depsdev-license-checker,clearlydefined-license-checker
```

When both matchers resolve a license for the same package, the priority is set by the detector pipeline order. Inspect `license_source` on the package to see which one won.

## Limitations

- **Coverage is uneven.** ClearlyDefined relies on community curation; well-known packages have rich definitions, obscure ones may have none.
- **Definitions can lag releases.** A newly published version may have no definition for several days.
- **Private packages** are not curated by ClearlyDefined.
- **License declarations are aggregated**, not authoritative. A package's actual license is in its source repo; ClearlyDefined records what reviewers found.
