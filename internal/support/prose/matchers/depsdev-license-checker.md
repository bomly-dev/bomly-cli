## What `depsdev-license-checker` does

`depsdev-license-checker` fetches package metadata from [deps.dev](https://deps.dev) (Google's open package metadata service) and attaches license information to packages that the detector did not resolve a license for. deps.dev coverage is strongest for npm, Go, Maven, NuGet, PyPI, Cargo, and RubyGems.

## When it runs

Requires `--enrich`. Does not run by default.

```bash
bomly scan --enrich
bomly scan --enrich --matchers depsdev-license-checker  # this matcher only
```

## Network

| Endpoint | Used for | Cache TTL |
| --- | --- | --- |
| `api.deps.dev/v3alpha/systems/<system>/packages/<name>/versions/<version>` | Per-package license metadata | 24h |

Cache directory: `~/.bomly/cache/licenses/depsdev/`. Cache failures are non-fatal.

## Output fields

Each package gains:

- `license` — SPDX expression when deps.dev reports one
- `license_source` — set to `depsdev` so you can distinguish from licenses the detector resolved natively
- `matched_package` — `true` flag indicating the matcher resolved data for this package

## Examples

### Use deps.dev for license-only enrichment

If you want license data without vulnerability data (e.g. to feed a license-compliance dashboard):

```bash
bomly scan --enrich \
  --matchers depsdev-license-checker,clearlydefined-license-checker
```

This skips OSV/Grype/EOL and only runs the license matchers.

## Limitations

- **deps.dev's license accuracy varies by ecosystem.** It is highest for ecosystems where the package registry exposes a license field (npm, RubyGems, Cargo). For Java/Maven, deps.dev reads `<licenses>` from POMs, which is often incomplete or non-SPDX.
- **Pre-release versions** may not have license metadata published yet.
- **Private packages** are not in deps.dev. Use `clearlydefined-license-checker` or have your detector resolve the license from the manifest.
- **Rate limits** apply. The cache keeps repeated runs cheap.
