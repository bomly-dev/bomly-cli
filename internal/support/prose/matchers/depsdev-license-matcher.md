## What `depsdev-license-matcher` does

`depsdev-license-matcher` fetches package metadata from [deps.dev](https://deps.dev), Google's open package metadata service. It attaches license information to packages for which the detector did not resolve a license. It covers the ecosystems listed in the table above and skips packages from any other ecosystem.

## When it runs

Use it when local manifests do not carry enough license information, for example with generated SBOMs or ecosystems whose lockfiles omit license fields:

```bash
bomly scan --enrich --matchers depsdev-license-matcher  # this matcher only
```

## Network

The matcher batches version lookups through deps.dev and caches responses for 24 hours under `~/.bomly/cache/licenses/depsdev/`. Each successful batch response is limited to 16 MiB. A cache failure is logged as a warning, and the API response is still applied. A failed HTTP response reports the status code without copying the server's response body into the error.

## Output fields

Each matched package can gain:

- `licenses[]` entries with normalized SPDX expressions
- `licenses[].source` set to `external-depsdev`
- `matched` set to `true` on packages that received license data

Bomly only fills packages that have no license data yet. A license the detector resolved is never replaced.

## Examples

A CI run that enriches licenses only:

```bash
bomly scan \
  --path . \
  --enrich \
  --matchers depsdev-license-matcher
```

Add `--audit --fail-on any` only when your policy should fail builds on denied or unknown license findings.
