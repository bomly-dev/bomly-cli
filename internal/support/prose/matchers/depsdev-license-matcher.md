## What `depsdev-license-matcher` does

`depsdev-license-matcher` fetches package metadata from [deps.dev](https://deps.dev) (Google's open package metadata service) and attaches license information to packages that the detector did not resolve a license for. deps.dev coverage is strongest for npm, Go, Maven, NuGet, PyPI, Cargo, and RubyGems.

## When to use it

Use it when local manifests do not carry enough license information, especially for generated SBOMs or ecosystems where lockfiles omit license fields:

```bash
bomly scan --enrich --matchers depsdev-license-matcher  # this matcher only
```

## What gets added

Each matched package can gain:

- `licenses[]` entries with normalized SPDX expressions
- `licenses[].source = external-depsdev`
- `matched = true` on packages that received license data

Bomly only fills packages that do not already have license data. Detector-resolved licenses remain the first source of truth.

## Cache and network

The matcher batches version lookups through deps.dev and caches responses for 24 hours under `~/.bomly/cache/licenses/depsdev/`. Cache failures are non-fatal: Bomly logs a warning and still applies the API response.

## CI recipe

```bash
bomly scan \
  --path . \
  --enrich \
  --matchers depsdev-license-matcher
```

Add `--audit --fail-on any` only when your policy should fail builds on denied or unknown license findings.
