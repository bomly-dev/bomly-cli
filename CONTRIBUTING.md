# Contributing to Bomly

Thanks for your interest in Bomly!

## Repository layout

This repository contains the full Bomly CLI: the implementation under
`internal/`, the `cmd/bomly` entry point, user documentation, release
automation, install scripts, the npm MCP wrapper, and the end-to-end smoke
test suite that exercises the built binary.

One piece lives in its own repository:

- [`github.com/bomly-dev/bomly-sdk`](https://github.com/bomly-dev/bomly-sdk) —
  the public contract for building Bomly components and managed plugins,
  released independently and pinned here. Plugin authors should start there,
  with [docs/PLUGINS.md](docs/PLUGINS.md), and with the starter repository at
  [`bomly-plugin-template`](https://github.com/bomly-dev/bomly-plugin-template).

## What to contribute

- Bug fixes and features across the CLI, detectors, matchers, auditors, and
  analyzers (see [AGENTS.md](AGENTS.md) for the feature checklist and package
  boundaries).
- Documentation fixes and improvements under `docs/`.
- Install script, packaging (`npm/`), and workflow fixes.
- Smoke test additions under `test/smoke` (see the notes in that package —
  cases pin public example repositories by tag and compare against goldens).

Bug reports and feature requests are welcome as issues here — this is Bomly's
public issue tracker.

## Development

Building requires Go 1.27 or newer. On Go 1.21+ with the default
`GOTOOLCHAIN=auto`, the right toolchain downloads automatically from the
`go.mod` directive; with `GOTOOLCHAIN=local` or an older Go, install Go 1.27
first.

```sh
make build       # bin/bomly and bin/bomly-lite
make test        # unit tests (includes the plugin fixture compile check)
make verify      # everything that gates a push (add SMOKE=1 for the smoke suite)
make smoke       # end-to-end tests (slow, requires network)
make fuzz FUZZTIME=5s  # run the registered fuzz targets briefly
make fmt         # format
make lint        # golangci-lint
make generate    # regenerate config reference, schemas, support matrix, component docs
```

Run `make verify` before submitting -- `.githooks/pre-push` refuses a push without it, and `make install-hooks` turns that on. If your change touches configuration,
output schemas, or the pinned SDK version, run `make generate` and commit the
regenerated docs.

## Commit style

Conventional commits drive releases: `feat:` → minor, anything else → patch,
`type!:`/`BREAKING CHANGE:` → major, `[skip release]` to suppress. Squash-merge
titles determine the bump.

## Releases

Merges to `main` create draft releases automatically; publishing runs
GoReleaser with signed checksums and provenance. See
[docs/INSTALLATION.md](docs/INSTALLATION.md) for the artifacts users receive.
