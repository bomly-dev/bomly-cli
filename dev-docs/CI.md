# CI

All continuous integration for the Bomly CLI runs in this repository's
GitHub Actions workflows. The public SDK module (`bomly-dev/bomly-sdk`) has
its own minimal CI in its own repository.

## Workflow Overview

| Workflow                | Trigger                          | Purpose                                                              |
|-------------------------|----------------------------------|----------------------------------------------------------------------|
| `CI`                    | Pull requests, pushes to `main`  | Lint, `go test ./...`, full and lite builds, npm wrapper tests, go.mod/go.sum tidy-drift and no-`replace` checks |
| `Smoke`                 | Pull requests (labeled), nightly | End-to-end smoke slices driving the built binary against pinned public repositories |
| `Update Smoke Goldens`  | Manual dispatch                  | Regenerates smoke golden files per slice and opens a PR with the drift |
| `Fuzz`                  | Nightly schedule, manual dispatch | Native Go fuzzing over the `scripts/run-fuzz.sh` target list; uploads minimized failures as artifacts |
| `CodeQL`                | Pull requests, pushes, schedule  | Static analysis for Go and JavaScript                                |
| `SBOM Interoperability` | Schedule, manual dispatch        | Binary-driven SBOM export/ingest checks against third-party tools    |
| `Auto Version`          | Pushes to `main`                 | Computes the next semver from the squash-commit prefix and creates a draft release tag |
| `Release`               | Release tags                     | GoReleaser build/publish with signed checksums and SLSA provenance   |
| `Scorecard`, `Dependency Review`, `Bomly Guard` | Various | Supply-chain posture checks and dogfooding                         |

Workflows use `actions/setup-go` with the Go version read from `go.mod`, so
`gofmt`, compilation, and test behavior stay aligned between local development
and GitHub Actions. Every workflow declares a top-level `permissions:` block
scoped to `contents: read`; write scopes are granted at the job level only.

## Native Go Fuzzing

The highest-risk untrusted-input boundaries have native Go fuzz targets in this
repository (lockfile parsers, SBOM JSON detection/decoding, baseline decoding,
vulnerability alias consolidation, plugin archive/path sanitizers; the SDK's
own transport parsers are fuzzed in the SDK repo). The `Fuzz` workflow runs
the full list nightly with a bounded per-target budget. Run the targets
locally with:

```bash
make fuzz
make fuzz FUZZTIME=5s
```

`FUZZTIME` is passed to each `go test -fuzz` invocation and defaults to `60s`.
The target list is maintained in `scripts/run-fuzz.sh`; register every new fuzz
target there. When Go minimizes a failure into
`testdata/fuzz/<FuzzName>/<hash>`, rerun the exact command printed by
`go test`, then commit the reproducer only after confirming it is a useful
regression seed.

## Local parity

- `make fmt` rewrites tracked Go files with `gofmt`
- `make fmt-check` fails when tracked Go files are not formatted
- `make lint` runs the repository-pinned `golangci-lint`
- `make install-hooks` points Git at the `.githooks/` pre-commit hook

## Releases

Merges to `main` create draft releases automatically from conventional-commit
prefixes (`feat:` → minor, other → patch, `type!:`/`BREAKING CHANGE:` → major,
`[skip release]` → none; squash titles count). Publishing runs GoReleaser —
archives, Linux packages, Homebrew/Scoop/WinGet manifests, signed checksums,
and SLSA provenance. See `dev-docs/RELEASE_CHECKLIST.md` and
`docs/INSTALLATION.md` for the artifacts users receive.
