# CI and Release Pipeline

Bomly uses GitHub Actions for validation, security analysis, smoke coverage, and release packaging.

## Workflow Overview

| Workflow               | Trigger                                        | Purpose                                                                                                                |
|------------------------|------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `CI`                   | Pull requests, pushes to `main`                | Fast validation: `golangci-lint`, `gofmt` drift checks, tests, build sanity, module drift, and generated-doc drift |
| `CodeQL`               | Pull requests, pushes to `main`, weekly        | Static security/quality analysis for Go; results surface in the Security tab                                           |
| `Scorecard`            | Pushes to `main`, weekly, manual dispatch      | OpenSSF Scorecard supply-chain checks; publishes results and uploads SARIF                                             |
| `Dependency review`    | Pull requests                                  | GitHub dependency-review of added/changed dependencies; fails on high-severity introductions                          |
| `Bomly Review`         | Pull requests                                  | Dogfoods the Bomly review action to diff and audit dependency changes on each PR                                       |
| `Smoke`                | Merge queue, nightly schedule, manual dispatch | Slow end-to-end coverage against real repositories, SBOMs, and containers before merge, plus scheduled drift detection |
| `Update Smoke Goldens` | Manual dispatch                                | Regenerate golden files on a chosen ref and open a PR when the changes are intentional                                 |
| `Auto Version`         | Manual dispatch                                | Bump `cmd/bomly/main.go`, create a semver tag, and start the release workflow                                          |
| `Release`              | Semver tags like `v1.2.3`, manual dispatch     | Cross-platform packaging, checksum generation, and draft GitHub prerelease publication                                 |

## Required Checks

For protected branches, require at least:

- `CI`
- `Dependency Review` when dependency metadata changes
- `Smoke` on merge queue entries

`Smoke` is intentionally not a per-PR check; it is the slower pre-merge gate for merge queue entries and a nightly health monitor for upstream drift.

## Merge Queue Strategy

Bomly uses a layered merge policy:

- `CI` provides fast feedback on every pull request.
- `Smoke` runs when a change enters the merge queue, which catches end-to-end regressions before merge without slowing every PR update.
- The nightly `Smoke` run remains in place to catch ecosystem drift, container changes, and upstream repository changes that are unrelated to a new pull request.

This split keeps the expensive real-world coverage close to merge time while preserving developer iteration speed.

When `Smoke` fails because golden files drift, the workflow automatically reruns the suite with `-update` and uploads candidate golden files plus a diff artifact. The job still fails, so regressions remain visible; the artifact is there to speed up review and intentional golden updates.

After confirming that the failure is expected and not a regression, maintainers can run the `Update Smoke Goldens` workflow. It regenerates `test/smoke/testdata/golden` on the selected ref and opens a pull request only when the regenerated files differ from the committed golden set.

## Smoke Test Framework

Smoke tests live under `test/smoke` and are intentionally separate from fast unit tests. They exercise Bomly against real repositories, SBOM files, and container inputs, then compare normalized output with committed golden files.

Run the full smoke suite locally with:

```bash
make smoke
```

Pass Go test arguments through `ARGS`:

```bash
make smoke ARGS="-run TestScan/scan-npm"
```

Regenerate smoke goldens only after confirming the behavior change is expected:

```bash
make smoke ARGS="-update"
```

Smoke leaf cases run in parallel within each `go test` invocation. Go's default
`-parallel` setting is used unless you override it through `ARGS`:

```bash
make smoke ARGS="-parallel 4"
make smoke ARGS="-update -parallel 4"
```

The URL-backed scan cases are defined in the embedded `internal/benchmark/testdata/scan_targets.json` manifest. Each target has:

- `name`: stable test and artifact identity
- `url`: public repository URL
- `ref`: pinned smoke-test ref, preserving deterministic golden behavior
- `ecosystem`: canonical ecosystem selector
- `args`: additional Bomly scan arguments
- `tools`: package managers required for the case
- `benchmark_enabled`: whether the same target can participate in the local benchmark

Smoke tests use the pinned `ref`. The local benchmark intentionally does not, because GitHub's SBOM API exports the repository's current default-branch state.

The GitHub Actions `Smoke` workflow calls `make smoke`; it does not call package-specific scripts directly. Keep that pattern when adding smoke coverage so local and CI behavior stay aligned.

## Local Dependency Graph Benchmark

Bomly ships a hidden, local-only `benchmark` command for comparing native-detector output with GitHub Dependency Graph and Syft SBOMs. It is intentionally not called by GitHub Actions.

```bash
make benchmark
make benchmark ARGS="--source github,syft --ecosystem npm"
make benchmark ARGS="--case scan-gradle,scan-yarn"
make benchmark ARGS="--repo https://github.com/owner/repo --ecosystem npm"
```

The command reads the embedded scan-target manifest, clones each selected repository default branch, captures its HEAD SHA, and writes artifacts under `.benchmark-runs/latest`. Custom repositories must be public `https://github.com/<owner>/<repo>` URLs and use the default branch.

Each completed comparison preserves raw and ecosystem-filtered SBOMs, a detailed `bomly diff --sbom` artifact, and `benchmark-summary.json` files at the source, case, and run levels. Scores cover package agreement, comparable dependency edges, and their mean. Packages without PURLs are reported separately and excluded from scoring. Scores are informational: GitHub SBOM `404` responses and missing Syft executables are recorded as unavailable so other comparisons can continue.

GitHub SBOM requests can be unauthenticated, but local unauthenticated runs quickly hit GitHub's low public API rate limit. The benchmark checks token environment variables in this order:

1. `BOMLY_BENCHMARK_GITHUB_TOKEN`
2. `GITHUB_TOKEN`
3. `GH_TOKEN`

Generate an optional local Copilot report after a benchmark run:

```bash
make benchmark-report
```

This target requires `copilot`, reads `docs/prompts/bomly-benchmark-report.prompt.md`, and writes `.benchmark-runs/latest/benchmark-report.md`. It is not part of CI.

All workflows that build or test Go code use `actions/setup-go` with module and build cache enabled, keyed from `go.sum`, so runners do not need to download the full module set on every run.

The repository pins the Go version in `go.mod`, and CI reads that file directly. That keeps `gofmt`, compilation, and test behavior aligned between local development and GitHub Actions.

For local parity, the Makefile exposes:

- `make fmt` to rewrite tracked Go files with `gofmt`
- `make fmt-check` to fail when tracked Go files are not formatted
- `make lint` to run the repository-pinned `golangci-lint`

The repository also ships a pre-commit hook in `.githooks/pre-commit`. Run `make install-hooks` once per clone to point Git at that hook directory.

## Cost Controls

The per-PR workflow set is intentionally lean so the common path stays fast:

- `golangci-lint` runs inside the main `CI` workflow with the official action, pinned to the repository's lint version and using the action's built-in cache.
- Standalone `go vet ./...` is not run separately in `CI` because `.golangci.yml` already enables `govet`.
- `go test -race` is not enabled in CI because it adds runtime cost and is best reintroduced later if we need the extra concurrency diagnostics.

## Build and Packaging Model

Bomly ships in two modes:

| Artifact     | Default? | Behavior                                                         |
|--------------|----------|------------------------------------------------------------------|
| `bomly`      | Yes      | Full builtin binary with embedded Syft and Grype support         |
| `bomly-lite` | No       | Alternate binary that shells out to `syft` and `grype` on `PATH` |

The source tree now treats builtin mode as the default build. That means:

```bash
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

installs the full Bomly experience without extra tags.

The lite build remains available for advanced users and releases packaging with:

```bash
go build -tags "bomly_external_syft,bomly_external_grype" -o bin/bomly-lite ./cmd/bomly
```

## Release Process

1. Merge to `main`.
2. When ready to publish, a maintainer runs the `Auto Version` workflow from `main` and chooses a `patch`, `minor`, or `major` bump.
3. The `Auto Version` workflow updates `cmd/bomly/main.go`, commits the bump, creates a tag such as `v0.2.0`, and starts the `Release` workflow.
4. The `Release` workflow reruns validation and then cross-compiles `bomly` and `bomly-lite`.
5. The workflow packages archives for:
   - `linux/amd64`
   - `linux/arm64`
   - `darwin/amd64`
   - `darwin/arm64`
   - `windows/amd64`
   - `windows/arm64`
6. The workflow generates `SHA256SUMS`.
7. The workflow creates a **draft prerelease** in GitHub Releases and uploads all archives plus checksums.

Version bump rules are chosen explicitly when running `Auto Version`:

| Selected bump | Result             |
|---------------|--------------------|
| `patch`       | `0.2.3` -> `0.2.4` |
| `minor`       | `0.2.3` -> `0.3.0` |
| `major`       | `0.2.3` -> `1.0.0` |

The workflow uses the latest `vX.Y.Z` tag as the current version. If no tag exists yet, it falls back to the version in `cmd/bomly/main.go`. Manual dispatch is restricted to `main` so release tags are cut from the release branch.

Archive naming follows this pattern:

- `bomly_<version>_<os>_<arch>.tar.gz`
- `bomly-lite_<version>_<os>_<arch>.tar.gz`
- Windows uses `.zip` instead of `.tar.gz`

## Verification and Integrity

Every release includes `SHA256SUMS` so consumers can verify downloaded assets locally.

Examples:

```bash
sha256sum --check SHA256SUMS
```

```powershell
Get-FileHash .\bomly_v0.2.0_windows_amd64.zip -Algorithm SHA256
```

GitHub-native artifact attestations are planned. The release workflow is structured so provenance attestation steps can be added after packaging and before release publication.
