# CI and Release Pipeline

Bomly uses GitHub Actions for validation, security analysis, smoke coverage, and release packaging.

## Workflow Overview

| Workflow               | Trigger                                        | Purpose                                                                                                                |
|------------------------|------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `Build & Test`         | Pull requests, pushes to `main`                | Fast validation split into parallel jobs: `lint`, `test`, `build`, `format`, `modules` (go.mod drift), and `generated-docs` (generated-doc drift) |
| `CodeQL`               | Pull requests, pushes to `main`, weekly        | Static security/quality analysis for Go; results surface in the Security tab                                           |
| `Scorecard`            | Pushes to `main`, weekly, manual dispatch      | OpenSSF Scorecard supply-chain checks; publishes results and uploads SARIF                                             |
| `Fuzz`                 | Nightly schedule, manual dispatch              | Native Go fuzzing over lockfile parsers, SBOM JSON, SDK transport JSON, and plugin path/archive sanitizers            |
| `Dependency review`    | Pull requests                                  | GitHub dependency-review of added/changed dependencies; fails on high-severity introductions                          |
| `Bomly Guard`          | Pull requests                                  | Dogfoods the Bomly Guard action to diff and audit dependency changes on each PR                                        |
| `Smoke`                | Merge queue, nightly schedule, manual dispatch | Slow end-to-end coverage against real repositories, SBOMs, and containers before merge, plus scheduled drift detection |
| `Update Smoke Goldens` | Manual dispatch                                | Regenerate golden files on a chosen ref and open a PR when the changes are intentional                                 |
| `Auto Version`         | Manual dispatch                                | Bump `cmd/bomly/main.go`, create a semver tag, and start the release workflow                                          |
| `Release`              | Semver tags like `v1.2.3`, manual dispatch     | GoReleaser packaging, checksums, Linux packages, package-manager manifests, GitHub release publication, cosign keyless signing, and SLSA provenance |

## Required Checks

For protected branches, require at least:

- The `Build & Test` jobs (`Lint`, `Test`, `Build`, `Format`, `Module drift`, `Generated docs drift`)
- `Dependency review` when dependency metadata changes
- `Smoke` on merge queue entries

`Build & Test` runs each check as its own job so they execute in parallel and report independently. Because the checks are now per-job, update the required status checks in branch protection to the individual job names above (the previous single `CI` check no longer exists).

`Smoke` is intentionally not a per-PR check; it is the slower pre-merge gate for merge queue entries and a nightly health monitor for upstream drift.

## Supply-Chain Hardening (OpenSSF Scorecard)

Bomly dogfoods its own domain by tracking the project's [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/bomly-dev/bomly-cli). The weekly `Scorecard` workflow republishes results to the Security tab. Most checks are satisfied in-repo and stay green automatically:

- **Token-Permissions** — every workflow declares a top-level `permissions:` block scoped to `contents: read`. Any write scope (release publishing, the Guard PR comment, the smoke-goldens PR) is granted at the **job** level only, never at the top level.
- **Pinned-Dependencies** — all GitHub Actions are pinned by full commit SHA with a trailing `# vX.Y.Z` comment (for example `actions/checkout@<sha> # v7.0.0`). Dependabot's `github-actions` updater understands this form and bumps both the SHA and the comment, so pinning does not freeze us on stale actions. When adding a new `uses:`, pin it the same way — `pinact run` (suzuki-shunsuke/pinact) rewrites the whole tree, or resolve a single tag with `gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`. The `Smoke` and `Update Smoke Goldens` workflows install `pip`/`pipenv`/`poetry` from `.github/requirements-ci-tools.txt`, a hash-locked, fully-resolved requirements file (`pip install --require-hashes`) instead of an unpinned inline `pip install`. Regenerate it after bumping `.github/requirements-ci-tools.in` with `pip-compile --allow-unsafe --generate-hashes --output-file=requirements-ci-tools.txt requirements-ci-tools.in` run from `.github/` under the same Python version the workflows use (3.12), so the resolved hash set covers the right wheel tags.
- **SAST** — CodeQL runs on every push, PR, and weekly.
- **Signed-Releases** — the `release` job signs `SHA256SUMS` keylessly with [cosign](https://docs.sigstore.dev/cosign/signing/overview/) (`SHA256SUMS.sigstore.json`, GitHub OIDC identity, no managed keys), and a separate `provenance` job calls the [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) generic builder to produce a single `multiple.intoto.jsonl` SLSA Build Level 3 provenance file over every release artifact's hash. The `publish` job then uploads it to the GitHub release itself, by release ID — not via the generator's built-in `upload-assets`, which can't target draft releases (see [Release Process](#release-process) for why). Verification commands for end users are in [docs/INSTALLATION.md](../docs/INSTALLATION.md#verify-release-checksums). The generator's `uses:` line is pinned to the `v2.1.0` tag, not a commit SHA — SHA-pinning it breaks `slsa-verifier`'s builder-identity check — and `.github/pinact.yaml` excludes that line from automated re-pinning so it doesn't regress. Because the provenance file is attached by a job downstream of `release`, and GitHub's immutable releases feature blocks adding assets after a release is published, `.goreleaser.yaml` keeps the release as a draft and the `publish` job flips it to published only after provenance is attached.

A few Scorecard checks require maintainer action **outside** the repository and are not code changes:

- **Branch-Protection** — on `main`, require pull-request reviews (at least one approval), require the status checks listed under [Required Checks](#required-checks), and **enable "Do not allow bypassing the above settings" / include administrators**. Admin bypass is the specific gap Scorecard currently flags. Configure under Settings → Branches.
- **CII / OpenSSF Best Practices badge** — register the project at <https://www.bestpractices.dev>, complete the passing-tier questionnaire, and add the earned badge to `README.md`. One-time, external.

Time-based checks (Code-Review approvals, Contributors, Maintained) improve on their own as the project accrues history and reviewed merges; they need no configuration.

## Merge Queue Strategy

Bomly uses a layered merge policy:

- `Build & Test` provides fast feedback on every pull request.
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
- `adjudicated_relationships`: exact PURL edges independently verified in the pinned repository but omitted by a comparison source; every entry requires a reason

Smoke tests use the pinned `ref`. The local benchmark intentionally does not, because GitHub's SBOM API exports the repository's current default-branch state.

The GitHub Actions `Smoke` workflow calls `make smoke`; it does not call package-specific scripts directly. Keep that pattern when adding smoke coverage so local and CI behavior stay aligned.

## Native Go Fuzzing

Bomly runs native Go fuzzing nightly and on demand through the `Fuzz` workflow. The target matrix is intentionally explicit so CI spends time on the highest-risk untrusted input boundaries:

- Node lockfile parsers for npm, pnpm, and Yarn
- SPDX/CycloneDX SBOM JSON detection and decoding
- Cross-matcher vulnerability alias consolidation and evidence preservation
- SDK package URL canonicalization and transport JSON
- Managed plugin archive-name and relative-path sanitizers

Run the same matrix locally with:

```bash
make fuzz
make fuzz FUZZTIME=5s
```

`FUZZTIME` is passed to each `go test -fuzz` invocation and defaults to `60s`. When Go minimizes a failure into `testdata/fuzz/<FuzzName>/<hash>`, rerun the exact command printed by `go test`, then commit the reproducer only after confirming it is a useful regression seed.

## Local Dependency Graph Benchmark

Bomly ships a hidden, local-only `benchmark` command for comparing native-detector output with GitHub Dependency Graph and Syft SBOMs. It is intentionally not called by GitHub Actions.

```bash
make benchmark
make benchmark ARGS="--source github,syft --ecosystem npm"
make benchmark ARGS="--case scan-gradle,scan-yarn"
make benchmark ARGS="--repo https://github.com/owner/repo --ecosystem npm"
```

The command reads the embedded scan-target manifest, clones each selected repository default branch, captures its HEAD SHA, and writes artifacts under `.benchmark-runs/latest`. Custom repositories must be public `https://github.com/<owner>/<repo>` URLs and use the default branch.

Each completed comparison preserves raw and ecosystem-filtered SBOMs, a detailed `bomly diff --sbom` artifact, an exact `mismatches.json` classification, and `benchmark-summary.json` files at the source, case, and run levels. Evidence sources contribute to the headline correctness score; observational sources such as Syft contribute raw agreement without being treated as ground truth. Multiple serialization formats from one source family remain visible as separate rows and artifacts but receive one aggregate weight. Correctness excludes only graph extensions backed by explicit evidence: non-registry occurrences identified by Bomly's graph model and target-manifest relationships with mandatory reasons. Raw symmetric agreement remains visible alongside correctness, and every excluded package or edge remains listed in the mismatch artifact. Unadjudicated Bomly-only data and all source-only data continue to reduce evidence-source correctness. Packages without PURLs are reported separately and excluded from scoring. Scores are informational: GitHub SBOM `404` responses and missing Syft executables are recorded as unavailable so other comparisons can continue.

GitHub SBOM requests can be unauthenticated, but local unauthenticated runs quickly hit GitHub's low public API rate limit. The benchmark checks token environment variables in this order:

1. `BOMLY_BENCHMARK_GITHUB_TOKEN`
2. `GITHUB_TOKEN`
3. `GH_TOKEN`

Generate an optional local Copilot report after a benchmark run:

```bash
make benchmark-report
```

This target requires `copilot`, reads `dev-docs/prompts/bomly-benchmark-report.prompt.md`, and writes `.benchmark-runs/latest/benchmark-report.md`. It is not part of CI.

All workflows that build or test Go code use `actions/setup-go` with module and build cache enabled, keyed from `go.sum`, so runners do not need to download the full module set on every run.

The repository pins the Go version in `go.mod`, and CI reads that file directly. That keeps `gofmt`, compilation, and test behavior aligned between local development and GitHub Actions.

For local parity, the Makefile exposes:

- `make fmt` to rewrite tracked Go files with `gofmt`
- `make fmt-check` to fail when tracked Go files are not formatted
- `make lint` to run the repository-pinned `golangci-lint`

The repository also ships a pre-commit hook in `.githooks/pre-commit`. Run `make install-hooks` once per clone to point Git at that hook directory.

## Cost Controls

The per-PR workflow set is intentionally lean so the common path stays fast:

- `golangci-lint` runs as the `lint` job in the `Build & Test` workflow with the official action, pinned to the repository's lint version and using the action's built-in cache.
- Standalone `go vet ./...` is not run separately because `.golangci.yml` already enables `govet`.
- `go test -race` is not enabled because it adds runtime cost and is best reintroduced later if we need the extra concurrency diagnostics.

## Build and Packaging Model

Bomly ships in two modes:

| Artifact     | Default? | Behavior                                                         |
|--------------|----------|------------------------------------------------------------------|
| `bomly`      | Yes      | Full builtin binary with embedded Syft and Grype support         |
| `bomly-lite` | No       | Alternate binary that shells out to `syft` and `grype` on `PATH` |

The source tree treats builtin mode as the default build. That means:

```bash
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

installs the full Bomly experience without extra tags.

The lite build remains available for advanced users and release packaging with:

```bash
go build -tags "bomly_external_syft,bomly_external_grype" -o bin/bomly-lite ./cmd/bomly
```

Release packaging is driven by `.goreleaser.yaml`. The release workflow uses GoReleaser to create:

- A GitHub Release with archives for `bomly` and `bomly-lite`.
- `SHA256SUMS`, keylessly signed with cosign (`SHA256SUMS.sigstore.json`).
- Linux `.deb`, `.rpm`, `.apk`, and Arch Linux package artifacts for the full `bomly` binary.
- Homebrew cask, Scoop, and WinGet manifest pull requests.

## Release Process

1. Merge to `main`.
2. When ready to publish, a maintainer runs the `Auto Version` workflow from `main` and chooses a `patch`, `minor`, or `major` bump.
3. The `Auto Version` workflow updates `cmd/bomly/main.go`, commits the bump, creates a tag such as `v0.2.0`, and starts the `Release` workflow.
4. The `Release` workflow reruns validation, then the `release` job runs GoReleaser.
5. GoReleaser cross-compiles `bomly` and `bomly-lite`, packages archives for:
   - `linux/amd64`
   - `linux/arm64`
   - `darwin/amd64`
   - `darwin/arm64`
   - `windows/amd64`
   - `windows/arm64`
6. GoReleaser generates `SHA256SUMS`, Linux packages, and the cosign signature, then creates the GitHub Release **as a draft** and uploads everything to it.
7. GoReleaser opens or updates package-manager manifest PRs for Homebrew, Scoop, and WinGet (these reference the release's download URLs, which aren't publicly fetchable until the release is published in step 9 — a brief window, typically under a minute).
8. The `provenance` job calls `slsa-github-generator` to generate SLSA provenance (`multiple.intoto.jsonl`) as a workflow artifact. It does **not** upload it to the release itself (`upload-assets: false`) — see the caveat below.
9. The `publish` job downloads that provenance artifact, looks up the draft release **by ID** (listing releases and filtering for the matching tag with `draft == true`, not by tag name), uploads the provenance file to it directly via the GitHub REST API, then flips the release from draft to published, using the configured GoReleaser header plus GitHub-native generated release notes.
10. After the release is published, the `Release lifecycle sync` workflow dispatches the landing-page docs and changelog sync with the published timestamp.

The manual approval point for a release is the `Auto Version` workflow that creates the release tag. The GitHub Release stays a draft until every asset — including SLSA provenance — is attached, then a final job publishes it. This is required by GitHub's [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) feature: once a release is published, no further assets can be added by anyone, so the provenance file (generated by a separate downstream job, by design — see [Supply-Chain Hardening](#supply-chain-hardening-openssf-scorecard)) must land before publish, not after.

**Why the `provenance` job can't upload directly:** GitHub's "get release by tag" API does not return draft releases — they aren't associated with a tag ref until published. The SLSA generator's built-in `upload-assets` option uses `softprops/action-gh-release`, which resolves the target release by tag; against our draft, it finds nothing and **creates a second, non-draft release for the same tag** instead of failing cleanly. That second release immediately and permanently marks the tag as immutable, even if you delete the bad release afterward — there is no way to free the tag back up. (This happened once in production; recovering meant abandoning the tag and cutting a new one.) The `publish` job avoids the whole failure mode by resolving the release by ID itself and never giving any tool a chance to "helpfully" create a duplicate.

## Yanking Releases

Deleting or unpublishing a GitHub Release automatically starts the yanking path in the `Release lifecycle sync` workflow. The workflow dispatches a landing-page removal event so the yanked version is removed from the version selector and changelog.

Package-manager cleanup depends on where the manifest lives. Homebrew and Scoop are maintained as current manifests in `bomly-dev/homebrew-tap` and `bomly-dev/scoop-bucket`, so closing stale package-manager PRs and publishing a replacement release is normally sufficient. WinGet stores versioned manifests in `microsoft/winget-pkgs`, so the workflow also checks for `Bomly.BomlyCLI` under `manifests/b/Bomly/BomlyCLI/<version>`. When that version directory exists, it pushes a deletion branch to `bomly-dev/winget-pkgs` and opens a PR against `microsoft/winget-pkgs:master`.

GoReleaser continues to own normal package-manager publication for new releases. WinGet yanking is handled by the release lifecycle workflow because it is a deletion PR, not a release publication step.

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

Linux package artifacts follow the same `bomly_<version>_<os>_<arch>` prefix with package-manager-specific extensions.

See [Release Checklist](RELEASE_CHECKLIST.md) before running the release workflow.

## Install Script Hosting

The canonical install scripts live in this repository under `scripts/` so changes are reviewed with the CLI release workflow. The public URLs documented for users are:

- `https://bomly.dev/install.sh`
- `https://bomly.dev/install.ps1`

The landing page should serve those files as static assets at the root paths above. Extend the existing release-lifecycle sync in `bomly-landing-page` to copy `scripts/install.sh` and `scripts/install.ps1` from this repo at the published tag. That keeps script content tied to reviewed CLI tags while giving users short, stable install URLs.

## Verification and Integrity

Every release includes `SHA256SUMS` so consumers can verify downloaded assets locally.

Examples:

```bash
sha256sum --check SHA256SUMS
```

```powershell
Get-FileHash .\bomly_v0.2.0_windows_amd64.zip -Algorithm SHA256
```

GitHub-native artifact attestations and image signing are planned. The release workflow is structured so provenance attestation and cosign steps can be added after packaging and before release publication.
