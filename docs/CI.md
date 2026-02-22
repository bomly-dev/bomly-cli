# CI and Release Pipeline

Bomly uses GitHub Actions for validation, security analysis, smoke coverage, and release packaging.

## Workflow Overview

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| `CI` | Pull requests, pushes to `main` | Fast validation: tests, build sanity, formatting, module drift, and generated-doc drift |
| `Quality` | Pushes to `main`, manual dispatch | `go vet` plus Linux `go test -race` |
| `CodeQL` | Pull requests, pushes to `main`, weekly schedule | Static analysis for Go |
| `Dependency Review` | Pull requests touching `go.mod` or `go.sum` | Review dependency changes before merge |
| `Smoke` | Merge queue, nightly schedule, manual dispatch | Slow end-to-end coverage against real repositories, SBOMs, and containers before merge, plus scheduled drift detection |
| `Update Smoke Goldens` | Manual dispatch | Regenerate golden files on a chosen ref and open a PR when the changes are intentional |
| `Release` | Semver tags like `v1.2.3` | Cross-platform packaging, checksum generation, and draft GitHub prerelease publication |

## Required Checks

For protected branches, require at least:

- `CI`
- `CodeQL`
- `Dependency Review` when dependency metadata changes
- `Smoke` on merge queue entries

`Quality` is intended for protected-branch hardening on `main`. `Smoke` is intentionally not a per-PR check; it is the slower pre-merge gate for merge queue entries and a nightly health monitor for upstream drift.

## Merge Queue Strategy

Bomly uses a layered merge policy:

- `CI` provides fast feedback on every pull request.
- `Smoke` runs when a change enters the merge queue, which catches end-to-end regressions before merge without slowing every PR update.
- The nightly `Smoke` run remains in place to catch ecosystem drift, container changes, and upstream repository changes that are unrelated to a new pull request.

This split keeps the expensive real-world coverage close to merge time while preserving developer iteration speed.

When `Smoke` fails because golden files drift, the workflow automatically reruns the suite with `-update` and uploads candidate golden files plus a diff artifact. The job still fails so regressions remain visible; the artifact is there to speed up review and intentional golden updates.

After confirming that the failure is expected and not a regression, maintainers can run the `Update Smoke Goldens` workflow. It regenerates `test/smoke/testdata/golden` on the selected ref and opens a pull request only when the regenerated files differ from the committed golden set.

## Build and Packaging Model

Bomly ships in two modes:

| Artifact | Default? | Behavior |
| --- | --- | --- |
| `bomly` | Yes | Full builtin binary with embedded Syft and Grype support |
| `bomly-lite` | No | Alternate binary that shells out to `syft` and `grype` on `PATH` |

The source tree now treats builtin mode as the default build. That means:

```bash
go install github.com/bomly/bomly-cli/cmd/bomly@latest
```

installs the full Bomly experience without extra tags.

The lite build remains available for advanced users and release packaging with:

```bash
go build -tags "bomly_external_syft,bomly_external_grype" -o bin/bomly-lite ./cmd/bomly
```

## Release Process

1. Push a semver tag such as `v0.2.0`.
2. The `Release` workflow reruns validation and then cross-compiles `bomly` and `bomly-lite`.
3. The workflow packages archives for:
   - `linux/amd64`
   - `linux/arm64`
   - `darwin/amd64`
   - `darwin/arm64`
   - `windows/amd64`
   - `windows/arm64`
4. The workflow generates `SHA256SUMS`.
5. The workflow creates a **draft prerelease** in GitHub Releases and uploads all archives plus checksums.

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

GitHub-native artifact attestations are intentionally deferred for now because the repository is private and the current plan assumes private-repo attestations are not available. The release workflow is structured so provenance attestation steps can be added later after packaging and before release publication.
