# Release Checklist

Use this checklist when publishing a tagged Bomly CLI release.

## Before tagging

- Confirm `main` is green for required checks.
- Confirm release publishing credentials are configured in GitHub Actions.
- `Auto Version` runs the `Release prerequisites` stage (smoke, platform stability, cross-builds, fuzz, catalog) on the commit it is about to tag and refuses to tag when it fails, so there is no separate smoke run to start by hand. To pre-flight without tagging: `gh workflow run assurance-prerequisites.yml -f ref=main`.
- If the stage fails, fix the cause on `main` — for stale golden files, run `Update Smoke Goldens` and merge its PR — then start `Auto Version` again. No tag and no release exist yet.

## Release workflow

- Run `Auto Version` from `main`, choosing `patch`, `minor`, or `major`.
- Wait for `Release` to finish. It builds the draft release, then runs the final pre-release checks against the draft (asset completeness, checksums on three platforms, cosign signature, SLSA provenance, and the released binaries) and only publishes when they pass.
- If the pre-release gate fails, nothing is published. Fix the cause, delete the tag and the draft release, then tag again. Deleting a draft does not trigger the yanking workflow.
- Confirm `cmd/bomly/main.go` contains the intended version.
- Review the published GitHub release:
  - `bomly` archives exist for Linux, macOS, and Windows on `amd64` and `arm64`.
  - `bomly-lite` archives exist for the same platforms.
  - `SHA256SUMS` exists.
  - `.deb`, `.rpm`, `.apk`, and Arch Linux package artifacts exist.
  - Homebrew, Scoop, and WinGet manifest PRs were opened or updated.
  - The landing-page sync PR updates `/install.sh` and `/install.ps1` from this tag when those scripts changed.

## After publishing

- `Release assessment` starts automatically once the release is published: it runs the install scripts on all three operating systems, re-downloads the public files, scans real projects with the released binary, validates its SBOM output with the official tools, and records repeated-scan timings.
- Read the report it publishes at [bomly.dev/assurance](https://bomly.dev/assurance), or the JSON it commits to `docs/assurance/reports/<tag>.json`.
- If it opens a `Release assurance: <tag>` issue, triage it: the release is already live, so the fix is a follow-up release, not an edit to this one.

## Verification

The assessment runs these automatically. Run them by hand when investigating a
report, replacing `VERSION` with the release tag, such as `v0.2.0`.

```bash
gh release download VERSION --pattern SHA256SUMS --pattern 'bomly_VERSION_linux_amd64.tar.gz'
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf bomly_VERSION_linux_amd64.tar.gz bomly
./bomly version
```

If practical, verify package-manager installs in clean runners or VMs. The `bomly-dev/tap` Homebrew reference is managed by GoReleaser through `bomly-dev/homebrew-tap`; no manual tap registration is required during release.

```bash
brew install bomly-dev/tap/bomly
dpkg -i bomly_VERSION_linux_amd64.deb
rpm -i bomly_VERSION_linux_amd64.rpm
apk add --allow-untrusted bomly_VERSION_linux_amd64.apk
```

On Windows, validate:

```powershell
winget install Bomly.BomlyCLI
scoop bucket add bomly https://github.com/bomly-dev/scoop-bucket
scoop install bomly
```

## Publish and rollback

- Merge package-manager PRs after their generated manifests pass review.
- Confirm the landing-page docs sync PR opened.
- If a release must be pulled, delete or unpublish the GitHub Release to trigger the automatic yanking workflow.
- Close Homebrew and Scoop package-manager PRs that reference the bad tag, then tag a replacement patch release when appropriate.
- For WinGet, confirm the release lifecycle workflow either skipped cleanup because no version manifest existed or opened a removal PR against `microsoft/winget-pkgs`.
