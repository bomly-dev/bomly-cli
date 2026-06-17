# Release Checklist

Use this checklist when publishing a tagged Bomly CLI release.

## Before tagging

- Confirm `main` is green for required checks.
- Run the smoke workflow or confirm the latest scheduled smoke result is healthy.
- Confirm `cmd/bomly/main.go` contains the intended version after the `Auto Version` workflow.
- Confirm release secrets are present:
  - `DOCKERHUB_USERNAME`
  - `DOCKERHUB_TOKEN`
  - `TAP_GITHUB_TOKEN`
  - `SCOOP_GITHUB_TOKEN`
  - `WINGET_GITHUB_TOKEN`
  - `RELEASE_BOT_CLIENT_ID` repository variable
  - `RELEASE_BOT_PRIVATE_KEY`

## Release workflow

- Run `Auto Version` from `main`, choosing `patch`, `minor`, or `major`.
- Wait for `Release` to finish.
- Review the draft GitHub release:
  - `bomly` archives exist for Linux, macOS, and Windows on `amd64` and `arm64`.
  - `bomly-lite` archives exist for the same platforms.
  - `SHA256SUMS` exists.
  - `.deb`, `.rpm`, `.apk`, and Arch Linux package artifacts exist.
  - Container images are present on GHCR and Docker Hub.
  - Homebrew, Scoop, and WinGet manifest PRs were opened or updated.

## Verification

Run the checks against the draft release tag before publishing. Replace `VERSION` in the examples below with the actual release tag, such as `v0.2.0`.

```bash
gh release download VERSION --pattern SHA256SUMS --pattern 'bomly_VERSION_linux_amd64.tar.gz'
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf bomly_VERSION_linux_amd64.tar.gz bomly
./bomly version
```

```bash
docker run --rm ghcr.io/bomly-dev/bomly-cli:VERSION version
docker run --rm bomly/bomly-cli:VERSION version
```

If practical, verify package-manager installs in clean runners or VMs. The `bomly-dev/tap` Homebrew reference is managed by GoReleaser through `bomly-dev/homebrew-tap`; no manual tap registration is required during release.

```bash
brew install --cask bomly-dev/tap/bomly
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

- Publish the GitHub draft release after verification.
- Merge package-manager PRs after their generated manifests pass review.
- Confirm the landing-page docs sync PR opened.
- If a release must be pulled, mark the GitHub release as draft again, delete broken container tags if needed, and close package-manager PRs that reference the bad tag.
