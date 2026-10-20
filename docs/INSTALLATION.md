# Installation

This page lists every way to install, upgrade, verify, and remove Bomly. Pick the method that matches how you already manage developer tools. If you only want to get started, run one command from the first table and go to [Getting started](GETTING_STARTED.md).

## Install methods

| Method | Platforms | Install | Upgrade | Uninstall |
| --- | --- | --- | --- | --- |
| Homebrew | macOS, Linux | `brew install bomly-dev/tap/bomly` | `brew upgrade bomly` | `brew uninstall bomly` |
| Install script | Linux, macOS | `curl -fsSL https://bomly.dev/install.sh \| sh` | Run the script again | `rm "$(command -v bomly)"` |
| Install script | Windows | `irm https://bomly.dev/install.ps1 \| iex` | Run the script again | Delete `bomly.exe` from `%LOCALAPPDATA%\Bomly\bin` |
| WinGet | Windows | `winget install Bomly.BomlyCLI` | `winget upgrade Bomly.BomlyCLI` | `winget uninstall Bomly.BomlyCLI` |
| Scoop | Windows | `scoop bucket add bomly https://github.com/bomly-dev/scoop-bucket` then `scoop install bomly` | `scoop update bomly` | `scoop uninstall bomly` |
| Linux packages | Debian, Ubuntu, Fedora, RHEL, SUSE, Alpine, Arch | Download the `.deb`, `.rpm`, `.apk`, or `.pkg.tar.zst` from the release and install it with your package manager | Install the newer package | `apt remove bomly`, `rpm -e bomly`, and so on |
| `go install` | Any with Go | `go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest` | Run it again | Delete the binary from `$(go env GOPATH)/bin` |
| Release archive | Linux, macOS, Windows | See [Manual install](#manual-install-from-a-release-archive) | Replace the binary | Delete the binary |

After any install, check the version:

```bash
bomly version
```

Notes on individual methods:

- **Install scripts** download the release archive, verify it against `SHA256SUMS`, and put `bomly` on your `PATH`. On Linux and macOS the default directory is `/usr/local/bin`; set `BOMLY_INSTALL_DIR` to change it. On Windows it is `%LOCALAPPDATA%\Bomly\bin`, which the script adds to your user `PATH`. Set `BOMLY_VERSION=v<version>` to pin a release and `BOMLY_BINARY=bomly-lite` to install the lite binary:

  ```bash
  curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.28.3 sh
  ```

  ```powershell
  $env:BOMLY_VERSION = "v0.28.3"; irm https://bomly.dev/install.ps1 | iex
  ```

- **Linux packages** are built for `amd64` and `arm64`. Install with `sudo dpkg -i`, `sudo rpm -i`, `sudo apk add --allow-untrusted`, or `sudo pacman -U`.
- **`go install`** builds the full binary with Syft and Grype compiled in. It cannot build `bomly-lite`.
- **In CI**, prefer a package manager where available, and pin a release tag rather than `latest`. See [CI integration](CI_INTEGRATION.md).

Bomly writes no configuration or cache during install. To remove its runtime state after uninstalling, delete `~/.bomly` (on Windows, `%USERPROFILE%\.bomly`).

## `bomly` and `bomly-lite`

| Binary | What it is |
| --- | --- |
| `bomly` | The default. Syft and Grype are compiled in, so nothing else is needed |
| `bomly-lite` | A smaller binary that runs the `syft` and `grype` binaries already on your `PATH`. You manage their versions |

Most users want `bomly`. Choose `bomly-lite` only when you already install Syft and Grype yourself. If you do, Anchore's scripts install both:

```bash
curl -sSfL https://get.anchore.io/syft  | sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
```

## Manual install from a release archive

Every release on [GitHub Releases](https://github.com/bomly-dev/bomly-cli/releases) publishes `bomly` and `bomly-lite` archives for Linux, macOS, and Windows, the Linux packages, a `SHA256SUMS` file, its signature, and a provenance file. Archives are named `bomly_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) and contain the binary, `LICENSE`, `NOTICE`, and a `licenses/` directory with third-party license text.

The commands below use release `v0.28.3` on Linux `amd64`. Replace the version and platform with yours.

On Linux or macOS, download the archive and the checksum file, verify, and install:

```bash
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/download/v0.28.3/bomly_0.28.3_linux_amd64.tar.gz
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/download/v0.28.3/SHA256SUMS
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf bomly_0.28.3_linux_amd64.tar.gz
sudo install -m 0755 bomly /usr/local/bin/
```

On macOS, replace the `sha256sum` line with `grep " bomly_0.28.3_darwin_arm64.tar.gz$" SHA256SUMS | shasum -a 256 -c`. A verified archive prints one `OK` line.

On Windows, download, compare the hash, and extract:

```powershell
$archive = "bomly_0.28.3_windows_amd64.zip"
Invoke-WebRequest -Uri "https://github.com/bomly-dev/bomly-cli/releases/download/v0.28.3/$archive" -OutFile $archive
Invoke-WebRequest -Uri "https://github.com/bomly-dev/bomly-cli/releases/download/v0.28.3/SHA256SUMS" -OutFile SHA256SUMS
Get-FileHash .\$archive -Algorithm SHA256   # compare with the matching line in SHA256SUMS
Expand-Archive -Path $archive -DestinationPath .
# Move bomly.exe somewhere on your PATH.
```

## Verify a release

Two more checks prove that a release came from Bomly's own build pipeline.

**The checksum file is signed.** `SHA256SUMS` is signed with [cosign](https://docs.sigstore.dev/cosign/signing/overview/), using a short-lived certificate tied to the GitHub Actions workflow run that built the release. Verify it with:

```bash
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/download/v0.28.3/SHA256SUMS.sigstore.json
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp "^https://github.com/bomly-dev/bomly-cli/.github/workflows/release.yml@.*$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

A valid signature prints `Verified OK`.

**Every artifact has build provenance.** Each release publishes one `multiple.intoto.jsonl` file: a SLSA (Supply-chain Levels for Software Artifacts) Build Level 3 attestation that records which source commit and workflow produced each artifact. Verify an archive against it with [slsa-verifier](https://github.com/slsa-framework/slsa-verifier/releases):

```bash
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/download/v0.28.3/multiple.intoto.jsonl
slsa-verifier verify-artifact bomly_0.28.3_linux_amd64.tar.gz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/bomly-dev/bomly-cli \
  --source-tag v0.28.3
```

[Release assurance](ASSURANCE.md) describes every check a release goes through.

## Next

- [Getting started](GETTING_STARTED.md) — run your first scan
- [CI integration](CI_INTEGRATION.md) — pinned installs for GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI
- [Plugins](PLUGINS.md) — install and enable external components
