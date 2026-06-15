# Installation

Bomly ships as a single binary. Pick the install method that fits your environment.

## Quick install

```bash
# Go toolchain on PATH
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

Or grab a release archive from [GitHub Releases](https://github.com/bomly-dev/bomly-cli/releases). Verify:

```bash
bomly version
```

If you're ready to scan, jump to [Getting Started](GETTING_STARTED.md).

## Install methods

### `go install`

The most common path for developers who already have Go on `PATH`.

```bash
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

`go install` builds the **full** Bomly binary with builtin Syft and Grype support — no extra binaries required. The command package path follows Go conventions; the installed executable is named `bomly`.

**Requirements**: A Go toolchain compatible with the version declared in `go.mod`. Bomly does not bundle a Go toolchain.

### GitHub Releases

The canonical distribution point for prebuilt packaged binaries. Each release publishes:

- `bomly` archives for Linux, macOS, and Windows.
- `bomly-lite` archives for users who prefer external `syft` and `grype` binaries on `PATH`.
- `SHA256SUMS` for checksum verification.

Each archive also contains `LICENSE`, `NOTICE`, and a `licenses/` directory with the full license text for every bundled dependency.

Archive naming:

- `bomly_<version>_<os>_<arch>.tar.gz`
- `bomly-lite_<version>_<os>_<arch>.tar.gz`
- Windows archives use `.zip`.

#### Linux / macOS

```bash
# Replace VERSION, OS (linux|darwin), ARCH (amd64|arm64)
curl -L -o bomly.tar.gz \
  https://github.com/bomly-dev/bomly-cli/releases/download/VERSION/bomly_VERSION_OS_ARCH.tar.gz
tar -xzf bomly.tar.gz
sudo install -m 0755 bomly /usr/local/bin/
```

Or auto-detect host details:

```bash
curl -L -o bomly.tar.gz \
  https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_$(uname -s)_$(uname -m).tar.gz
tar -xzf bomly.tar.gz
sudo install -m 0755 bomly /usr/local/bin/
```

#### Windows (PowerShell)

```powershell
$archive = "bomly_v0.2.0_windows_amd64.zip"
Invoke-WebRequest -Uri "https://github.com/bomly-dev/bomly-cli/releases/latest/download/$archive" -OutFile $archive
Expand-Archive -Path $archive -DestinationPath .
# Move bomly.exe somewhere on your PATH
```

## `bomly` vs `bomly-lite`

| Artifact | Behavior |
| --- | --- |
| `bomly` | Full default binary with compiled-in Syft and Grype support. No extra runtime dependencies. |
| `bomly-lite` | Alternate binary that shells out to external `syft` and `grype` binaries on `PATH`. Smaller download, requires Syft/Grype installed separately. |

Most users want `bomly`. Pick `bomly-lite` only if you already manage `syft` and `grype` versions across your fleet and want Bomly to ride along on those.

If you choose `bomly-lite`, install Syft and Grype with Anchore's official scripts:

```bash
curl -sSfL https://get.anchore.io/syft  | sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
```

## Verify release checksums

Releases include a `SHA256SUMS` file alongside every archive.

On Linux and macOS:

```bash
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/latest/download/SHA256SUMS
sha256sum --check SHA256SUMS --ignore-missing
```

On PowerShell:

```powershell
Get-FileHash .\bomly_v0.2.0_windows_amd64.zip -Algorithm SHA256
# Compare the printed hash against the line for this archive in SHA256SUMS.
```

## CI installation

For pinned, scripted installs in CI pipelines, see [CI integration](CI_INTEGRATION.md). The most common pattern is:

```bash
curl -sSfL https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_linux_amd64.tar.gz \
  | tar -xz -C /usr/local/bin bomly
```

Pin to a specific release tag rather than `latest` to make scans reproducible.

## Upgrading

`go install` users can re-run the install command to pull the latest tag:

```bash
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

GitHub Release users replace the binary on disk. Check the current version with `bomly version` before and after.

## Uninstall

`go install` writes to `$GOBIN` (defaults to `$GOPATH/bin`). Remove the binary directly:

```bash
rm "$(command -v bomly)"
```

For Release-archive installs, remove the binary from wherever you placed it (typically `/usr/local/bin/bomly`).

Bomly does not write configuration or cache state during install. To also clear runtime state:

```bash
rm -rf ~/.bomly                               # Unix/macOS — config, plugins, cache
Remove-Item -Recurse $env:USERPROFILE\.bomly  # PowerShell
```

## Next

- [Getting Started](GETTING_STARTED.md) — run your first scan in five minutes.
- [CI integration](CI_INTEGRATION.md) — drop-in recipes for GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI.
- [Plugins](PLUGINS.md) — install and enable external detectors, matchers, and auditors.
