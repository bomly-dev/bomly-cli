# Installation

Bomly ships as a release binary, package-manager entry, and Linux package. Pick the method that matches how you normally manage developer tools.

## Quick install

### macOS / Linuxbrew

```bash
brew install --cask bomly-dev/tap/bomly
bomly version
```

### Linux / macOS script

```bash
curl -fsSL https://bomly.dev/install.sh | sh
bomly version
```

### Windows

```powershell
winget install Bomly.BomlyCLI
bomly version
```

If you're ready to scan, jump to [Getting Started](GETTING_STARTED.md).

## Install methods

### Homebrew

Homebrew is the preferred macOS path and also works for Linuxbrew users:

```bash
brew install --cask bomly-dev/tap/bomly
```

Upgrade and uninstall:

```bash
brew upgrade --cask bomly
brew uninstall --cask bomly
```

### WinGet

WinGet is the preferred Windows package-manager path:

```powershell
winget install Bomly.BomlyCLI
```

Upgrade and uninstall:

```powershell
winget upgrade Bomly.BomlyCLI
winget uninstall Bomly.BomlyCLI
```

### Scoop

Scoop is a good fit for Windows developers who already manage CLI tools with buckets:

```powershell
scoop bucket add bomly https://github.com/bomly-dev/scoop-bucket
scoop install bomly
```

Upgrade and uninstall:

```powershell
scoop update bomly
scoop uninstall bomly
```

### Install scripts

The install scripts download a GitHub Release archive, verify it against `SHA256SUMS`, and place `bomly` on your PATH.

Linux / macOS:

```bash
curl -fsSL https://bomly.dev/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://bomly.dev/install.ps1 | iex
```

Pin a version or install the lite binary:

```bash
curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.14.2 sh
curl -fsSL https://bomly.dev/install.sh | BOMLY_BINARY=bomly-lite sh
```

```powershell
$env:BOMLY_VERSION = "v0.14.2"; irm https://bomly.dev/install.ps1 | iex
$env:BOMLY_BINARY = "bomly-lite"; irm https://bomly.dev/install.ps1 | iex
```

By default, Unix installs to `/usr/local/bin`. Set `BOMLY_INSTALL_DIR` to choose another directory. Windows installs to `%LOCALAPPDATA%\Bomly\bin` and adds that directory to the user PATH.

### Linux packages

Each release publishes native package artifacts for Linux `amd64` and `arm64`:

- `.deb` for Debian and Ubuntu families.
- `.rpm` for Fedora, RHEL, Rocky, AlmaLinux, and SUSE families.
- `.apk` for Alpine.
- Arch Linux package artifacts for users who prefer pacman-compatible local packages.

Examples:

```bash
sudo dpkg -i bomly_VERSION_linux_amd64.deb
sudo rpm -i bomly_VERSION_linux_amd64.rpm
sudo apk add --allow-untrusted bomly_VERSION_linux_amd64.apk
sudo pacman -U bomly_VERSION_linux_amd64.pkg.tar.zst
```

Use your package manager's normal remove command to uninstall, for example `sudo apt remove bomly` or `sudo rpm -e bomly`.

### GitHub Releases

GitHub Releases remain the canonical distribution point for all release artifacts. Each release publishes:

- `bomly` archives for Linux, macOS, and Windows.
- `bomly-lite` archives for users who prefer external `syft` and `grype` binaries on `PATH`.
- Linux `.deb`, `.rpm`, `.apk`, and Arch package artifacts.
- `SHA256SUMS` for checksum verification.

Archive naming:

- `bomly_<version>_<os>_<arch>.tar.gz`
- `bomly-lite_<version>_<os>_<arch>.tar.gz`
- Windows archives use `.zip`.

Manual Linux / macOS install:

```bash
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/download/v0.14.2/bomly_v0.14.2_linux_amd64.tar.gz
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/download/v0.14.2/SHA256SUMS
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf bomly_v0.14.2_linux_amd64.tar.gz
sudo install -m 0755 bomly /usr/local/bin/
```

Manual Windows install:

```powershell
$archive = "bomly_v0.14.2_windows_amd64.zip"
Invoke-WebRequest -Uri "https://github.com/bomly-dev/bomly-cli/releases/download/v0.14.2/$archive" -OutFile $archive
Invoke-WebRequest -Uri "https://github.com/bomly-dev/bomly-cli/releases/download/v0.14.2/SHA256SUMS" -OutFile SHA256SUMS
Get-FileHash .\$archive -Algorithm SHA256
Expand-Archive -Path $archive -DestinationPath .
# Move bomly.exe somewhere on your PATH.
```

Each archive also contains `LICENSE`, `NOTICE`, and a `licenses/` directory with third-party license text.

### `go install`

Use this path if you already have Go on `PATH`:

```bash
go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest
```

`go install` builds the full Bomly binary with builtin Syft and Grype support. It does not install `bomly-lite`.

## `bomly` vs `bomly-lite`

| Artifact | Behavior |
| --- | --- |
| `bomly` | Full default binary with compiled-in Syft and Grype support. No extra Syft or Grype binaries required. |
| `bomly-lite` | Alternate binary that shells out to external `syft` and `grype` binaries on `PATH`. Smaller download, but you manage Syft and Grype versions. |

Most users want `bomly`. Pick `bomly-lite` only if you already manage `syft` and `grype` across your fleet.

If you choose `bomly-lite`, install Syft and Grype with Anchore's official scripts:

```bash
curl -sSfL https://get.anchore.io/syft  | sh -s -- -b /usr/local/bin
curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin
```

## Verify release checksums

Releases include `SHA256SUMS` alongside every archive and package.

Linux and macOS:

```bash
curl -L -O https://github.com/bomly-dev/bomly-cli/releases/download/v0.14.2/SHA256SUMS
sha256sum --check SHA256SUMS --ignore-missing
```

PowerShell:

```powershell
Get-FileHash .\bomly_v0.14.2_windows_amd64.zip -Algorithm SHA256
# Compare the printed hash against the matching line in SHA256SUMS.
```

## CI installation

For pinned CI recipes, see [CI integration](CI_INTEGRATION.md). Prefer a package-manager install when your CI environment supports it. If you download archives directly, pin a specific tag rather than `latest`.

## Upgrading

Use the package manager that installed Bomly:

- Homebrew: `brew upgrade --cask bomly`
- WinGet: `winget upgrade Bomly.BomlyCLI`
- Scoop: `scoop update bomly`
- Linux packages: install the newer package artifact with your system package manager.
- Go: re-run `go install github.com/bomly-dev/bomly-cli/cmd/bomly@latest`.
- Install script: re-run the same script, optionally with `BOMLY_VERSION`.

Check the current version before and after:

```bash
bomly version
```

## Uninstall

Use the package manager that installed Bomly. For manual archive or install-script installs, remove the binary from its install directory:

```bash
rm "$(command -v bomly)"
```

Bomly does not write configuration or cache state during install. To also clear runtime state:

```bash
rm -rf ~/.bomly
```

```powershell
Remove-Item -Recurse $env:USERPROFILE\.bomly
```

## Next

- [Getting Started](GETTING_STARTED.md) - run your first scan in five minutes.
- [CI integration](CI_INTEGRATION.md) - drop-in recipes for GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI.
- [Plugins](PLUGINS.md) - install and enable external detectors, matchers, and auditors.
