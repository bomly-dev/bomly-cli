# Support Matrix

This document lists the ecosystems and package managers Bomly can identify today.

It is generated from the canonical support registry in `internal/registry/support.go`.

Bomly groups support into two implementation paths:

- Core detectors implemented directly in Bomly.
- Bundled detectors based on third-party tools that are distributed with Bomly and maintained by the Bomly team.

## Core Detectors

Primary detector files are the preferred inputs for Bomly-owned resolution. Fallback detector files are inputs for the next built-in Bomly detector in the same chain; Syft-only backstops are omitted here and listed under Bundled detectors support.

Some primary detectors execute the ecosystem build tool to recover richer dependency edges than a committed lockfile or manifest can provide. When the tool is not installed or the build-tool command fails, Bomly falls back to the next detector in the chain. For reproducible validation of those richer graphs, make sure the relevant tools are on `PATH` before running smoke tests or the local benchmark.

| Ecosystem | Package managers | Primary detector files | Fallback detector files | Detector |
| --- | --- | --- | --- | --- |
| `cpp` | `conan` | `conan.lock`, `conanfile.txt`, `conanfile.py`, `conaninfo.txt` | - | Native detector |
| `dart` | `pub` | `pubspec.lock`, `pubspec.yaml`, `pubspec.yml` | `pubspec.lock`, `pubspec.yaml`, `pubspec.yml` | Native detector |
| `dotnet` | `nuget` | `packages.lock.json`, `*.deps.json`, `packages.config`, `*.csproj`, `*.fsproj`, `*.vbproj`, `*.vcxproj`, `project.assets.json` | - | Native detector |
| `elixir` | `mix` | `mix.lock`, `mix.exs` | - | Native detector |
| `github-actions` | `github-actions` | `.github/workflows/*.yaml`, `.github/workflows/*.yml`, `.github/actions/*/action.yml`, `.github/actions/*/action.yaml` | - | Native detector |
| `go` | `gomod` | `go.mod` | - | Native Go detector |
| `maven` | `gradle`, `maven` | `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.lockfile*`, `pom.xml`, `*pom.xml` | - | Native Maven and Gradle detectors |
| `npm` | `npm`, `pnpm`, `yarn` | `npm-shrinkwrap.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | `package.json` | Native Node detectors |
| `php` | `composer` | `composer.lock`, `installed.json` | - | Native detector |
| `python` | `pip`, `pipenv`, `poetry`, `uv` | `requirements.txt`, `requirements-dev.txt`, `requirements.in`, `requirements.lock`, `*requirements*.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `uv.lock` | - | Native Python detectors |
| `ruby` | `bundler` | `Gemfile.lock`, `Gemfile.next.lock` | - | Native detector |
| `rust` | `cargo` | `Cargo.lock`, `Cargo.toml` | - | Native detector |
| `sbom` | `sbom` | `*.syft.json`, `*.bom.*`, `*.bom`, `bom`, `*.sbom.*`, `*.sbom`, `sbom`, `*.cdx.*`, `*.cdx`, `*.spdx.*`, `*.spdx` | - | Native SBOM detector |
| `scala` | `sbt` | `build.sbt`, `project/plugins.sbt`, `project/build.properties` | `build.sbt`, `project/plugins.sbt`, `project/build.properties` | Native detector |
| `swift` | `cocoapods`, `swiftpm` | `Podfile.lock`, `Podfile`, `Package.resolved`, `.package.resolved`, `Package.swift`, `project.xcworkspace/xcshareddata/swiftpm/Package.resolved` | `Package.resolved`, `.package.resolved`, `Package.swift`, `project.xcworkspace/xcshareddata/swiftpm/Package.resolved` | Native detector |

## Bundled Detectors

The entries below show Syft-backed ecosystem coverage plus representative files Bomly uses during planning and discovery.

Source: https://oss.anchore.com/docs/capabilities/all-packages/

| Ecosystem | Package managers | Representative file evidence |
| --- | --- | --- |
| `alpm` | `alpm` | `var/lib/pacman/local/*/desc` |
| `apk` | `apk` | `lib/apk/db/installed` |
| `conda` | `conda` | `conda-meta/*.json` |
| `cpp` | `conan` | `conan.lock`, `conanfile.txt`, `conaninfo.txt` |
| `dart` | `pub` | `pubspec.yml`, `pubspec.yaml`, `pubspec.lock` |
| `dotnet` | `nuget` | `packages.lock.json`, `*.deps.json` |
| `dpkg` | `dpkg` | `lib/dpkg/status`, `lib/dpkg/status.d/*`, `lib/opkg/info/*.control`, `lib/opkg/status` |
| `elixir` | `mix` | `mix.lock` |
| `erlang` | `rebar`, `otp` | `rebar.lock`, `*.app` |
| `github-actions` | `github-actions` | `.github/workflows/*.yaml`, `.github/workflows/*.yml`, `.github/actions/*/action.yml`, `.github/actions/*/action.yaml` |
| `go` | `gomod` | `go.mod` |
| `haskell` | `cabal`, `stack` | `cabal.project.freeze`, `stack.yaml`, `stack.yaml.lock` |
| `homebrew` | `homebrew` | `Cellar/*/*/.brew/*.rb`, `Library/Taps/*/*/Formula/*.rb` |
| `lua` | `luarocks` | `*.rockspec` |
| `maven` | `gradle`, `maven` | `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.lockfile*`, `pom.xml`, `*pom.xml` |
| `nix` | `nix` | `nix/var/nix/db/db.sqlite`, `nix/store/*.drv` |
| `npm` | `npm`, `pnpm`, `yarn` | `package-lock.json`, `package.json`, `pnpm-lock.yaml`, `yarn.lock` |
| `ocaml` | `opam` | `*opam` |
| `php` | `composer`, `pear` | `composer.lock`, `installed.json`, `php/.registry/**/*.reg` |
| `portage` | `portage` | `var/db/pkg/*/*/CONTENTS` |
| `prolog` | `swipl-pack` | `pack.pl` |
| `python` | `pip`, `pipenv`, `poetry`, `uv`, `pdm`, `setuppy` | `requirements.txt`, `requirements-dev.txt`, `requirements.in`, `requirements.lock`, `*requirements*.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `uv.lock`, `pdm.lock`, `setup.py` |
| `r` | `r-package` | `DESCRIPTION` |
| `rpm` | `rpm` | `var/lib/rpmmanifest/container-manifest-2`, `var/lib/rpm/Packages`, `var/lib/rpm/Packages.db`, `var/lib/rpm/rpmdb.sqlite`, `usr/share/rpm/Packages`, `usr/share/rpm/Packages.db`, `usr/share/rpm/rpmdb.sqlite`, `usr/lib/sysimage/rpm/Packages`, `usr/lib/sysimage/rpm/Packages.db`, `usr/lib/sysimage/rpm/rpmdb.sqlite` |
| `ruby` | `bundler`, `gemspec` | `Gemfile.lock`, `Gemfile.next.lock`, `*.gemspec` |
| `rust` | `cargo` | `Cargo.lock` |
| `snap` | `snap` | `snap/snapcraft.yaml`, `snap/manifest.yaml`, `doc/linux-modules-*/changelog.Debian.gz`, `usr/share/snappy/dpkg.yaml` |
| `swift` | `cocoapods`, `swiftpm` | `Podfile.lock`, `Package.resolved`, `.package.resolved` |
| `terraform` | `terraform` | `.terraform.lock.hcl` |
| `wordpress` | `wordpress` | `wp-content/plugins/*/*.php` |

## Notes

- Bomly does not expose every Syft cataloger as a package manager.
- Some OS image and binary catalogers are intentionally omitted when they do not map cleanly to Bomly's ecosystem and package-manager model.
- Build-tool-backed detectors currently include Pub (`dart`), SwiftPM (`swift`), and SBT (`sbt`) for richer transitive graph resolution when those tools are available.

## Syft Container OS Support

These OS families are listed separately because they describe container base-image detection rather than language-specific package managers.

Source: https://oss.anchore.com/docs/capabilities/all-os/

| OS family | Syft provider | Version source |
| --- | --- | --- |
| `alpine` | `apk-db-cataloger` | `/etc/os-release` |
| `amazon linux (amzn)` | `rpm-db-cataloger` | `/etc/os-release` |
| `busybox` | `busybox-cataloger` | `busybox binary metadata` |
| `centos` | `rpm-db-cataloger` | `/etc/os-release` |
| `debian` | `dpkg-db-cataloger` | `/etc/os-release` |
| `distroless` | `os-release-cataloger` | `/etc/os-release` |
| `photon` | `rpm-db-cataloger` | `/etc/os-release` |
| `red hat (rhel, ubi)` | `rpm-db-cataloger` | `/etc/os-release` |
| `rocky linux (rocky)` | `rpm-db-cataloger` | `/etc/os-release` |
| `sles (suse, opensuse, opensuse leap)` | `rpm-db-cataloger` | `/etc/os-release` |
| `ubuntu` | `dpkg-db-cataloger` | `/etc/os-release` |
| `wolfi` | `apk-db-cataloger` | `/etc/os-release` |
