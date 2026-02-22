# Support Matrix

This document is the canonical support matrix for built-in ecosystem detection in Bomly core.

The current model is split into two groups:

- Native detectors with Bomly-specific execution and parsing logic.
- Third-party-backed detection where Bomly relies on external package cataloging support.

The matrix below is generated from the central support registry in `internal/registry/support.go`.

## Native Detectors

| Ecosystem | Package managers | Detector |
| --- | --- | --- |
| `github-actions` | `github-actions` | Native detector |
| `go` | `gomod` | Native Go detector |
| `maven` | `gradle`, `maven` | Native Maven and Gradle detectors |
| `npm` | `npm`, `pnpm`, `yarn` | Native Node detectors |
| `php` | `composer` | Native detector |
| `python` | `pip`, `pipenv`, `poetry`, `uv` | Native Python detectors |
| `ruby` | `bundler` | Native detector |
| `sbom` | `sbom` | Native SBOM detector |

## Third-Party Support

The entries below are based on external detector support metadata and representative file evidence:

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

- Bomly does not model every Syft cataloger category as a package manager.
- In particular, broad binary catalogers and OS image/package-db-only cases are only surfaced here when they map cleanly into the current Bomly ecosystem/package-manager abstraction.
- The `maven` ecosystem is a shared registry umbrella for both Maven and Gradle in Bomly.

## Syft Container OS Support

These OS families are recorded separately because they describe container base-image detection, not package-manager ecosystems.

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
