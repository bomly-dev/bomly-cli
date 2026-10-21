## How `bundler` resolves

`bundler-detector` is a **lockfile parser**. It reads `Gemfile.lock` directly and produces a full transitive graph with RubyGems names and resolved versions. No command runs.

| Step | Strategy | Command |
| --- | --- | --- |
| Resolve graph | Lockfile parser | None |

The detector reads one file and runs nothing, so it never uses the network. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- A committed `Gemfile.lock`. The detector understands Bundler 1.x and 2.x, and the `Gemfile.next.lock` that `bundle update --conservative` workflows produce.
- No Ruby or Bundler installation is required to scan.
- For `--install-first`: `bundle` on `PATH`.

## Examples

### Fix a direct vulnerability

Raise the version in the `Gemfile`:

```ruby
gem "rails", "~> 7.1.4"
```

Re-lock with `bundle lock --update rails` and re-scan.

### Pin a transitive vulnerability

Add the transitive gem at the top level so Bundler's resolver picks your version:

```ruby
gem "nokogiri", ">= 1.16.5"
```

Re-lock with `bundle lock --update nokogiri` and re-scan.

## `--install-first`

With `--install-first`, Bomly runs `bundle install` in the project directory before resolving the graph. That downloads gems from RubyGems, or from the sources your `Gemfile` declares, and writes to the configured gem path. Use it on a clean checkout when the lockfile is missing or you want a fresh install:

```bash
bomly scan --install-first
```

To append flags to that command, repeat `--install-arg`. This requires `--detectors bundler-detector`:

```bash
# Production deployment mode: frozen lockfile, no version updates
bomly scan --install-first --detectors bundler-detector \
  --install-arg --deployment --install-arg --without --install-arg development
```

## Source details

Bomly maps the `GEM`, `GIT`, and `PATH` sections in `Gemfile.lock` to registry, Git, and local-file sources. That lets `bomly diff` review a gem that moves to Git.

## Reachability

Bomly has no Ruby reachability analyzer. `--analyze` reports `not_applicable` for Ruby packages.

## Limitations

- **Local-path gems** (`gem "x", path: "../x"`) are recorded, but their dependencies come from the local checkout, not RubyGems.
- **Git-sourced gems** (`gem "x", git: "…"`) are tracked by URL and ref. Advisory matching by name still applies, but version-range matching may be imprecise for refs that are not semver.
- **Platform-specific gems** (for example `nokogiri-x86_64-linux`) collapse to the base name. Per-platform advisories are matched against the base name.
- **Gem libraries with only a `*.gemspec`** and no `Gemfile.lock` fall back to Syft, which produces a flat package list without edges.
