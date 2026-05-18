## How `bundler` resolves

`bundler-detector` is a **lockfile parser** — it reads `Gemfile.lock` directly and produces a full transitive graph with RubyGems names and resolved versions. No subprocess runs.

| Step | Strategy | Command |
| --- | --- | --- |
| Resolve graph | Lockfile parser | None |

## Network behavior

✅ **Fully offline-safe.** Bomly does not invoke Ruby, Bundler, or any other tool to resolve the graph.

## Prerequisites

- A committed `Gemfile.lock`. The detector understands Bundler 1.x, 2.x, and the `Gemfile.next.lock` produced by `bundle update --conservative` workflows.
- No Ruby or Bundler installation is required to scan.
- For `--install-first`: `bundle` on `PATH`.

## `--install-first`

`bundler` does **not** support `--install-first` today. Commit `Gemfile.lock` before scanning, or run `bundle install` yourself.

## Examples

### Fix a direct vulnerability

```ruby
# Gemfile
gem "rails", "~> 7.1.4"
```

`bundle lock --update rails`. Re-scan.

### Pin a transitive vulnerability

Add the transitive gem at the top level so Bundler's resolver picks your version:

```ruby
gem "nokogiri", ">= 1.16.5"
```

`bundle lock --update nokogiri`. Re-scan.

## Reachability

> **Not yet supported.** Bomly has no Ruby reachability analyzer today. `--reachability` produces `not_applicable` for Ruby packages.

## Limitations

- **Local-path gems** (`gem "x", path: "../x"`) are recorded but their internal dependencies come from the local checkout, not RubyGems.
- **Git-sourced gems** (`gem "x", git: "…"`) are tracked by the URL and ref; advisory matching by name still applies but version-range matching may be imprecise for non-semver refs.
- **Platform-specific gems** (e.g. `nokogiri-x86_64-linux`) collapse to the base name; per-platform CVEs are matched against the base name.
- **`*.gemspec`-only projects** (gem libraries with no `Gemfile.lock`) fall back to Syft, which produces a flat package list without edges.
