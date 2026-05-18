## Scan your Ruby project

Bomly's `bundler-detector` reads `Gemfile.lock` and produces a full transitive graph with RubyGems names and resolved versions. `.gemspec`-only projects fall through to Syft for a flat package list.

```bash
bomly scan --path .
```

## Prerequisites

- A committed `Gemfile.lock` for full transitive resolution. The detector understands Bundler 1.x, 2.x, and the `Gemfile.next.lock` produced by `bundle update --conservative` workflows.
- No Ruby or Bundler installation is required to scan — the lockfile is parsed directly.
- For `--install-first`: `bundle` on `PATH` (Bomly will run `bundle lock` if the lockfile is missing).

## Examples

### Fix a direct vulnerability

Bump in `Gemfile`:

```ruby
gem "rails", "~> 7.1.4"
```

Re-lock: `bundle lock --update rails`. Re-scan.

### Pin a transitive vulnerability

Add the transitive gem at the top level so Bundler's resolver picks your version:

```ruby
gem "nokogiri", ">= 1.16.5"
```

`bundle lock --update nokogiri`. Re-scan.

## Limitations

- **No reachability analyzer for Ruby today.** All vulnerabilities are evaluated by severity only; `--reachability` produces `not_applicable` for Ruby packages.
- **Local-path gems** (`gem "x", path: "../x"`) are recorded but their internal dependencies come from the local checkout, not RubyGems.
- **Git-sourced gems** (`gem "x", git: "…"`) are tracked by the URL and ref; advisories matched by name still apply but version-range matching may be imprecise for non-semver refs.
- **Platforms.** `Gemfile.lock` records platform-specific gems (e.g. `nokogiri-x86_64-linux`). Bomly collapses them by gem name; per-platform CVEs are matched against the base name.
- **`*.gemspec`-only projects** (gem libraries with no `Gemfile.lock`) fall back to Syft, which produces a flat package list without edges.
