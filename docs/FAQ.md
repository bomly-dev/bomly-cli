# FAQ

Short answers to the questions people ask before and shortly after their first scan. For error messages and broken runs, see [Troubleshooting](TROUBLESHOOTING.md) instead — it is organized by symptom and exit code.

## Does Bomly send my code anywhere?

No. A plain `bomly scan` runs entirely against local files and makes no matcher network calls. When you opt in with `--enrich`, Bomly sends package identifiers — name, version, ecosystem, and for Scorecard the source repository URL — to the enrichment services you selected. It never uploads your source code, and the CISA KEV catalog is downloaded as a whole rather than queried per package. See [Matchers → Network endpoints](MATCHERS.md#network-endpoints) and [Architecture → Network behavior](ARCHITECTURE.md#network-behavior) for the complete model, including the separate boundaries for `--url`, build-tool detectors, and `--install-first`.

## Do I need an account, API key, or login?

No. Bomly has no account system, no license key, and no sign-up. Every feature in this documentation works with the binary alone.

## Does Bomly collect telemetry?

No. Bomly sends no usage data, crash reports, or version pings. The only network traffic is what you explicitly trigger (`--enrich`, `--url`, `--image`, `--install-first`, plugin installation).

## How is Bomly different from image scanners like Trivy or Grype?

Different focus. General-purpose scanners are built to cover many target and finding types — container images, IaC misconfigurations, secrets — with vulnerability detection per target. Bomly is built around one thing: the dependency graph. It keeps the full graph so it can answer *why* a package is present (`bomly explain`), *what changed* between two refs or SBOMs (`bomly diff`), and *whether a vulnerability is actually reachable* from your code (`--analyze`), alongside SBOM generation and policy auditing. For container images, Bomly embeds the same Syft technology those tools build on. The tools compose: many teams run an image scanner for images and Bomly for dependency intelligence and PR review.

## Why does my scan show fewer dependencies than I expected?

Bomly resolves the graph from evidence — lockfiles first, then package-manager output, then fallbacks. If a project has no lockfile, the responsible detector may fall back to a coarser source and report a `fallback` warning, which means transitive dependencies can be missing. Check the warnings in the report, commit a lockfile, or use `--install-first` to let the detector materialize one. See [Detectors](DETECTORS.md) and [CI-readiness warnings](CI_READINESS.md).

## Does "unreachable" mean the vulnerability is safe to ignore?

No. Reachability is a triage signal: "unreachable" at package precision means static analysis found no import path, and static analysis cannot see dynamic imports, plugin loaders, or runtime code generation. Use it to prioritize, not to dismiss. Read [Reachability](REACHABILITY.md) — especially ["Unreachable" is not "safe"](REACHABILITY.md#unreachable-is-not-safe) — before gating CI on `--fail-on reachable`.

## Does `--audit` make network calls?

No. `--audit` evaluates the vulnerability and license data already present on packages. Fetching that data is `--enrich`'s job; combine them (`--enrich --audit`) when you want to fetch and evaluate in one run. See [Auditors](AUDITORS.md).

## Why did my scan exit non-zero?

Bomly uses a small, stable set of exit codes: `2` means a finding matched your `--fail-on` policy, while `1`, `3`, `4`, and `5` distinguish execution errors, resolution failures, invalid input, and "nothing to evaluate". [Exit Codes](EXIT_CODES.md) has the full table and CI recipes for branching on them.

## Should I install `bomly` or `bomly-lite`?

`bomly` is the full binary with builtin Syft and Grype — no external tools needed. `bomly-lite` is a smaller download that shells out to `syft` and `grype` on your `PATH`. Both behave the same from the command line. If in doubt, install `bomly`. See [Installation](INSTALLATION.md#bomly-vs-bomly-lite).

## Where are the release notes?

On [GitHub Releases](https://github.com/bomly-dev/bomly-cli/releases). Draft releases are created automatically after merges to `main`, and the documentation site is versioned per release.

## Where do I ask something this page doesn't answer?

[Bomly Discussions](https://github.com/orgs/bomly-dev/discussions) for questions and ideas; this repository's issues for confirmed bugs and actionable work.
