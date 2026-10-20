# Bomly Guard (GitHub Action)

Bomly Guard is the official GitHub Action around `bomly diff`. It reviews the dependency changes a pull request makes (new packages, new vulnerabilities, license violations, denied packages, suspicious names) and fails the check when they break your policy. This page is for anyone adding Bomly to GitHub pull requests. Source and release notes: [`bomly-dev/bomly-guard`](https://github.com/bomly-dev/bomly-guard).

The action is a thin wrapper. All analysis and the Markdown summary come from `bomly diff`. The action only does the GitHub Actions work:

- installs the CLI;
- works out the PR merge base;
- exposes outputs to later steps;
- writes the job summary;
- optionally posts a PR comment;
- optionally uploads SARIF to the Security tab.

## Quick start

```yaml
name: Bomly Guard

on:
  pull_request:

permissions:
  actions: read            # required for SARIF upload on private repos
  contents: read
  pull-requests: write     # required to post the summary comment (when opted in)
  security-events: write   # required for SARIF upload
  issues: write            # PR summary comments post via the issue-comments API

jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0   # full history so base and head refs resolve
      - uses: bomly-dev/bomly-guard@v1
        with:
          fail-on: high
          comment-summary-in-pr: on-failure
```

`fetch-depth: 0` matters. The action compares the PR head with the PR merge base, so it needs enough history to resolve both. With a shallow checkout the refs may not be reachable.

Pin to a major tag (`@v1`) for automatic patch and minor updates, or to an exact release (`@v1.2.3`) for a fully reproducible build.

## How it works

On a `pull_request` event the action:

1. Installs the Bomly CLI (the `version` input, default `latest`).
2. Resolves the refs: the PR merge base as base, the PR head commit as head.
3. Runs `bomly diff --format json` with the enrich, audit, analyze, and policy flags mapped from the inputs.
4. Renders the Markdown summary and the SARIF file.
5. Writes the job summary, posts or updates the PR comment if enabled, and uploads SARIF if enabled.
6. Exits non-zero when the policy fails, which fails the job.

Only the packages the PR changed are audited. Existing findings on the target branch stay out of the review. A persisted finding on a package the PR did change still counts when it matches the policy. The [diff command](commands/diff.md#audit-the-delta) page explains the rule. Because the engine is the same `bomly diff` you run locally, the policy you enforce on your machine is the policy the action enforces.

When a repository commits `.bomly/baseline.json`, each side of the diff uses the baseline from that Git tree. Matching findings stay in the output with policy status `suppressed` and do not fail the job. See [Finding baselines](BASELINES.md).

## Package manager setup

The action installs the Bomly CLI. It does not install your project's package managers.

Many repositories can be reviewed from committed lockfiles alone. Three detectors (Dart pub, SwiftPM, and SBT) produce richer graphs when their build tool is available, and any detector may need its package manager when the lockfile is not enough or when `install-first` is on. Install the tool with the usual setup action before Bomly Guard:

```yaml
steps:
  - uses: actions/checkout@v5
    with:
      fetch-depth: 0

  - uses: actions/setup-node@v6
    with:
      node-version: 22
      cache: npm

  - uses: bomly-dev/bomly-guard@v1
    with:
      fail-on: high
      install-first: true
```

`install-first: true` passes `--install-first` to `bomly diff`, which tells detectors that support it to install project dependencies before resolving the graph. It does not install the package manager itself. The [Bomly Guard README](https://github.com/bomly-dev/bomly-guard) has the per-ecosystem setup reference.

## Inputs

Inputs map directly onto CLI flags. A comma-separated value becomes repeated flags: `fail-on: high,critical` becomes `--fail-on high --fail-on critical`.

| Input | Default | Maps to / effect |
| --- | --- | --- |
| `version` | `latest` | CLI release to install (`latest`, `v0.4.6`, `0.4.6`) |
| `repo-token` | `${{ github.token }}` | Current-repository API access for PR comments and security checks |
| `cli-repo-token` | `${{ github.token }}` | Token for reading Bomly CLI releases |
| `log-level` | `verbose` | CLI log level: `quiet`, `verbose`, `debug` |
| `base-ref` | inferred | Base Git ref. PRs use the merge base when unset |
| `head-ref` | inferred | Head Git ref. PRs use the PR head SHA when unset |
| `config-file` | | Local config path, or `owner/repo/path@ref` for a file in another repository |
| `external-repo-token` | `repo-token` | Token for a private external config repository |
| `enrich` | `true` | `--enrich`: license and vulnerability enrichment |
| `audit` | `true` | `--audit`: policy evaluation. SARIF is produced only when audit is on |
| `analyze` | `false` | `--analyze`: reachability analysis (see [Reachability](REACHABILITY.md)) |
| `fail-on` | | Repeated `--fail-on` |
| `allow-licenses` | | Repeated `--allow-license` |
| `deny-licenses` | | Repeated `--deny-license` |
| `license-exempt-packages` | | Repeated `--license-exempt-package` (PURLs) |
| `allow-vulnerability-ids` | | Repeated `--allow-vulnerability-id` |
| `deny-packages` | | Repeated `--deny-package` (PURLs) |
| `deny-groups` | | Repeated `--deny-group` (PURL namespaces) |
| `protected-packages` | | Repeated `--protected-package` (typosquat protection) |
| `typosquat-threshold` | | `--typosquat-threshold` |
| `typosquat-mode` | | `--typosquat-mode`: `warn` or `fail` |
| `warn-only` | `false` | `--warn-only`: report failing findings as warnings |
| `ecosystems` | | `--ecosystems` selector |
| `detectors` | | `--detectors` selector |
| `matchers` | | `--matchers` selector |
| `auditors` | | `--auditors` selector |
| `analyzers` | | `--analyzers` selector |
| `install-first` | `false` | `--install-first`: let detectors install project dependencies before resolving. Does not install package managers |
| `install-args` | | Repeated `--install-arg` |
| `comment-summary-in-pr` | `never` | PR comment mode: `never`, `always`, `on-failure` |
| `upload-sarif` | `auto` | SARIF upload: `auto`, `true`, `false` |

The action sets `--format json` itself and renders the Markdown and SARIF outputs, so the job outputs, summary, comment, and upload keep a stable shape. `--format`, `--json`, `--output`, and `--interactive` are therefore not inputs.

For what each flag means, see [Auditors](AUDITORS.md) (`--fail-on`, license and package policy), [Matchers](MATCHERS.md) (`--enrich`), and the [Config reference](CONFIG_REFERENCE.md).

## Outputs

Later steps read each output as `${{ steps.<id>.outputs.<name> }}`:

| Output | Content |
| --- | --- |
| `comment-content` | The Markdown summary |
| `dependency-changes` | All dependency changes, as JSON |
| `vulnerable-changes` | Introduced vulnerability findings, as JSON |
| `invalid-license-changes` | Introduced license findings, as JSON |
| `denied-changes` | Introduced denied-package findings, as JSON |
| `suspicious-package-changes` | Introduced suspicious-name (typosquat) findings, as JSON |
| `sarif-file` | Path to the SARIF file, when audit is on |

Use them for custom follow-up steps, for example failing only on `vulnerable-changes`, or sending `comment-content` to a chat channel.

## PR comments and job summary

The action always writes a job summary. PR comments are controlled by `comment-summary-in-pr`:

| Value | Behavior |
| --- | --- |
| `never` (default) | No comment |
| `always` | Comment on every run |
| `on-failure` | Comment only when a finding fails the review |

Comments go through the issue-comments API, so grant both `pull-requests: write` and `issues: write`. The action updates its existing comment instead of adding a new one on every run.

## SARIF upload

When `audit` is on, the action produces a SARIF file. With `upload-sarif` it sends the file to GitHub code scanning through `github/codeql-action/upload-sarif`, and findings appear under **Security → Code scanning**.

GitHub requires `security-events: write`. Private repositories also need `actions: read` and GitHub Code Security enabled. The default `upload-sarif: auto` skips the upload when those requirements are not met. Bomly's own policy result still decides whether the job passes, so a skipped upload never turns a failing PR into a passing one.

## Configuration files

`config-file` accepts a local path or a reference to a file in another repository, in the form `owner/repo/path@ref`:

```yaml
      - uses: bomly-dev/bomly-guard@v1
        with:
          config-file: my-org/security-policy/bomly.yaml@main
          external-repo-token: ${{ secrets.POLICY_REPO_TOKEN }}
```

External reads use `external-repo-token` when set, otherwise `repo-token`. A shared policy repository lets you enforce one policy across many repositories without copying YAML into each. See the [Config reference](CONFIG_REFERENCE.md) for the file's schema.

## When to call the CLI instead

Bomly Guard covers GitHub pull requests. For anything else (pushes to `main`, scheduled scans, other CI systems, or full control over `bomly scan` and `bomly diff` flags), call the CLI directly. [CI integration](CI_INTEGRATION.md) has recipes for GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI, and pre-commit, including a hand-written `bomly diff` PR gate.

## See also

- [CI integration](CI_INTEGRATION.md) — CLI recipes for every CI system
- [diff command](commands/diff.md) — what the action runs
- [Auditors](AUDITORS.md) — the policy behind `fail-on` and the license and package inputs
- [Reachability](REACHABILITY.md) — what `analyze: true` adds
- [Output formats](OUTPUT_FORMATS.md) — the SARIF and JSON shapes
- [Exit codes](EXIT_CODES.md) — how policy results map to pass and fail
