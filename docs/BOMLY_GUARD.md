# Bomly Guard (GitHub Action)

**Bomly Guard** is the official GitHub Action wrapper around `bomly diff`. It reviews the dependency changes a pull request introduces — new packages, new vulnerabilities, license violations, denied packages, suspicious (typosquat) names — and gates the merge on policy.

The action is a thin composite wrapper around the CLI. All dependency analysis and Markdown summary rendering come from `bomly diff`; the action only handles GitHub Actions plumbing: installing the CLI, inferring the PR merge base, exposing outputs, writing the job summary, optionally posting a PR comment, and optionally uploading SARIF to the Security tab.

Source and full reference: [`bomly-dev/bomly-guard`](https://github.com/bomly-dev/bomly-guard).

## Quick start

```yaml
name: Bomly Guard

on:
  pull_request:

permissions:
  actions: read            # required for SARIF upload on private repos
  contents: read
  pull-requests: write     # required to post the summary comment
  security-events: write   # required for SARIF upload
  issues: write

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

`fetch-depth: 0` matters: the action compares the PR head against the PR **merge base**, so it needs enough history to resolve both refs. With a shallow checkout the refs may not be reachable.

Pin to a major tag (`@v1`) for automatic patch and minor updates, or to an exact release (`@v1.2.3`) for fully reproducible builds.

## How it works

On a `pull_request` event the action:

1. Installs the Bomly CLI (`version` input, defaults to `latest`).
2. Resolves the base and head refs. Pull requests default to the PR merge base for the base and the PR head SHA for the head, so review focuses only on what the PR changes — pre-existing findings on the target branch are ignored.
3. Runs `bomly diff --format json` with the enrich/audit/analyze and policy flags mapped from the action inputs.
4. Renders the Markdown summary and SARIF side outputs.
5. Writes the job summary, optionally posts (or updates) a PR comment, and optionally uploads SARIF.
6. Exits non-zero when policy fails the review, failing the job.

Because the engine is the same `bomly diff` you run locally, the policy you enforce on your machine is the policy the action enforces on PRs.

## Inputs

Inputs map directly onto CLI flags. Comma-separated values become repeated flags (for example `fail-on: high,critical` → `--fail-on high --fail-on critical`).

| Input | Default | Maps to / effect |
| --- | --- | --- |
| `version` | `latest` | CLI release to install (`latest`, `v0.4.6`, `0.4.6`). |
| `repo-token` | `${{ github.token }}` | Current-repo API access, PR comments, security checks. |
| `cli-repo-token` | `${{ github.token }}` | Token for reading Bomly CLI releases. |
| `log-level` | `verbose` | CLI log level: `quiet`, `verbose`, `debug`. |
| `base-ref` | inferred | Base git ref. PRs use the merge base when unset. |
| `head-ref` | inferred | Head git ref. PRs use the PR head SHA when unset. |
| `config-file` | | Local config path or `owner/repo/path@ref` external reference. |
| `external-repo-token` | `repo-token` | Token for private external config repositories. |
| `enrich` | `true` | `--enrich` — license and vulnerability enrichment. |
| `audit` | `true` | `--audit` — policy evaluation. SARIF is produced only when audit is on. |
| `analyze` | `false` | `--analyze` — reachability analysis (see [Reachability](REACHABILITY.md)). |
| `fail-on` | | repeated `--fail-on` policy constraints. |
| `allow-licenses` | | repeated `--allow-license`. |
| `deny-licenses` | | repeated `--deny-license`. |
| `license-exempt-packages` | | repeated `--license-exempt-package` (PURLs). |
| `allow-vulnerability-ids` | | repeated `--allow-vulnerability-id`. |
| `deny-packages` | | repeated `--deny-package` (PURLs). |
| `deny-groups` | | repeated `--deny-group` (PURL namespaces). |
| `protected-packages` | | repeated `--protected-package` (typosquat protection). |
| `typosquat-threshold` | | `--typosquat-threshold` similarity value. |
| `typosquat-mode` | | `--typosquat-mode`: `warn` or `fail`. |
| `warn-only` | `false` | `--warn-only` — downgrade failing findings to warnings. |
| `ecosystems` | | `--ecosystems` selector. |
| `detectors` | | `--detectors` selector. |
| `matchers` | | `--matchers` selector. |
| `auditors` | | `--auditors` selector. |
| `analyzers` | | `--analyzers` selector. |
| `install-first` | `false` | `--install-first` — run detector installs before resolving. |
| `install-args` | | repeated `--install-arg`. |
| `comment-summary-in-pr` | `never` | PR comment mode: `never`, `always`, `on-failure`. |
| `upload-sarif` | `auto` | SARIF upload: `auto`, `true`, `false`. |

The action always owns `--format json` and the Markdown/SARIF side outputs so the job outputs, summary, comment, and code-scanning upload stay stable. The CLI flags `--format`, `--json`, `--output`, and `--interactive` are intentionally **not** action inputs.

For the underlying flag semantics, see [Auditors](AUDITORS.md) (`--fail-on`, license and package policy), [Matchers](MATCHERS.md) (`--enrich`), and the [Config Reference](CONFIG_REFERENCE.md).

## Outputs

Each output is available to later steps via `${{ steps.<id>.outputs.<name> }}`:

- `comment-content` — the Markdown summary content.
- `dependency-changes` — all dependency changes as JSON.
- `vulnerable-changes` — introduced vulnerability findings as JSON.
- `invalid-license-changes` — introduced license findings as JSON.
- `denied-changes` — introduced denied-package findings as JSON.
- `suspicious-package-changes` — introduced suspicious (typosquat) findings as JSON.
- `sarif-file` — path to the generated SARIF file (when audit is enabled).

These let you wire custom downstream steps — for example, failing only on `vulnerable-changes`, or forwarding `comment-content` to a chat notification.

## PR comments and job summary

The action always writes a job summary to the workflow run. PR comments are controlled by `comment-summary-in-pr`:

- `never` (default) — no comment.
- `always` — comment on every PR run.
- `on-failure` — comment only when a finding fails the review.

Posting comments requires `pull-requests: write`. The action updates its existing comment in place rather than stacking a new one on every run.

## SARIF upload

When `audit` is enabled the action produces a SARIF file and, with `upload-sarif`, sends it to GitHub code scanning via `github/codeql-action/upload-sarif`. Findings then appear in the repository **Security → Code scanning** tab.

GitHub requires `security-events: write`. Private repositories additionally require `actions: read` and GitHub Code Security enabled. The default `upload-sarif: auto` skips the upload cleanly when those requirements are not met — Bomly's own policy evaluation still determines the final job result, so a missing code-scanning entitlement never silently passes a failing PR.

## Configuration files

`config-file` accepts either a local path or an external reference of the form `owner/repo/path@ref`:

```yaml
      - uses: bomly-dev/bomly-guard@v1
        with:
          config-file: my-org/security-policy/bomly.yaml@main
          external-repo-token: ${{ secrets.POLICY_REPO_TOKEN }}
```

External reads use `external-repo-token` when set, otherwise `repo-token`. A shared policy repo lets you enforce one organization-wide policy across many repositories without copying YAML into each. See the [Config Reference](CONFIG_REFERENCE.md) for the full config schema.

## Action inputs vs. raw CLI

Bomly Guard is the turnkey option for GitHub pull requests. If you need a workflow the action doesn't cover — pushing to `main`, scheduled scans, non-GitHub CI, or full control over `bomly scan`/`bomly diff` flags — call the CLI directly. [CI Integration](CI_INTEGRATION.md) has drop-in recipes for GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI, and pre-commit, including a hand-rolled `bomly diff` PR gate equivalent to what the action automates.

## See also

- [CI Integration](CI_INTEGRATION.md) — CLI recipes for every CI system, including raw `bomly diff` on PRs
- [Auditors](AUDITORS.md) — policy constraints behind `fail-on` and the license/package inputs
- [Reachability](REACHABILITY.md) — what `analyze: true` adds
- [Output Formats](OUTPUT_FORMATS.md) — SARIF and JSON shapes
- [Exit Codes](EXIT_CODES.md) — how policy results map to job pass/fail
- [`bomly-dev/bomly-guard`](https://github.com/bomly-dev/bomly-guard) — action source and release process
