# Tutorial: From First Scan to a CI Gate

A start-to-finish walkthrough on a real project: scan it, understand a finding, cut the list down to what matters, accept the existing debt, and wire the gate into CI. Every command below was run against the pinned repository shown, and the output you see is what it printed.

Where [Getting Started](GETTING_STARTED.md) introduces each feature on its own, this page chains them into the workflow you'd actually deploy.

## Prerequisites

- `bomly` on your `PATH` ([Installation](INSTALLATION.md)) — verify with `bomly version`
- `git`
- Network access for the enrichment steps (`--enrich` is the explicit opt-in — see [Network and Privacy](NETWORK.md))

We'll use a deliberately vulnerable demo project maintained by the Bomly org, pinned to a tag so your results match this page:

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/bomly-dev/example-javascript-npm
cd example-javascript-npm
```

## Step 1 — Inventory the project

```bash
bomly scan
```

```text
✓ 136 packages in 1 manifest   (14 direct, 122 transitive · runtime 43, dev 93)

Top-level dependencies
  NAME               VERSION   LICENSE   SCOPE         VULNS
  algo-httpserv      1.1.1     -         runtime       -
  js-yaml            3.13.0    -         runtime       -
  larvitbase         3.1.3     -         runtime       -
  larvitfs           2.3.1     -         runtime       -
  larvitreqparser    0.2.1     -         runtime       -
  larvitrouter       3.0.2     -         runtime       -
  larvitutils        2.3.0     -         runtime       -
  lodash             4.17.15   -         runtime       -
  marked             0.3.19    -         runtime       -
  mocha              7.2.0     -         development   -
  node-yaml-config   0.0.5     -         runtime       -
  semver             5.7.1     -         runtime       -
  to                 0.2.9     -         runtime       -
  url                0.11.0    -         runtime       -
```

Fourteen direct dependencies fan out into 136 packages — the other 122 are transitive, and they're where most surprises live. No network call happened yet: the license and vulnerability columns stay empty until you enrich.

## Step 2 — Ask why a package is there

Pick a package you never installed on purpose. `minimist` is a classic:

```bash
bomly explain minimist
```

```text
ecosystem  npm
manager    npm
package    minimist@0.0.10
scope      runtime
direct     no
introduced by:
  example-javascript-vulnerable-methods@0.0.1
  └─ to@0.2.9
     └─ optimist@0.6.1
        └─ minimist@0.0.10 [analyzed] (transitive)
```

The chain reads bottom-up: removing `minimist@0.0.10` means dealing with `optimist`, which means dealing with the direct dependency `to`. That's the fact you need before filing any upgrade PR. ([explain reference](commands/explain.md))

## Step 3 — Enrich with vulnerability and license data

```bash
bomly scan --enrich
```

```text
✓ 136 packages in 1 manifest   (14 direct, 122 transitive · runtime 43, dev 93)

✓ Enriched via Grype, deps.dev License Matcher

✓ 22 fix suggestions for 22 of 23 vulnerable packages.
  Run again with --format json to see remediation details.

Top-level dependencies
  NAME               VERSION   LICENSE   SCOPE         VULNS
  algo-httpserv      1.1.1     MIT       runtime       1H
  js-yaml            3.13.0    MIT       runtime       1H 1M
  ...
```

Twenty-three vulnerable packages, and a fix exists for all but one. Enrichment sends package coordinates — never your code — to the services listed in [Matchers](MATCHERS.md).

## Step 4 — Turn data into a gate

```bash
bomly scan --enrich --audit --fail-on high
echo $?
```

<details>
<summary>Findings (31 total — first ten shown)</summary>

```text
Findings
  [CRITICAL]  GHSA-cf4h-3jhx-xvhq     underscore@1.9.2
  [CRITICAL]  GHSA-xvch-5gv4-984h     minimist@0.0.10
  [CRITICAL]  GHSA-xvch-5gv4-984h     minimist@1.2.5
  [HIGH]      GHSA-23c5-xmqv-rm74     minimatch@3.0.4
  [HIGH]      GHSA-35jh-r3h4-6jhm     lodash@4.17.15
  [HIGH]      GHSA-3ppc-4f35-3m26     minimatch@3.0.4
  [HIGH]      GHSA-5v2h-r2cx-5xgj     marked@0.3.19
  [HIGH]      GHSA-8j8c-7jfh-h6hx     js-yaml@3.13.0
  [HIGH]      GHSA-cgjv-rghq-qhgp     algo-httpserv@1.1.1
  [HIGH]      GHSA-p6mc-m468-83gw     lodash@4.17.15
```

</details>

The exit code is `2`: at least one finding matched `--fail-on high`. On this project that's 31 findings — too many to fix in one sitting, which is exactly the situation the next two steps are for. ([Auditors](AUDITORS.md), [Exit Codes](EXIT_CODES.md))

## Step 5 — Triage by reachability (experimental)

Which of those 31 findings live in code this app actually imports?

```bash
bomly scan --enrich --audit --analyze --fail-on high --fail-on reachable
```

The two `--fail-on` constraints AND together: a finding now gates only when it is high-or-above **and** reachable. On this project that cuts 31 findings to 16 — for example, `minimist@1.2.5` (pulled in by the dev-only `mocha` toolchain) drops out, while `minimist@0.0.10` on the runtime path stays.

Reachability is experimental, and at package precision "unreachable" means "no import path found", not "safe" — read [Reachability](REACHABILITY.md) before making this your only gate.

## Step 6 — Accept the existing debt

A gate you can't turn on because of old findings protects nothing. Baselines record today's findings so the gate fails only on *new* ones:

```bash
bomly baseline create --enrich
bomly scan --enrich --audit --fail-on high
echo $?   # 0
```

The findings are still reported — their policy status becomes `suppressed` instead of gating. Commit `.bomly/baseline.json` so CI and teammates share the same accepted set, and use `bomly baseline update` / `prune` as debt gets paid down. ([Finding Baselines](BASELINES.md))

## Step 7 — Review changes, not snapshots

For pull requests, compare two states and audit only what changed. The demo repo has two tags to compare:

```bash
bomly diff --url https://github.com/bomly-dev/example-javascript-npm \
  --base v0.9.0 --head v1.0.0 --enrich --audit --fail-on high
echo $?   # 2
```

```text
Version changed (1)
  ~ lodash  4.17.14 → 4.17.15

6 finding(s) persisted.
  persisted  [HIGH]      GHSA-35jh-r3h4-6jhm  lodash@4.17.15
  persisted  [HIGH]      GHSA-p6mc-m468-83gw  lodash@4.17.15
  persisted  [HIGH]      GHSA-r5fr-rjxr-66jc  lodash@4.17.15
  persisted  [MEDIUM]    GHSA-29mw-wpgm-hmr9  lodash@4.17.15
  persisted  [MEDIUM]    GHSA-f23m-r3pf-42rh  lodash@4.17.15
  persisted  [MEDIUM]    GHSA-xxjr-mmjv-4gpg  lodash@4.17.15

✓ 1 fix suggestion for 1 of 1 vulnerable package.
  Run again with --format json to see remediation details.
```

Read this carefully, because it shows both halves of how diff gating works:

- The other 21 vulnerable packages from Step 4 are absent. Diff audits **only the packages the change touched** — untouched debt elsewhere in the repo never blocks a PR.
- The exit code is still `2`. The lodash bump *persisted* three high-severity findings: 4.17.15 still ships them, so the gate correctly refuses to call this upgrade done. The way out is the bump the fix suggestion points at — or an accepted baseline.
- The baseline from Step 6 didn't apply here because diff materializes each side from git: every side uses the baseline **committed at that ref**. Commit `.bomly/baseline.json` and PRs that leave accepted findings untouched pass.

([diff reference](commands/diff.md))

## Step 8 — Put it in CI

The turnkey form for GitHub pull requests is the Guard action — it runs the diff from Step 7 against the PR's merge base and posts the result as a check and an updatable comment:

```yaml
# .github/workflows/bomly.yml
on: pull_request
jobs:
  bomly:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0
      - uses: bomly-dev/bomly-guard@v1
        with:
          fail-on: high
```

Prefer the CLI directly (any CI system), with SARIF for the security tab:

```yaml
- name: Bomly gate
  run: bomly diff --base origin/main --head HEAD --enrich --audit --fail-on high -o sarif=bomly.sarif
- name: Upload SARIF
  if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bomly.sarif
```

Recipes for GitLab, Jenkins, Azure DevOps, and CircleCI live in [CI Integration](CI_INTEGRATION.md); Guard's full input reference in [Bomly Guard](BOMLY_GUARD.md).

## What you built

An inventory you can query (`scan`, `explain`), an enrichment-backed policy gate with a reachability-aware triage path, a committed baseline that separates old debt from new risk, and a PR-level diff gate in CI. From here:

- [Use Cases](USE_CASES.md) — more goal-shaped recipes (licenses, typosquats, containers, SBOMs)
- [Output Formats](OUTPUT_FORMATS.md) — JSON, SARIF, and SBOM artifacts from the same runs
- [Interactive TUI](TUI.md) — explore the same graph with `bomly scan --interactive`
