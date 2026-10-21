# Tutorial: from first scan to a CI gate

This walkthrough takes a real project from a first scan to a pull request gate in CI: scan it, understand a finding, cut the list down to what matters, accept the existing findings, and wire the gate into CI. Every command was run against the pinned repository shown, and the output is what it printed.

[Getting started](GETTING_STARTED.md) shows each feature on its own. This page combines them into the workflow you would deploy.

## Prerequisites

- `bomly` on your `PATH` ([Installation](INSTALLATION.md)); check with `bomly version`
- `git`
- Network access for the enrichment steps ([Network and privacy](NETWORK.md) lists what `--enrich` contacts)

The project is a deliberately vulnerable demo maintained by the Bomly organization, pinned to a tag so the dependency graph you scan matches this page. The outputs were captured with Bomly 0.20.2 on 2026-07-30. The package counts are stable, but advisory counts and IDs may differ on your run because vulnerability databases change:

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/bomly-dev/example-javascript-npm
cd example-javascript-npm
```

## Step 1: inventory the project

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

Fourteen direct dependencies pull in 136 packages. The other 122 are transitive, and most problems come from those. No network call happened yet: the license and vulnerability columns stay empty until you enrich.

## Step 2: ask why a package is there

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

Read the chain from the bottom: to remove `minimist@0.0.10` you have to deal with `optimist`, and for that with the direct dependency `to`. That is the fact you need before you file an upgrade PR. ([explain reference](commands/explain.md))

## Step 3: add vulnerability and license data

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

Twenty-three vulnerable packages, and a fix exists for all but one. Enrichment sends package names and versions, never your code, to the services listed in [Matchers](MATCHERS.md).

## Step 4: turn data into a gate

```bash
bomly scan --enrich --audit --fail-on high
echo $?
```

<details>
<summary>Findings (31 rows: 25 gating vulnerabilities + 6 license warnings — first ten shown)</summary>

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

The exit code is `2`: at least one finding matched `--fail-on high`. The report lists 31 findings of two kinds. Twenty-five are vulnerability findings that gate. Six are license warnings (`[WARNING] UNKNOWN-…` rows further down, for packages whose license could not be determined) that inform but never gate. Twenty-five gating findings is too many to fix at once, which is what the next two steps are for. ([Auditors](AUDITORS.md), [Exit codes](EXIT_CODES.md))

## Step 5: triage by reachability (experimental)

Which of those 25 gating findings live in code this app actually imports?

```bash
bomly scan --enrich --audit --analyze --fail-on high --fail-on reachable
```

Both conditions must hold: a vulnerability finding now gates only when it is high or above **and** reachable. On this project that cuts the gating findings from 25 to 10 (the report shows 16 rows, because the 6 license warnings are unaffected). For example, `minimist@1.2.5`, pulled in by the dev-only `mocha` toolchain, drops out, while `minimist@0.0.10` on the runtime path stays.

Reachability is experimental. For these analyzers "unreachable" means "no import path found", not "safe". Read [Reachability](REACHABILITY.md) before you make this your only gate.

## Step 6: accept the existing findings

A gate you cannot turn on because of old findings protects nothing. A baseline records today's findings so the gate fails only on new ones:

```bash
bomly baseline create --enrich
bomly scan --enrich --audit --fail-on high
echo $?   # 0
```

The findings are still reported, but their policy status becomes `suppressed` instead of gating. Commit `.bomly/baseline.json` so CI and teammates share the same accepted set. Use `bomly baseline update` and `prune` as you fix findings. This tutorial does not commit the file yet, which matters in the next step. ([Finding baselines](BASELINES.md))

## Step 7: review changes, not snapshots

For pull requests, compare two states and audit only what changed. The demo repo has two tags to compare:

```bash
bomly diff --url https://github.com/bomly-dev/example-javascript-npm \
  --base v0.9.0 --head v1.0.0 --enrich --audit --fail-on high
echo $?   # 2
```

```text
Version changed (1)
  ~ lodash  4.17.14 → 4.17.15

3 finding(s) persisted.
  persisted  [HIGH]      GHSA-35jh-r3h4-6jhm  lodash@4.17.15
  persisted  [HIGH]      GHSA-p6mc-m468-83gw  lodash@4.17.15
  persisted  [HIGH]      GHSA-r5fr-rjxr-66jc  lodash@4.17.15

✓ 1 fix suggestion for 1 of 1 vulnerable package.
  Run again with --format json to see remediation details.
```

(`--fail-on high` also filters the findings shown. Drop it to see this bump's three medium-severity persisted advisories as well.)

This output shows the two halves of diff gating:

- The other 22 vulnerable packages from Step 3 are absent. Diff audits only the packages the change touched, so existing findings elsewhere in the repository never block a PR.
- The exit code is still `2`. The lodash bump kept three high-severity findings alive: 4.17.15 still ships them, so the gate refuses to call this upgrade done. The way out is the version the fix suggestion names, or an accepted baseline.
- The baseline from Step 6 did not apply, because you never committed it. Diff reads each side from Git, so each side uses the baseline committed at that ref. Commit `.bomly/baseline.json`, and PRs that leave accepted findings untouched pass.

([diff reference](commands/diff.md))

## Step 8: put it in CI

For GitHub pull requests, the Guard action runs the diff from Step 7 against the PR's merge base and posts the result as a check and a PR comment:

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

On any CI system you can call the CLI directly, here with SARIF for the security tab:

```yaml
- name: Bomly gate
  run: bomly diff --base origin/main --head HEAD --enrich --audit --fail-on high -o sarif=bomly.sarif
- name: Upload SARIF
  if: success() || failure()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: bomly.sarif
```

[CI integration](CI_INTEGRATION.md) has recipes for GitLab, Jenkins, Azure DevOps, and CircleCI. [Bomly Guard](BOMLY_GUARD.md) has the action's inputs.

## What you built

- An inventory you can query with `scan` and `explain`.
- A policy gate on enriched data, with reachability to triage it.
- A baseline that separates old findings from new risk.
- A PR-level diff gate in CI.

From here:

- [Use cases](USE_CASES.md) — recipes for licenses, typosquats, containers, and SBOMs
- [Output formats](OUTPUT_FORMATS.md) — JSON, SARIF, and SBOM output from the same runs
- [Interactive TUI](TUI.md) — explore the same graph with `bomly scan --interactive`
