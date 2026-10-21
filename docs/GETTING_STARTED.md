# Getting started

This page takes you from installation to a useful first scan in about five minutes. It is for developers and security engineers who have never run Bomly. Each section ends with a link to the page that goes deeper.

## Install

On Linux or macOS:

```bash
curl -fsSL https://bomly.dev/install.sh | sh
```

On Windows:

```powershell
winget install Bomly.BomlyCLI
```

Check that it worked:

```bash
bomly version
```

[Installation](INSTALLATION.md) covers Homebrew, Scoop, Linux packages, `go install`, the smaller `bomly-lite` binary, checksums, and uninstalling.

## Scan a project

Run this from inside any source tree:

```bash
bomly scan
```

Bomly finds every lockfile or manifest in the directory, reads each one with the best available detector, and prints a report. On a small npm project it looks like this:

```text
✓ 68 packages in 1 manifest   (1 direct, 67 transitive · runtime 68, dev 0)

Top-level dependencies
  NAME      VERSION   LICENSE   SCOPE     VULNS
  express   4.19.2    MIT       runtime   -
```

The VULNS column stays empty until you enrich. That is the next section.

Other targets use the same command:

```bash
bomly scan --path ./services/api                                  # another directory
bomly scan --url https://github.com/example/repo --ref v1.2.0     # a Git repository, no manual clone
bomly scan --image ghcr.io/example/app:latest                     # a container image
bomly scan --json                                                 # structured output (same as --format json)
```

[Scan targets](SCAN_TARGETS.md) lists every input, and [Monorepos](MONOREPOS.md) explains `--recursive`.

## Add vulnerability and license data

A plain scan does not contact any vulnerability or license service. Add `--enrich` to look packages up:

```bash
bomly scan --enrich
```

The same project now shows which packages carry advisories and whether fixes exist:

```text
✓ 68 packages in 1 manifest   (1 direct, 67 transitive · runtime 68, dev 0)

✓ Enriched via Grype, deps.dev License Matcher

✓ 7 fix suggestions for 7 of 7 vulnerable packages.
  Run again with --format json to see remediation details.

Top-level dependencies
  NAME      VERSION   LICENSE   SCOPE     VULNS
  express   4.19.2    MIT       runtime   1L
```

By default enrichment uses Grype for vulnerabilities and deps.dev for licenses. [Matchers](MATCHERS.md) lists the optional sources (OSV with the CISA KEV catalog, OpenSSF Scorecard, and plugin matchers) and the cache rules. [Network and privacy](NETWORK.md) lists everything that can reach the network, including the build tools some detectors run.

## Generate an SBOM

Use `-o` to write an SPDX 2.3 or CycloneDX 1.7 Software Bill of Materials (SBOM):

```bash
bomly scan -o spdx=sbom.spdx.json -o cyclonedx=sbom.cdx.json
```

When every `-o` names a file, the run writes the files and prints nothing. Add `--format text` to keep the terminal report. See [SBOM formats](SBOM.md).

## Gate CI on a policy

Add `--audit --fail-on <severity>` to turn findings into an exit code:

```bash
bomly scan --enrich --audit --fail-on high
```

On a project with vulnerable packages the report gains a Findings section and the process exits with code 2:

```text
Findings
  [HIGH]      GHSA-37ch-88jc-xwx2  path-to-regexp@0.1.7
  [HIGH]      GHSA-9wv6-86v2-598j  path-to-regexp@0.1.7
  [HIGH]      GHSA-qwcr-r2fm-qrc7  body-parser@1.20.2
  [HIGH]      GHSA-rhx6-c78j-4q9w  path-to-regexp@0.1.7
```

Exit 0 means no finding matched. Exit 2 means at least one did. [Exit codes](EXIT_CODES.md) lists the rest.

To fail only when a high-or-higher finding is also reachable from your code, add the experimental reachability analysis:

```bash
bomly scan --enrich --audit --analyze --fail-on high --fail-on reachable
```

[Auditors](AUDITORS.md) lists every `--fail-on` value. Read [Reachability](REACHABILITY.md) before you gate CI on it.

## Explain why a package is in the graph

Ask for every path that pulls a package in:

```bash
bomly explain send
```

```text
ecosystem  npm
manager    npm
package    send@0.18.0
scope      runtime
direct     no
licenses
  MIT [declared]
introduced by:
  demo@1.0.0
  └─ express@4.19.2
     ├─ send@0.18.0 [analyzed] (transitive)
     └─ serve-static@1.15.0
        └─ send@0.18.0 [analyzed] (transitive)
```

Bomly prints every path, not only the shortest, so you can see each route you would have to break to remove the package. See the [explain command](commands/explain.md).

## Compare two versions

Compare two Git refs, or two SBOM files:

```bash
bomly diff --base main --head HEAD
bomly diff --sbom --base ./old.spdx.json --head ./new.spdx.json --json
```

Add `--enrich --audit --fail-on high` to gate a pull request. The diff audits only the packages the change touched, so existing findings elsewhere never block a PR. See the [diff command](commands/diff.md).

## What to read next

- [Tutorial](TUTORIAL.md) — the same features chained into a CI gate on a real project
- [Use cases](USE_CASES.md) — recipes for PR gates, SBOMs, triage, licenses, and offline scans
- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [MCP server](MCP.md) — let an AI coding agent call `scan`, `explain`, and `diff`
- [Interactive TUI](TUI.md) — browse a scan with `bomly scan --interactive`
- [CI integration](CI_INTEGRATION.md) — GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI
- [Troubleshooting](TROUBLESHOOTING.md) — common errors and fixes
