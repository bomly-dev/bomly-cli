# Use cases

This page is a set of recipes, one per job people use Bomly for. Each recipe states the goal, the command, what you get back, and where to read more. New to Bomly? Start with [Getting started](GETTING_STARTED.md).

| Goal | Command |
| --- | --- |
| Gate a pull request | `bomly diff --base main --head HEAD --enrich --audit --fail-on high` |
| Generate SBOMs | `bomly scan -o spdx=sbom.spdx.json -o cyclonedx=sbom.cdx.json` |
| Triage by reachability | `bomly scan --enrich --audit --analyze --fail-on high --fail-on reachable` |
| Enforce a license policy | `bomly scan --enrich --audit --allow-license MIT --fail-on any` |
| Catch typosquats and banned packages | `bomly scan --enrich --audit --protected-package react --deny-package event-stream --fail-on any` |
| Scan offline | `bomly scan` |
| Scan a container image | `bomly scan --image ghcr.io/example/app:latest --enrich --audit --fail-on high` |
| Diff two releases | `bomly diff --base v1.2.0 --head v1.3.0 --enrich --audit` |
| Explain a dependency | `bomly explain send` |
| Explore interactively | `bomly scan --enrich --interactive` |

## Gate a pull request on dependency vulnerabilities

**Goal:** fail a PR when its dependency changes carry a high-severity vulnerability, without complaining about packages the PR did not touch.

```bash
bomly diff --base main --head HEAD --enrich --audit --fail-on high
```

**You get:** added, removed, and changed packages, and their findings classified as introduced, resolved, or persisted. Only the packages the change touched are audited, and both introduced and persisted findings gate. The [diff command](commands/diff.md) page explains the classification. Exit code `2` means the change carries a gating finding.

<details>
<summary>Sample output — an <code>express</code> upgrade that drags in one new advisory</summary>

```text
Added (1)
  + encodeurl@2.0.0  MIT      runtime
Version changed (9)
  ~ body-parser        1.20.2 → 1.20.3
  ~ cookie             0.6.0 → 0.7.1
  ~ express            4.19.2 → 4.21.2
  ~ finalhandler       1.2.0 → 1.3.1
  ~ merge-descriptors  1.0.1 → 1.0.3
  ~ path-to-regexp     0.1.7 → 0.1.12
  ~ qs                 6.11.0 → 6.13.0
  ~ send               0.18.0 → 0.19.0
  ~ serve-static       1.15.0 → 1.16.2

1 new finding(s) introduced; 3 finding(s) persisted.
  introduced  [MEDIUM]    GHSA-q8mj-m7cp-5q26  qs@6.13.0
  persisted   [HIGH]      GHSA-37ch-88jc-xwx2  path-to-regexp@0.1.12
  persisted   [MEDIUM]    GHSA-6rw7-vpxm-498p  qs@6.13.0
  persisted   [LOW]       GHSA-w7fw-mjwx-w883  qs@6.13.0

✓ 2 fix suggestions for 2 of 2 vulnerable packages.
  Run again with --format json to see remediation details.
```

With `--fail-on high` this run exits `2`. The introduced finding is only medium, but `path-to-regexp` still has a high-severity issue after the upgrade. The gate holds until a version with the fix, or until the finding is accepted into a committed [baseline](BASELINES.md).

</details>

For GitHub pull requests, the [Bomly Guard action](BOMLY_GUARD.md) runs this command for you and posts the result as a PR comment.

## Generate and publish an SBOM

**Goal:** produce SPDX and CycloneDX SBOMs as build artifacts.

```bash
bomly scan -o spdx=sbom.spdx.json -o cyclonedx=sbom.cdx.json
```

**You get:** both files from one scan. Add `--enrich` when the SBOM is for someone else, because most lockfiles carry no license data. Details and the `-o` rules: [SBOM formats](SBOM.md).

## Triage vulnerabilities by reachability

**Goal:** cut a long advisory list down to the ones your code can reach.

```bash
bomly scan --enrich --audit --analyze --fail-on high --fail-on reachable
```

**You get:** a reachability status on each advisory, and a gate that fails only on advisories that are both high severity and reachable. Reachability is experimental, and "unreachable" is not "safe". Read [Reachability](REACHABILITY.md) before you rely on this gate.

## Enforce a license policy

**Goal:** block dependencies under licenses you cannot ship.

```bash
# Allowlist: permit only these, fail on anything else
bomly scan --enrich --audit \
  --allow-license MIT --allow-license Apache-2.0 --allow-license BSD-3-Clause \
  --fail-on any
```

**You get:** a finding for every package whose license is outside the list. Licenses are matched as SPDX expressions. Use `--deny-license` to block specific licenses instead, and `--license-exempt-package` to skip the check for one package. See the [license auditor](auditors/license.md).

## Catch typosquats and banned packages

**Goal:** flag dependency names that look like packages you trust, or that you have banned.

```bash
bomly scan --enrich --audit \
  --protected-package react --protected-package lodash \
  --typosquat-threshold 0.85 \
  --deny-package event-stream \
  --fail-on any
```

**You get:** a finding for each name close to a protected one, and for each denied package. The check itself only compares names, but `--audit` requires `--enrich`, so this run does contact the enrichment services. See the [package auditor](auditors/package.md).

## Scan offline

**Goal:** analyze dependencies without contacting any service.

```bash
bomly scan                         # no enrichment calls
bomly scan --sbom --path sbom.json # read an SBOM you already have
```

**You get:** the dependency graph with no license or vulnerability data. Without `--enrich` Bomly makes no enrichment calls, but a detector that runs your build tool (Go, Maven, Gradle) may download packages. Commit a lockfile or fill the build tool's cache first to stay fully offline. See [Network and privacy](NETWORK.md).

## Scan and audit a container image

**Goal:** find out what is inside an image and gate on it.

```bash
# Inventory an image (native lockfile detectors in layers + Syft for OS packages)
bomly scan --image ghcr.io/example/app:latest

# Audit an image and fail on high-severity vulnerabilities
bomly scan --image ghcr.io/example/app:latest --enrich --audit --fail-on high

# Generate an SBOM from an image
bomly scan --image ghcr.io/example/app:latest -o spdx=image.spdx.json

# Pin by digest for a reproducible scan
bomly scan --image ghcr.io/example/app@sha256:<digest> --enrich --audit
```

**You get:** every package in the image. Native detectors read the lockfiles they find in the layers, and Syft covers the rest, including operating-system packages. Bomly uses your host's registry credentials (the same ones `docker` and `podman` use), so private images work once you have run `docker login`. See [Scan targets](SCAN_TARGETS.md).

### Gate a base-image upgrade in CI

In a GitHub Actions job, install Bomly and audit the image you just built:

```yaml
steps:
  - name: Install Bomly
    run: curl -fsSL https://bomly.dev/install.sh | sh
  - name: Audit the built image
    run: bomly scan --image ${{ env.IMAGE }}:${{ github.sha }} --enrich --audit --fail-on high --format sarif > image.sarif
```

Exit code `2` fails the job on a policy violation. Upload `image.sarif` to the Security tab as shown in [CI integration](CI_INTEGRATION.md).

## Diff two releases

**Goal:** see what changed in your dependency tree between two versions.

```bash
# Between Git refs
bomly diff --base v1.2.0 --head v1.3.0 --enrich --audit

# Between two SBOM files (no checkout needed)
bomly diff --sbom --base old.spdx.json --head new.spdx.json

# Between two tags (or digests) of the same container image
bomly diff --image ghcr.io/example/app --base 1.4.0 --head 1.5.0 --enrich --audit --fail-on high
```

**You get:** added, removed, and changed dependencies, plus introduced, resolved, and persisted findings when `--audit` is set. Use it for release notes, upgrade reviews, and base-image bumps.

## Understand why a dependency is there

**Goal:** find the path that pulled a transitive package into your build.

```bash
bomly explain send
```

**You get:** every dependency path that introduces the package:

```text
package    send@0.18.0
direct     no
introduced by:
  demo@1.0.0
  └─ express@4.19.2
     ├─ send@0.18.0 [analyzed] (transitive)
     └─ serve-static@1.15.0
        └─ send@0.18.0 [analyzed] (transitive)
```

Add `--enrich --audit` to see the package's findings alongside the paths. Full reference: [explain](commands/explain.md).

## Explore results interactively

**Goal:** browse a scan without parsing JSON.

```bash
bomly scan --enrich --interactive
```

**You get:** a terminal UI with tabs for packages, vulnerabilities, licenses, findings, and dependency paths. Keybindings: [TUI](TUI.md).

## See also

- [CI integration](CI_INTEGRATION.md) — recipes for GitHub Actions, GitLab, Jenkins, Azure DevOps, CircleCI
- [Output formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [Config reference](CONFIG_REFERENCE.md) — every flag, environment variable, and config key
