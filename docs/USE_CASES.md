# Use Cases

Recipes for the jobs people actually use Bomly for. Each one is a goal, the command that does it, what you get back, and where to go deeper. New to Bomly? Start with [Getting Started](GETTING_STARTED.md) first.

## Gate a pull request on dependency vulnerabilities

**Goal:** fail a PR when its dependency changes carry a high-severity vulnerability, without nagging about debt the PR didn't touch.

```bash
bomly diff --base main --head HEAD --enrich --audit --fail-on high
```

`diff` audits only the packages the change touched and classifies their findings as introduced / resolved / persisted, so untouched debt elsewhere in the repo never blocks a PR. Introduced and persisted findings both gate — persisted means the changed package still ships a known issue at its new version. Exit code `2` means the change carries a gating finding; see [Exit codes](EXIT_CODES.md).

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

With `--fail-on high`, this run exits `2`: the introduced finding is only medium, but the persisted high on `path-to-regexp@0.1.12` means the upgrade still ships a known high-severity issue. The gate holds until a bump reaches a fixed version — or the finding is accepted into a committed [baseline](BASELINES.md).

</details>

→ Turnkey version for GitHub PRs: the [Bomly Guard action](https://github.com/bomly-dev/bomly-guard) ([setup](CI_INTEGRATION.md#turnkey-pr-reviews-with-bomly-guard)).

## Generate and publish an SBOM

**Goal:** produce SPDX and CycloneDX SBOMs as build artifacts.

```bash
bomly scan -o spdx=sbom.spdx.json -o cyclonedx=sbom.cdx.json
```

Both files are written in one pass from the same resolved graph, and a successful run prints nothing — add `--format text` if you also want the terminal report in the build log. Use `--format spdx` (or `cyclonedx`) to stream a single SBOM to stdout instead. Details: [SBOM formats](SBOM.md).

## Triage vulnerabilities by reachability

**Goal:** cut a long advisory list down to the ones your code actually calls.

```bash
bomly scan --enrich --audit --analyze --fail-on high --fail-on reachable
```

`--analyze` annotates each advisory with a reachability status; combining `--fail-on high --fail-on reachable` fails only on advisories that are both high severity *and* reachable. Reachability is experimental and tier-dependent — an `unknown` status is not "safe." Read [Reachability](REACHABILITY.md) before relying on this gate.

## Enforce a license policy

**Goal:** block dependencies under licenses you can't ship.

```bash
# Allowlist: permit only these, fail on anything else
bomly scan --enrich --audit \
  --allow-license MIT --allow-license Apache-2.0 --allow-license BSD-3-Clause \
  --fail-on any
```

Licenses are matched as SPDX expressions. Use `--deny-license` to block specific licenses instead of allowlisting, and `--license-exempt-package` to waive one package. See the [license auditor](auditors/license.md).

## Catch typosquats and banned packages

**Goal:** flag dependency names that impersonate packages you trust, or that you've banned outright.

```bash
bomly scan --enrich --audit \
  --protected-package react --protected-package lodash \
  --typosquat-threshold 0.85 \
  --deny-package event-stream \
  --fail-on any
```

The check itself is name-based — no enrichment data feeds it — but the CLI currently requires `--enrich` alongside `--audit`, so this run does contact the enrichment services. See the [package auditor](auditors/package.md).

## Scan offline / air-gapped

**Goal:** analyze dependencies without contacting enrichment services.

```bash
bomly scan                         # matcher network is off; detector behavior varies
bomly scan --sbom --path sbom.json # read an SBOM you already have
```

Without `--enrich`, matchers make **zero** outbound HTTP calls. Note that some build-tool detectors (Go, Maven, Gradle) may fetch packages during normal resolution — pre-warm the local cache or commit a lockfile to stay fully offline. See [Detectors → Network behavior](DETECTORS.md#network-behavior).

## Scan and audit a container image

**Goal:** find what's inside an image and gate on it.

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

Bomly pulls the image using your host's registry credentials — the same ones `docker`/`podman` use — so private images work once you've authenticated (`docker login ghcr.io`). Native detectors still parse lockfiles found in layers; everything else falls through to Syft. See [Scan targets](SCAN_TARGETS.md) for the full container behavior and exit codes.

### Gate a base-image upgrade in CI

```yaml
      - name: Install Bomly
        run: curl -sSfL https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_linux_amd64.tar.gz | tar -xz -C /usr/local/bin bomly
      - name: Audit the built image
        run: bomly scan --image ${{ env.IMAGE }}:${{ github.sha }} --enrich --audit --fail-on high --format sarif > image.sarif
```

Exit code `2` fails the job on a policy violation; upload `image.sarif` to the Security tab as in [CI Integration](CI_INTEGRATION.md).

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

You get added, removed, and updated dependencies, plus introduced, resolved, and persisted findings when `--audit` is set. Great for release notes, upgrade reviews, and catching what a base-image bump dragged in.

## Understand why a dependency is there

**Goal:** find the path that pulled a transitive package into your build.

```bash
bomly explain send
```

`explain` prints every dependency path that introduces the package:

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

Add `--audit` to see findings in that path's context. Full reference: [explain](commands/explain.md).

## Explore results interactively

**Goal:** browse a scan without parsing JSON.

```bash
bomly scan --enrich --interactive
```

Opens the terminal UI to navigate packages, findings, and dependency paths. Keybindings: [TUI](TUI.md).

## See also

- [CI Integration](CI_INTEGRATION.md) — drop-in recipes for GitHub Actions, GitLab, Jenkins, Azure, CircleCI
- [Output Formats](OUTPUT_FORMATS.md) — text, JSON, SARIF, SBOM
- [Config Reference](CONFIG_REFERENCE.md) — every flag, env var, and config key
