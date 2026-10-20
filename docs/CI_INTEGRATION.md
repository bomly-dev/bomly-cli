# CI integration

This page gives copy-and-paste recipes for running Bomly in GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, and a pre-commit hook. Read it when you run a CI system other than GitHub pull requests, or when you want full control over the flags. For GitHub pull requests, [Bomly Guard](BOMLY_GUARD.md) does this in one step.

Every recipe follows the same four steps:

1. Install a pinned Bomly version.
2. Run `bomly scan --enrich --audit --fail-on <severity>`.
3. Upload the SBOM and SARIF files, even when the scan fails.
4. Let exit code `2` fail the build. See [Exit codes](EXIT_CODES.md).

| Platform | SARIF display | SBOM artifact | Cache |
| --- | --- | --- | --- |
| GitHub Actions | Security tab, through `upload-sarif` | `upload-artifact` | `actions/cache` on `~/.bomly/cache` and `~/.cache/grype` |
| GitLab CI | Not native | `artifacts`, plus `reports:cyclonedx` for the built-in viewer | Project-local directory, linked to the real cache locations |
| Jenkins | Warnings Next Generation plugin | `archiveArtifacts` | Workspace |
| Azure DevOps | SARIF SAST Scans Tab extension | `PublishBuildArtifacts` | Pipeline caching |
| CircleCI | Not native | `store_artifacts` | `save_cache` on `~/.bomly/cache` and `~/.cache/grype` |

## Install

Prefer a package-manager install where the runner image supports it. Otherwise use the install script with a pinned version. Never rely on `latest` in CI:

```bash
curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.28.3 sh
```

## GitHub Actions

Scan on pushes and pull requests, upload SARIF to the Security tab, and keep the SBOMs as artifacts:

```yaml
name: Bomly

on:
  pull_request:
  push:
    branches: [main]

jobs:
  bomly:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v5

      - name: Install Bomly
        run: curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.28.3 sh

      - name: Scan
        run: |
          bomly scan --enrich --audit --fail-on high \
            --format sarif \
            -o spdx=sbom.spdx.json \
            -o cyclonedx=sbom.cdx.json \
            > bomly.sarif

      - name: Upload SARIF
        if: success() || failure()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: bomly.sarif

      - name: Upload SBOMs
        if: success() || failure()
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.*.json
```

`if: success() || failure()` runs the uploads even when the scan exits `2`.

### Diff against the base branch on pull requests

To audit only what a pull request changed, fetch the base branch and run `bomly diff`:

```yaml
      - name: Diff against main
        if: github.event_name == 'pull_request'
        run: |
          git fetch origin ${{ github.base_ref }}:base
          bomly diff --base base --head HEAD \
            --enrich --audit --fail-on high \
            --json > bomly-diff.json
```

Only the packages the PR touched are audited, so findings elsewhere never fail the job. The [diff command](commands/diff.md#audit-the-delta) page explains which findings gate.

### Cache enrichment data

Bomly keeps enrichment responses under `~/.bomly/cache` and the bundled Grype vulnerability database under the operating system's cache directory (`~/.cache/grype/db` on Linux). Caching both between runs cuts enrichment time from minutes to seconds:

```yaml
      - name: Cache Bomly enrichment data
        uses: actions/cache@v4
        with:
          path: |
            ~/.bomly/cache
            ~/.cache/grype
          key: bomly-${{ runner.os }}-${{ hashFiles('**/go.sum', '**/package-lock.json', '**/pom.xml') }}
          restore-keys: bomly-${{ runner.os }}-
```

Cache lifetimes are listed in [Matchers](MATCHERS.md#cache). A scheduled nightly run on `main` keeps the cache warm for pull request jobs.

### Pull request reviews with Bomly Guard

For GitHub pull requests, the [Bomly Guard action](BOMLY_GUARD.md) wraps `bomly diff --enrich --audit` in one step and posts the result as a PR comment. Its quick start, required permissions, and inputs are on that page. The action installs Bomly, not your package managers; add setup steps such as `actions/setup-node` before it when your project needs them (see [Package manager setup](BOMLY_GUARD.md#package-manager-setup)).

## GitLab CI

Scan, keep the SBOMs as artifacts, and show the CycloneDX SBOM in GitLab's dependency view:

```yaml
bomly:
  image: ubuntu:24.04
  stage: test
  variables:
    XDG_CACHE_HOME: "$CI_PROJECT_DIR/.bomly-cache"   # Grype database goes to .bomly-cache/grype/db
  before_script:
    - apt-get update && apt-get install -y curl ca-certificates
    - curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.28.3 sh
    - mkdir -p "$CI_PROJECT_DIR/.bomly-cache/bomly" ~/.bomly
    - ln -sfn "$CI_PROJECT_DIR/.bomly-cache/bomly" ~/.bomly/cache   # enrichment responses
  script:
    - |
      bomly scan --enrich --audit --fail-on high \
        --format text \
        -o spdx=sbom.spdx.json \
        -o cyclonedx=sbom.cdx.json
  artifacts:
    when: always
    paths:
      - sbom.spdx.json
      - sbom.cdx.json
    reports:
      cyclonedx: sbom.cdx.json
  cache:
    key:
      files:
        - "**/go.sum"
        - "**/package-lock.json"
        - "**/pom.xml"
    paths:
      - .bomly-cache
```

GitLab caches only paths inside the project directory, while Bomly writes enrichment responses to `~/.bomly/cache` and the bundled Grype database to the operating system's cache directory. The recipe points both at `.bomly-cache` inside the project: `XDG_CACHE_HOME` moves the Grype database there, and the symlink moves Bomly's own cache there. Only the OSV, KEV, and Scorecard matchers have a `cache_dir` setting of their own; see the [Config reference](CONFIG_REFERENCE.md).

## Jenkins

Scan, archive the files, and show findings on the build page through the Warnings Next Generation plugin:

```groovy
pipeline {
  agent any
  stages {
    stage('Bomly') {
      steps {
        sh '''
          curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.28.3 sh
          bomly scan --enrich --audit --fail-on high \
            --format sarif \
            -o spdx=sbom.spdx.json \
            -o cyclonedx=sbom.cdx.json \
            > bomly.sarif
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'bomly.sarif, sbom.*.json', fingerprint: true
          recordIssues tools: [sarif(pattern: 'bomly.sarif')]
        }
      }
    }
  }
}
```

## Azure DevOps

Scan and publish the SARIF file. The free SARIF SAST Scans Tab extension shows the results on the build page:

```yaml
steps:
- script: |
    curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.28.3 sh
    bomly scan --enrich --audit --fail-on high --format sarif > bomly.sarif
  displayName: 'Bomly scan'

- task: PublishBuildArtifacts@1
  condition: succeededOrFailed()
  inputs:
    pathToPublish: bomly.sarif
    artifactName: bomly-sarif
```

## CircleCI

Scan with the enrichment cache restored between runs:

```yaml
version: 2.1
jobs:
  bomly:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - restore_cache:
          keys:
            - bomly-cache-v2-{{ checksum "go.sum" }}
            - bomly-cache-v2-
      - run:
          name: Install and scan
          command: |
            curl -fsSL https://bomly.dev/install.sh | BOMLY_VERSION=v0.28.3 sh
            bomly scan --enrich --audit --fail-on high \
              --format text \
              -o spdx=sbom.spdx.json \
              -o cyclonedx=sbom.cdx.json
      - save_cache:
          key: bomly-cache-v2-{{ checksum "go.sum" }}
          paths:
            - ~/.bomly/cache
            - ~/.cache/grype
      - store_artifacts:
          path: sbom.spdx.json
      - store_artifacts:
          path: sbom.cdx.json
```

## Pre-commit hook

Run a scan before every push:

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: bomly
      name: bomly scan
      entry: bomly scan --enrich --audit --fail-on critical --format text
      language: system
      pass_filenames: false
      stages: [pre-push]
```

`pre-push` keeps commits fast. Choose the `--fail-on` level that fits your team.

## Recommendations

- Pin the Bomly version. Use a tagged release or a package-manager version, never `latest`.
- Cache `~/.bomly/cache` and the Grype database directory across runs. The cache lifetimes make this safe.
- Upload the SBOM even when the scan fails. It is a release artifact in its own right.
- Use `bomly diff` on pull requests, so only the packages the PR changes are audited.

## See also

- [Exit codes](EXIT_CODES.md) — what each exit code means in CI
- [Output formats](OUTPUT_FORMATS.md) — SARIF, JSON, and SBOM details
- [Auditors](AUDITORS.md) — `--fail-on` and the policy flags
