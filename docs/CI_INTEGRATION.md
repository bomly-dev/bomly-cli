# CI Integration

Drop-in recipes for running Bomly in CI. For Bomly's own CI configuration see [docs/development/CI.md](development/CI.md).

The pattern is the same everywhere: install Bomly, run `bomly scan` with `--audit --fail-on <severity>`, upload the SBOM and SARIF artifacts. Exit code 2 fails the build on policy violation; see [Exit codes](EXIT_CODES.md).

## GitHub Actions

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
      security-events: write   # for SARIF upload
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Install Bomly
        run: |
          curl -sSfL https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_linux_amd64.tar.gz \
            | tar -xz -C /usr/local/bin bomly

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

`if: success() || failure()` ensures SARIF and SBOM uploads run even when the scan exits 2 on policy violation.

### Diff against the base branch on PRs

```yaml
      - name: Diff against main
        if: github.event_name == 'pull_request'
        run: |
          git fetch origin ${{ github.base_ref }}:base
          bomly diff --base base --head HEAD \
            --enrich --audit --fail-on high \
            --json > bomly-diff.json
```

This fails only when the PR **introduces** a new high finding, ignoring pre-existing ones.

### Cache the matcher database

```yaml
      - name: Cache Bomly matcher data
        uses: actions/cache@v4
        with:
          path: ~/.bomly/cache
          key: bomly-${{ runner.os }}-${{ hashFiles('**/go.sum', '**/package-lock.json', '**/pom.xml') }}
          restore-keys: bomly-${{ runner.os }}-
```

Cuts cold-start enrichment time from minutes to seconds. Cache TTLs are listed in [Matchers](MATCHERS.md#cache); a 24h TTL means cache hits stay fresh for a day even if the cache key changes.

### Turnkey PR reviews with the Bomly Guard action

The recipes above call the CLI directly. For GitHub pull requests, the [**Bomly Guard action**](https://github.com/bomly-dev/bomly-guard) wraps the same `bomly diff --enrich --audit` flow into a single step: it installs the CLI, diffs the PR against its base, writes a Markdown job summary (and can post it as a PR comment when you opt in via `comment-summary-in-pr`), and uploads SARIF to the Security tab.

```yaml
name: Bomly Guard

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history so the base and head refs resolve
      - uses: bomly-dev/bomly-guard@v1
        with:
          fail-on: high
          deny-licenses: GPL-3.0-only
          comment-summary-in-pr: on-failure   # opt in: comment only when the review fails
```

The action's inputs map onto the CLI policy flags (`fail-on` → `--fail-on`, `deny-licenses` → `--deny-license`, `protected-packages` → `--protected-package`, and so on), so the policy you enforce locally is the policy it enforces on PRs. See [Bomly Guard](BOMLY_GUARD.md) for the full input and output reference. Bomly dogfoods this action — see the `Bomly Guard` workflow in [docs/development/CI.md](development/CI.md).

## GitLab CI

```yaml
bomly:
  image: ubuntu:24.04
  stage: test
  before_script:
    - apt-get update && apt-get install -y curl ca-certificates
    - curl -sSfL https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_linux_amd64.tar.gz | tar -xz -C /usr/local/bin bomly
  script:
    - bomly scan --enrich --audit --fail-on high
        -o spdx=sbom.spdx.json
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
      - .cache/bomly
```

GitLab natively renders CycloneDX SBOMs in the dependency-scanning panel via the `reports:cyclonedx` key. To point Bomly's cache at the GitLab cache, export `XDG_CACHE_HOME` or configure matcher-specific keys such as `matchers.osv.cache_dir` in `~/.bomly/config.yaml`.

## Jenkins (declarative)

```groovy
pipeline {
  agent any
  stages {
    stage('Bomly') {
      steps {
        sh '''
          curl -sSfL https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_linux_amd64.tar.gz | tar -xz bomly
          ./bomly scan --enrich --audit --fail-on high \
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

`recordIssues` (Warnings Next Generation plugin) ingests SARIF and surfaces findings on the build page.

## Azure DevOps

```yaml
steps:
- script: |
    curl -sSfL https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_linux_amd64.tar.gz | tar -xz -C /usr/local/bin bomly
    bomly scan --enrich --audit --fail-on high --format sarif > bomly.sarif
  displayName: 'Bomly scan'

- task: PublishBuildArtifacts@1
  condition: succeededOrFailed()
  inputs:
    pathToPublish: bomly.sarif
    artifactName: bomly-sarif
```

The free **SARIF SAST Scans Tab** extension renders results on the build page.

## CircleCI

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
            - bomly-cache-v1-{{ checksum "go.sum" }}
            - bomly-cache-v1-
      - run:
          name: Install and scan
          command: |
            curl -sSfL https://github.com/bomly-dev/bomly-cli/releases/latest/download/bomly_linux_amd64.tar.gz | tar -xz -C /tmp bomly
            /tmp/bomly scan --enrich --audit --fail-on high \
              -o spdx=sbom.spdx.json \
              -o cyclonedx=sbom.cdx.json
      - save_cache:
          key: bomly-cache-v1-{{ checksum "go.sum" }}
          paths:
            - ~/.bomly/cache
      - store_artifacts:
          path: sbom.spdx.json
      - store_artifacts:
          path: sbom.cdx.json
```

## Pre-commit hook

For local enforcement:

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: bomly
      name: bomly scan
      entry: bomly scan --audit --fail-on critical --format text
      language: system
      pass_filenames: false
      stages: [pre-push]
```

Tune `--fail-on` to taste. `pre-push` keeps commits fast and only runs on push.

## Recommendations

- **Pin the Bomly version** in CI. Use a tagged release URL, not `latest`.
- **Cache `~/.bomly/cache`** across runs. Matcher TTLs make this safe.
- **Always upload the SBOM** even when the scan fails. The SBOM is a release artifact in its own right.
- **Use `bomly diff` on PRs** to avoid penalizing PRs for pre-existing findings.
- **Pre-warm enrichment on `main`** with a scheduled nightly run so PR jobs start with a warm cache.

## See also

- [Exit codes](EXIT_CODES.md) — what each CI exit means
- [Output formats](OUTPUT_FORMATS.md) — SARIF, JSON, SBOM details
- [Auditors](AUDITORS.md) — `--fail-on`
- [docs/development/CI.md](development/CI.md) — Bomly's own internal CI configuration (not for end users)
