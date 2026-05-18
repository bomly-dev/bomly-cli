## Scan your GitHub Actions workflows

Bomly's `github-actions-detector` walks `.github/workflows/*.yml` and `.github/actions/*/action.yml` and resolves every `uses:` reference to a package node (`owner/repo@ref`). This is how you find supply-chain advisories against the actions your CI relies on.

```bash
bomly scan --path .
```

Add `--enrich` to look up GHSA advisories against pinned actions. Combine with `--audit --fail-on high` to fail CI when a workflow uses an action affected by a known high-severity advisory.

## Prerequisites

- A `.github/workflows/` directory containing at least one workflow YAML file (`*.yml` or `*.yaml`).
- For custom composite actions, `.github/actions/<name>/action.yml`. The detector follows nested action references.
- No GitHub CLI or authentication is required — the YAML files are parsed locally.

## Best practices the detector enforces

The detector treats two `uses:` patterns differently:

- **Tag references** (`uses: actions/checkout@v4`) — resolved by name; advisories applying to a tag range match.
- **Commit SHA references** (`uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29`) — pinned to that exact commit; advisories that mention the SHA still match.

GitHub's [security hardening guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) recommends pinning third-party actions to commit SHAs. Bomly does not enforce the policy itself, but the JSON output exposes the reference type so you can build it into a policy auditor.

## Examples

### Fix a vulnerable action

Bump the action version in the workflow file:

```yaml
- uses: actions/checkout@v4    # was @v3
```

For composite actions, update the SHA pin or version tag inside `.github/actions/<name>/action.yml`.

Re-scan to confirm the finding is gone.

### Scan a single workflow file

Bomly scans the whole `.github/` tree by default. To narrow to one workflow, point `--path` at the file's containing repo and use `bomly explain` to trace which workflow introduced a given action:

```bash
bomly explain actions/checkout
```

## Limitations

- **No reachability analyzer for GitHub Actions.** Every referenced action is treated as "imported"; `--reachability` produces `not_applicable`.
- **Dynamic action references** (e.g. `uses: ${{ matrix.action }}@v1`) are skipped — the detector requires a static `uses:` string.
- **Reusable workflows** (`uses: ./.github/workflows/x.yml@main`) are recorded as edges but the referenced workflow's own `uses:` declarations are only walked when the referenced file is in the same repo.
- **Marketplace actions referenced by Docker image** (`uses: docker://…`) are recorded with the image ref; advisory matching uses the image rather than the source action repo.
- **JavaScript action node-modules** are not recursed into. The detector tracks the action repo, not the npm packages bundled inside its `dist/` directory.
