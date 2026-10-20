## How `github-actions` resolves

`github-actions-detector` is a **manifest parser**. It walks `.github/workflows/*.yml`, `.github/workflows/*.yaml`, and `.github/actions/*/action.yml`, and turns every `uses:` reference into a package node named `owner/repo@ref`. No command runs.

| Step | Strategy | Command |
| --- | --- | --- |
| Resolve graph | YAML parser | None |

The detector reads files and runs nothing, so it never contacts GitHub. See [Network and privacy](../../NETWORK.md) for the shared rule.

## Prerequisites

- A `.github/workflows/` directory with at least one workflow file (`*.yml` or `*.yaml`).
- For composite actions, `.github/actions/<name>/action.yml`. The detector follows nested action references inside the same repository.
- No GitHub CLI or authentication is required.

## Examples

### Fix a vulnerable action

Bump the action version in the workflow file and re-scan:

```yaml
- uses: actions/checkout@v4    # was @v3
```

### Find which workflow introduces an action

```bash
bomly explain actions/checkout
```

## Reference styles

The detector records two kinds of `uses:` reference:

| Reference | Example | How it is matched |
| --- | --- | --- |
| Tag | `uses: actions/checkout@v4` | By name; advisories that apply to a tag range match |
| Commit SHA | `uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29` | Pinned to that commit; advisories that mention the SHA still match |

GitHub's [security hardening guide](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) recommends pinning third-party actions to commit SHAs. Bomly does not enforce that policy itself, but the JSON output exposes the reference type so you can build it into a custom auditor.

## `--install-first`

Not supported. There is nothing to install.

## Reachability

Every referenced action counts as imported. `--analyze` reports `not_applicable` for GitHub Actions.

## Limitations

- **Dynamic references** (for example `uses: ${{ matrix.action }}@v1`) are skipped. The detector needs a static `uses:` string.
- **Reusable workflows** (`uses: ./.github/workflows/x.yml@main`) are recorded as edges. The referenced workflow's own `uses:` entries are only walked when the file is in the same repository.
- **Docker-based actions** (`uses: docker://…`) are recorded with the image reference. Advisory matching uses the image, not the source action repository.
- **Bundled JavaScript dependencies** inside an action's `dist/` directory are not walked. The detector tracks the action repository, not the npm packages inside it.
