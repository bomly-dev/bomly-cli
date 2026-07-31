# bomly diff

Compare dependency state between two points — two Git refs, two SBOM files, or two container image tags — and report what changed. `diff` runs the [scan](scan.md) pipeline against both states, so the same target flags and gates apply to each side.

## Minimal invocation

```bash
bomly diff --base main --head HEAD
```

Comparing two commits where `express` was upgraded:

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
```

Beyond additions, removals, and version changes, `diff` also reports changes to a dependency's relationship (direct vs transitive), source, and registry-matching eligibility — the detail shifts that alter your exposure without a version number moving.

## What to compare

```bash
# Git refs of the current repository (or a remote one via --url)
bomly diff --base main --head HEAD
bomly diff --url https://github.com/owner/repo --base v1.2.0 --head v1.3.0

# Two SBOM files
bomly diff --sbom --base ./before.cdx.json --head ./after.cdx.json

# Two tags or digests of a container image
bomly diff --image alpine --base 3.19 --head 3.20
```

## Audit the delta

Add `--enrich --audit` to classify findings between the two states into three buckets — **introduced** (present in head, absent in base), **resolved** (present in base, absent in head), and **persisted** (present in both):

```bash
bomly diff --base main --head HEAD --enrich --audit --fail-on high
```

The audit only inspects packages the change touched, so unrelated pre-existing debt never appears. Within that scope, `--fail-on` gates on *introduced* **and** *persisted* findings — a persisted finding means the changed package still carries a known issue at its new version, so the gate holds until the bump reaches a fixed version (or the finding is [baselined](../BASELINES.md)). See [Auditors → Diff and auditing](../AUDITORS.md#diff-and-auditing). This is exactly what [Bomly Guard](../BOMLY_GUARD.md) runs on pull requests, with the result rendered as a PR comment.

```bash
bomly diff --base main --head HEAD --json   # structured delta for tooling
```

The JSON shape is documented in the [diff schema](../schemas/diff.md).

## Exit codes

Same table as every command ([Exit Codes](../EXIT_CODES.md)): `2` when an audited head-side finding matches `--fail-on`, `3`/`5` when either side fails to resolve or has nothing to evaluate.

## See also

- [scan](scan.md) — the shared target, gate, and output flags
- [Bomly Guard](../BOMLY_GUARD.md) — this command as a turnkey GitHub Action
- [Use Cases → Release diff](../USE_CASES.md) — reviewing dependency changes between releases
