# bomly diff

`bomly diff` compares the dependencies of two states (two Git refs, two SBOM files, or two container image tags) and reports what changed. It runs the [scan](scan.md) pipeline on both sides, so the same target flags and pipeline steps apply to each.

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

Besides additions, removals, and version changes, `diff` reports changes to a dependency's relationship (direct or transitive), its source, and whether Bomly can look it up in a registry. These can change your exposure even when no version number moves.

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

Add `--enrich --audit` to classify findings between the two states:

| Class | Meaning |
| --- | --- |
| **introduced** | Present in head, absent in base |
| **resolved** | Present in base, absent in head |
| **persisted** | Present in both |

For example:

```bash
bomly diff --base main --head HEAD --enrich --audit --fail-on high
```

The audit inspects only the packages the change touched. Findings on packages the change did not touch are never reported, so existing problems elsewhere in the repository never block a pull request. Within that scope, `--fail-on` gates on both introduced and persisted findings. A persisted finding means the changed package still has a known issue at its new version, so the gate holds until an upgrade reaches a fixed version or the finding is accepted into a [baseline](../BASELINES.md). See [Auditors](../AUDITORS.md#diff-and-auditing). [Bomly Guard](../BOMLY_GUARD.md) runs exactly this on pull requests and posts the result as a PR comment.

For tooling, ask for JSON:

```bash
bomly diff --base main --head HEAD --enrich --audit --json
```

The JSON shape is documented in the [diff schema](../schemas/diff.md).

## What counts as a change

`diff` compares the resolved graphs, not the manifests. Packages are reported as added, removed, or version-changed. A package can also have a **detail change** without a version change, when the same package occurrence changed in one of these ways:

- its relationship changed between direct, transitive, and unknown;
- its source changed, for example from a registry to Git or a workspace;
- whether Bomly can look it up in a registry changed.

A package can have a version change and a detail change in the same diff. JSON records each detail change as a `transition` under `results.dependencies.transitions` and under the matching manifest. Text, Markdown, the interactive view, and MCP show the same classification.

The human-readable outputs ask for extra review when a known source changes to Git or a URL, or when vulnerability checks covered the package before the change but no longer do. These labels help reviewers find important changes. They do not change the exit code by themselves; only `--fail-on source-change` gates on a source change.

Findings are classified by their advisory and package identity, independent of the version. A finding present on both sides is **persisted**, not one resolved finding plus one introduced finding.

## Exit codes

Same table as every command ([Exit codes](../EXIT_CODES.md)): `2` when an introduced or persisted finding matches `--fail-on`, `3` or `5` when either side fails to resolve or has nothing to evaluate.

## See also

- [scan](scan.md) — the shared target, step, and output flags
- [Bomly Guard](../BOMLY_GUARD.md) — this command as a ready-made GitHub Action
- [Use Cases → Release diff](../USE_CASES.md) — reviewing dependency changes between releases
