## What the `package` auditor does

It guards the *identity* of your dependencies rather than their contents. Two checks:

1. **Denylist** — flag any package (or any package in a denied group/namespace) you have decided to ban outright.
2. **Typosquat** — flag packages whose names are suspiciously close to a package you trust, catching `reqeusts`, `loadsh`, or `cross-env`-style lookalikes.

Both checks are name-based, so this auditor needs no enrichment and runs fully offline.

## Options

| Flag | YAML key | Effect |
| --- | --- | --- |
| `--deny-package <name>` | `policy.deny_packages` | Fail when this package is present. Repeatable. |
| `--deny-group <group>` | `policy.deny_groups` | Fail on any package in this group/namespace (e.g. a Maven groupId). Repeatable. |
| `--protected-package <name>` | `policy.protected_packages` | A trusted name; lookalikes within the threshold are flagged as possible typosquats. Repeatable. |
| `--typosquat-threshold <0..1>` | `policy.typosquat_threshold` | Similarity score above which a name is treated as a lookalike. Default `0.90`. Higher = stricter (fewer matches). |
| `--typosquat-mode <warn\|fail>` | `policy.typosquat_mode` | Policy status for a typosquat finding. `warn` (default) records a warning; `fail` makes it eligible to fail when it also matches `--fail-on`. |

`--typosquat-mode` controls only the *policy status* of typosquat findings, not how names are compared. The two accepted values are `warn` (the default) and `fail`. Note that even in `fail` mode a finding still has to match `--fail-on` to change the exit code, so a typical strict gate is `--typosquat-mode fail --fail-on any`.

## Examples

```bash
# Ban a known-bad package
bomly scan --audit --deny-package event-stream --fail-on any

# Ban an entire namespace
bomly scan --audit --deny-group com.evil --fail-on any

# Catch typosquats of the packages you actually depend on, and fail on them
bomly scan --audit \
  --protected-package react --protected-package lodash \
  --typosquat-threshold 0.85 --typosquat-mode fail \
  --fail-on any
```

## Diff and baselines

Under `bomly diff`, the base side of the comparison acts as a trusted baseline for the typosquat check. Bomly seeds the protected-name set with the package names already present in the base graph, and any package whose ID *or* display name already existed in the base is skipped. The practical effect: only **newly introduced** names are typosquat-checked — against both your `--protected-package` list and everything that was already in the tree — so a name that has lived in the project for releases is never flagged, while a freshly added lookalike is. Findings are then classified introduced / resolved / persisted like any other auditor (see [AUDITORS.md](../AUDITORS.md#diff-and-auditing)).

## Limitations

- **Names, not behavior.** This auditor cannot tell whether a package is malicious — only whether its name is denied or resembles a protected one. Pair it with the vulnerability auditor for content risk.
- **Typosquat tuning is a trade-off.** A lower threshold catches more lookalikes but raises false positives on legitimately similar names; tune `--typosquat-threshold` per project.
- **Protected lists are explicit.** Outside of `diff`, Bomly only checks lookalikes against names you pass with `--protected-package`; it does not infer a baseline of "popular" packages.
