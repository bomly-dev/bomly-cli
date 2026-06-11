## What the `package` auditor does

It guards the *identity* of your dependencies rather than their contents. Two checks:

1. **Denylist** — flag any package (or any package in a denied group/namespace) you have decided to ban outright.
2. **Typosquat** — flag packages whose names are suspiciously close to a package you trust, catching `reqeusts`, `loadsh`, or `cross-env`-style lookalikes.

Both checks are name-based, so this auditor needs no enrichment and runs fully offline.

## Options

| Flag | Effect |
| --- | --- |
| `--deny-package <name>` | Fail when this package is present. Repeatable. |
| `--deny-group <group>` | Fail on any package in this group/namespace (e.g. a Maven groupId). Repeatable. |
| `--protected-package <name>` | A trusted name; lookalikes within the threshold are flagged as possible typosquats. Repeatable. |
| `--typosquat-threshold <0..1>` | How close a name must be to a protected package to be flagged. Higher = stricter. |
| `--typosquat-mode <mode>` | How names are compared when scoring similarity. |

## Examples

```bash
# Ban a known-bad package
bomly scan --audit --deny-package event-stream --fail-on any

# Ban an entire namespace
bomly scan --audit --deny-group com.evil --fail-on any

# Catch typosquats of the packages you actually depend on
bomly scan --audit \
  --protected-package react --protected-package lodash \
  --typosquat-threshold 0.85 \
  --fail-on any
```

## Limitations

- **Names, not behavior.** This auditor cannot tell whether a package is malicious — only whether its name is denied or resembles a protected one. Pair it with the vulnerability auditor for content risk.
- **Typosquat tuning is a trade-off.** A low threshold catches more lookalikes but raises false positives on legitimately similar names; tune `--typosquat-threshold` per project.
- **Protected lists are explicit.** Bomly only checks lookalikes against names you pass with `--protected-package`; it does not infer a baseline of "popular" packages.
