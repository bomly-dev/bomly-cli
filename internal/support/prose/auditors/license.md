## What the `license` auditor does

It reads each package's license, parses it as an SPDX expression, and checks it against your allow and deny policy. A package fails policy when its license is denied, or, when an allowlist is set, when its license is not on it. A package with no resolved license can be flagged too, so license gaps do not pass silently.

License data comes from native detection or from a license matcher (deps.dev, ClearlyDefined). Run with `--enrich` when your graph is missing licenses.

## Options

| Flag | YAML key | Effect |
| --- | --- | --- |
| `--allow-license <spdx>` | `policy.allow_licenses` | Permit only these SPDX licenses. Anything else fails. Repeatable. |
| `--deny-license <spdx>` | `policy.deny_licenses` | Fail on these SPDX licenses whatever the allowlist says. Repeatable. |
| `--license-exempt-package <name>` | `policy.license_exempt_packages` | Waive license policy for one package. Repeatable. |

`--allow-license` and `--deny-license` accept SPDX identifiers such as `MIT`, `Apache-2.0`, and `GPL-3.0-only`.

## Examples

```bash
# Permit only permissive licenses
bomly scan --enrich --audit \
  --allow-license MIT --allow-license Apache-2.0 --allow-license BSD-3-Clause \
  --fail-on any

# Block one copyleft license, allow everything else
bomly scan --enrich --audit --deny-license GPL-3.0-only --fail-on any

# Allowlist, but exempt one internal package shipped under a custom license
bomly scan --enrich --audit \
  --allow-license MIT \
  --license-exempt-package my-internal-lib \
  --fail-on any
```

## Limitations

- **SPDX expressions only.** A license string that is not SPDX, such as a raw URL or a custom name, matches no allow or deny identifier. It may appear as a missing or unknown license.
- **One license value is evaluated.** When detection and a matcher disagree, the value on the package is what gets checked. Run with `--enrich` for the most complete coverage.
- **Exemptions are by package name.** A name that exists in several ecosystems is exempted in all of them.
