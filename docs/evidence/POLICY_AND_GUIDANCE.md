# Policy and vulnerability-guidance evidence

Bomly separates observed evidence from policy decisions:

- enrichment attaches vulnerability and license information to packages;
- analysis can add reachability evidence;
- audit evaluates the available evidence against the selected policy;
- read-only remediation guidance is derived from vulnerability and dependency
  evidence during enrichment.

That separation matters when reviewing results. A vulnerability can be
present but warning-only, suppressed by a baseline, or failing policy.
Reachability is another property of the same vulnerability; it does not
replace severity or policy status.

## Policy cases

| Case | What it checks | Expected outcome |
| --- | --- | --- |
| `vulnerability-policy` | Severity, reachability, known exploitation, advisory allowlists, and repeated constraints | Only findings that satisfy the selected constraints fail |
| `license-policy` | SPDX `AND`, `OR`, nesting, exceptions, custom references, and invalid expressions | Valid expressions keep their Boolean meaning; invalid expressions remain visible and fail |
| `baseline-policy` | Create and automatically use a project finding baseline | The finding remains present with suppressed policy status |
| `source-change-policy` | Same-version move from a registry package to a Git source | Diff requests review; `--fail-on source-change` can fail the audited change |
| `persisted-risk` | Same finding remains across a package version change | The finding is reported as persisted, not hidden as one resolved and one new finding |

Run any case through the public catalog:

```sh
make evidence CASE=license-policy
make evidence CASE=source-change-policy
make evidence CASE=persisted-risk
```

Each command prints the focused test command, the recorded inputs, and the
case limitation.

## Example policy workflow

A team wants high-severity vulnerabilities and risky source changes to block
a pull request while keeping accepted findings visible:

```sh
bomly diff \
  --base main \
  --head HEAD \
  --enrich \
  --audit \
  --fail-on high \
  --fail-on source-change
```

If a package changed from a known registry source to Git or an arbitrary URL,
Bomly explains that registry-based vulnerability matching may no longer cover
it. That is a review signal, not a claim that the change is malicious. Source
formats that cannot prove origin remain unknown.

A finding baseline does not delete matching findings. It changes their policy
status to `suppressed`, so JSON, SARIF, Guard, MCP, and human output can still
show the accepted risk.

## Reachability cases

The catalog includes `reachability-go`, `reachability-node`,
`reachability-python`, and `reachability-java`.

- The Go case records the analyzer and the tier actually returned for each
  vulnerability.
- The JavaScript, Python, and Java cases prove package-tier reachable and
  package-tier unreachable branches.
- Every case keeps the analyzer name, tier, status, and plain-language reason
  with the vulnerability.

These cases use current advisory services, so the checked golden is a dated
observation. Re-running later may legitimately discover added, changed, or
withdrawn advisories.

`unreachable` never means `safe`. Static analysis can miss dynamic loading,
reflection, generated code, tests, build tags, or code paths outside the
analyzer's model. Use reachability to prioritize review, not to erase the
underlying vulnerability.

## Read-only remediation guidance

The `remediation-read-only` case exercises the central remediation component.
For each vulnerable package, it derives:

- whether the available evidence describes a complete fix, partial fix, no
  upstream fix, or an unknown fix state;
- a recommended version only when all vulnerability evidence supports one;
- an occurrence-specific suggested action;
- package-manager advice supplied by the detector when available.

The guidance is derived during enrichment and applies only to vulnerabilities.
License and package-policy findings stay audit results because their meaning
depends on project policy.

Suggestions do not edit manifests, run package managers, or claim that a
change is guaranteed to work. Unknown parents and non-registry occurrences
receive manual-review guidance instead of a guessed parent upgrade.

Reproduce the deterministic derivation matrix:

```sh
make evidence CASE=remediation-read-only
```

## Limits

- `--audit` still requires `--enrich` by default. This avoids an accidental
  audit with fewer findings because matching was forgotten.
- Policy cannot make missing evidence complete. Unknown source, license,
  reachability, or fix data remains unknown.
- Live advisory services can change independently. Bomly does not ship an
  immutable offline advisory snapshot.
- Source changes, reachability, and remediation are different signals. None
  of them alone proves that a dependency is safe or malicious.
- Bomly provides read-only remediation suggestions; it does not apply fixes.
