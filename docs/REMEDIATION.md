# Experimental Remediation Proposals

Bomly can propose locally evidenced dependency upgrades inside the interactive vulnerabilities pane:

```bash
bomly scan --interactive --enrich --experimental-remediate
```

The feature is experimental and opt-in. It proposes candidate versions; it does not edit manifests, install dependencies, or claim that an upgrade has been verified.

## TUI Controls

Open the **Vulnerabilities** tab with `3`. When `--experimental-remediate` is enabled, the pane displays `f fix`. Press `f` to toggle between ordinary vulnerability details and **Proposed Upgrade Paths**.

- Advisory rows show the aggregate proposal for the affected component.
- Component-group rows show the same aggregate proposal.
- Severity and ecosystem groups ask you to select an advisory.
- Switching tabs resets the panel to ordinary vulnerability details.

Without `--experimental-remediate`, the `f` control is hidden and the key is ignored.

## Local-Only Behavior

The proposer reads vulnerability records already attached to the consolidated graph. It does not call matchers, cache readers, HTTP clients, package managers, or subprocesses.

`--enrich` remains required because matchers populate vulnerability metadata during the normal scan pipeline. Enrichment itself may use configured network-backed matchers. Enabling remediation does not add any later API request or retry.

For each vulnerable package, Bomly:

1. Collects `FixedIn` and `FixedVersions` metadata from every attached advisory.
2. Parses the installed version and fix candidates as semver.
3. Chooses the lowest newer fix candidate for each advisory.
4. Chooses the highest of those advisory minima as the component candidate.

If any advisory lacks usable fixed-version metadata, or if semver parsing fails, the panel reports `insufficient_local_data` without a candidate.

## Verification Required

Every proposal reports manifest-constraint compatibility as `unknown`. The consolidated graph does not currently retain portable declared dependency ranges, so Bomly cannot prove that a candidate satisfies the source manifest or lockfile constraints.

Treat the panel as triage guidance:

1. Verify the relevant manifest constraint.
2. Update the direct dependency or dependency override as appropriate.
3. Re-resolve the dependency tree with the package manager.
4. Re-run `bomly scan --enrich`.

Only the follow-up scan can confirm the resulting graph and vulnerability state.

## Limitations

- Only semver-compatible installed versions and fix metadata are supported.
- Missing or malformed fix metadata prevents a proposal for the entire component.
- Transitive dependencies often require upgrading a direct dependency or using an ecosystem-specific override. Bomly does not select that manifest edit automatically.
- A proposed version is local evidence from attached advisories, not a guarantee that no other advisory affects the candidate.
- `bomly_vuln_fix_context` remains the machine-facing MCP remediation surface. `--experimental-remediate` is a TUI-only gate.

## Configuration

The feature can also be enabled in YAML or through the environment:

```yaml
analysis:
  enrich: true
  experimental_remediate: true
output:
  interactive: true
```

```bash
export BOMLY_EXPERIMENTAL_REMEDIATE=true
```

Both `--interactive` and `--enrich` are required.
