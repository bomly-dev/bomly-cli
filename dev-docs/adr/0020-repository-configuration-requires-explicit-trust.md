# ADR-0020: Repository configuration requires explicit trust; baselines are the one auto-discovered repository input

- **Date:** 2026-07-25
- **Revised:** 2026-10-25 (folds ADR-0003 and ADR-0019; adds plugin access disclosure)
- **Status:** Accepted

## Context

A configuration file can select a target, enable network enrichment, run
package managers, load plugins and choose output paths. Loading one because
it sits inside the checkout being scanned would let the checkout grant
itself those permissions. Finding baselines also live in the repository, and
users expect them to apply without flags. A managed plugin runs with the
user's authority, so enabling one is the user's trust decision.

## Decision

- Bomly loads the user-controlled `~/.bomly/config.yaml` automatically and
  never loads `.bomly/config.yaml` from a scan target. `--config` or
  `BOMLY_CONFIG` opts in; the flag wins when both are set; the selected file
  must exist and be a regular file.
- YAML files are nested (`target`, `analysis`, `policy`, `network.proxy`,
  `matchers.osv`); the runtime `Resolved` struct stays flat and each leaf
  maps to one field. Unknown keys and the former flat keys fail with
  migration guidance, so a typo cannot silently disable requested behavior.
- A finding baseline is auto-discovered because its contract is narrow: a
  versioned document keyed by PURL, finding kind, auditor and advisory
  aliases or rule ID, portable across projects, able to change a finding's
  policy status and nothing else. It cannot select targets, start network or
  package-manager activity, load plugins or choose output paths. A symbolic
  link at `.bomly` or the baseline file is ignored with a warning; an
  explicit baseline path is trusted user input.
- Policy-status resolution runs inside the audit stage. After deduplication
  and warn-only handling, neutral `FindingPolicyResolver` implementations
  may replace a finding's status but cannot remove or mutate evidence; when
  several participate, the least suppressive decision wins. No
  baseline-specific stage or output model exists: a suppressed finding is an
  ordinary finding with `policy_status: suppressed`.
- A managed plugin's manifest `access` block is the publisher's unverified
  claim, shown at install (the plugin starts disabled) and in `plugins info`;
  `plugins enable` shows it but asks for no confirmation. It is never
  enforced. An absent block means unknown, never "needs no access".

## Rejected

Auto-loading repository configuration behind an allowlist of safe keys (the
allowlist becomes the attack surface); a separate baseline pipeline stage;
enforcing declared plugin access, which needs a sandbox, when a declaration
is not evidence of behavior.

## Consequences

- CI that wants repository configuration states it once on the command line.
- Baseline selection is visible in logs and run statistics.

Enforced by: `internal/config/validate_test.go`; the symlink tests in
`internal/baseline`; `internal/plugin/access_test.go` and
`internal/cli/plugin_access_test.go`.
