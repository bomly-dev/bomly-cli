# ADR-0040: The SDK is the default home for behavior

- **Date:** 2026-08-26
- **Status:** Accepted

## Context

The SDK maturity program (ADR-0036 through ADR-0039,
[`SDK_MATURITY_PLAN.md`](../SDK_MATURITY_PLAN.md)) exists because a month of
real fixes — PR #406, PR #407, PR #409, issues #410 and #396 — followed one
pattern: behavior that belonged to the shared model was implemented where the
symptom appeared, in the CLI or in a single detector, and then drifted from
its siblings. The program pays down that debt once. Nothing in it, by itself,
prevents the next feature or bug fix from starting the drift again.

The repository already has two partial answers. "Fix at the right depth"
(`CLAUDE.md`/`AGENTS.md`) says to centralize a rule once two call sites need
it, but is silent about *which repository* the center is. ADR-0029 says
shared helper code lives in `bomly-sdk` subpackages, but is scoped to helpers
that already exist in duplicate. Neither states the placement default for new
work, so each change re-litigates it.

## Decision

When a bug fix or feature touches the meaning of shared domain objects —
identity, coordinates, PURLs, licenses, SBOM assertions, graph semantics,
merge rules, validation gates — the change lands in `bomly-sdk` first, and
the CLI and plugins consume it. The SDK is the source of truth for what a
class of objects means and how it behaves; consumers hold only what is
genuinely theirs:

- **CLI-level** is presentation, command surface, pipeline orchestration, and
  policy wiring — how Bomly *uses* the model, never what the model *means*.
- **Plugin-level** is integration specifics of one external tool — how one
  component *produces or enriches* model data, never how that data is
  keyed, normalized, validated, or merged.

The test is ownership, not convenience: "only the CLI needs this today" is
not a reason to put model behavior in the CLI, because today's single
consumer is how every drifted copy started. The bar to stay out of the SDK is
that the behavior is specific to one consumer *by nature* — it would be
meaningless to a second consumer, not merely unused by one.

The cost asymmetry is accepted knowingly: an SDK change is slower to ship
(tag first, plugins adopt, CLI bumps the pin) than an internal patch. That
ordering is the price of one source of truth, and the release cadence
(multiple SDK tags in a single week is normal) keeps it small. When the
schedule genuinely cannot absorb it, the CLI-side fix ships with the SDK
issue already filed and linked from the code — a deliberate loan, not a
decision — and "Say so when you decline" from the fix-at-the-right-depth
convention applies.

## Consequences

- "Where does this go?" has a default answer with the burden of proof on
  staying local, recorded here so reviews can cite it instead of re-arguing
  it.
- The fix-at-the-right-depth convention in `CLAUDE.md`/`AGENTS.md` gains the
  cross-repo depth: the deepest home for a rule about shared objects is the
  SDK, and the guard tests that protect kit boundaries (ADR-0038) are the
  enforcement.
- ADR-0029 is subsumed but not superseded: it covers moving existing
  duplicated helpers; this ADR sets the default for new behavior before a
  duplicate ever exists.
- The SDK's surface grows more deliberately than the CLI's internals would —
  every addition is contract surface with doc comments, validation, and wire
  posture. That friction is a feature: it forces the "what does this mean?"
  conversation to happen once, at the definition, instead of at each
  consumer.
