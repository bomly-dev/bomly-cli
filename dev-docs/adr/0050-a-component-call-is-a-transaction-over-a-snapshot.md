# ADR-0050: A component call is a transaction over a snapshot, within the command's lifetime

- **Date:** 2026-10-25
- **Status:** Accepted

## Context

The same SDK module behaved differently depending on how it ran. A managed
plugin's request crosses the wire as a copy, and its result is applied only
when the RPC succeeds. An embedded matcher or analyzer received the host's own
graph, registry and target pointers, so one that changed them and then failed
-- the reachability analyzers enrich `req.Registry` in place -- left the
pipeline half-enriched. Lifetimes diverged too: embedded constructors ran
under `context.Background()` with no way to release what they acquired, and a
managed component was torn down only as a side effect of killing its process.

## Decision

- Every `Ready`, `Applicable` and `Match`/`Analyze` call receives its own
  `MatchRequest.Clone` / `AnalyzeRequest.Clone`. No component holds the host's
  state.
- Only a successful action is committed: a returned `Registry` wins, otherwise
  `PackageUpdates` merge through `model.ApplyPackageUpdates`. A failed call, or
  one that returns after the command was cancelled, commits nothing. Rollback
  is per call; earlier successes stand.
- Changes a component makes to the graph or target are never committed, as
  they never were for a managed plugin.
- An embedded component is constructed under the command's context and gets a
  `plugin.ComponentScope`. `Registry.Close` ends every scope, newest first, in
  the command's cleanup chain ahead of temp-dir cleanup. A managed component's
  scope closes when go-plugin's `Kill` shuts the plugin down gracefully, and the
  pool shuts plugins down concurrently, so the command waits one grace period.

## Rejected

Letting embedded components keep mutating the request, documented as a
feature, was rejected: it makes rollback depend on how a plugin is packaged.
Instead the cost of one snapshot per call is accepted, measured at under 1 ms
for 500 packages.

## Consequences

- A component that relied on mutating the graph or target to communicate must
  return a registry or deltas instead.
- Snapshots cost time and memory per call. That is the price of parity, and
  it is the first place to look if a very large scan slows.
- A component's cleanups run even when its constructor fails after
  registering them.

Enforced by: `TestEngineMatchCommitsOnlySuccessfulCalls`,
`TestEngineAnalyzeCommitsOnlySuccessfulCalls` (embedded and simulated-wire
parity), `TestEngineMatchDiscardsWorkFinishedAfterCancellation`,
`TestRegistryComponentLifetimeIsTheCommands`, and bomly-sdk's conformance
probe of a managed cleanup on shutdown.
