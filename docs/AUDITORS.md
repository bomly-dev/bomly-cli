# Auditors

Auditors evaluate a graph and produce findings.

The default policy auditor looks at vulnerability data that is already present on packages. It does not make network calls on its own. If you want Bomly to fetch vulnerability data and then evaluate policy in one command, run `bomly scan --enrich --audit`.

## When Auditors Run

- `bomly scan --audit` evaluates the full graph.
- `bomly explain --audit` evaluates the selected component context.
- `bomly diff --audit` classifies introduced, resolved, and persisted findings.

## Findings

Findings have a normalized shape: ID, kind, severity, package, title, reasons, and source. Text output summarizes them for humans, JSON exposes them for automation, and SARIF is available for audit results with `--format sarif`.
