# ADR-0006: Three-collection domain model — dependencies, packages, findings

- **Date:** 2026-06-04
- **Status:** Accepted

`sdk` separates three pipeline concerns that the original model conflated:

1. **`sdk.Dependency`** (`sdk/dependency.go`) is a detection-time graph node. It carries identity (`ID`, `Name`, `Version`, `PURL`), detection metadata (`Scopes`, `Locations`, `FoundBy`), an optional direct/transitive/unknown `Relationship`, occurrence `Source`, edges through the `Graph`, and a `PackageRef` (PURL) that links to a matching artifact. It does **not** carry licenses, vulnerabilities, or scorecard data.
2. **`sdk.Package`** (`sdk/package.go`) is a matching artifact keyed by PURL on a `sdk.PackageRegistry`. It carries `Licenses`, `Vulnerabilities` (OSV-aligned `sdk.Vulnerability`), `Scorecard`, `EOL`, and similar enrichment. There is one entry per unique PURL across the whole pipeline, so 50 dependencies referencing the same package share one set of CVEs and one license decision.
3. **`sdk.Finding`** (`sdk/vulnerability.go`) is a reference-style audit result. It carries policy fields (`Severity`, `PolicyStatus`, `Reasons`, `Auditor`, stable `RuleID`) plus the references `PackageRef` (PURL) and, for vulnerability findings, `VulnerabilityID`. It does **not** copy CVSS / EPSS / KEV / CWE — consumers resolve those by following the references back into the registry.

`sdk.Vulnerability` is OSV-aligned (id, aliases, summary, details, severity, affected, references, database_specific) and extended with Bomly's matching-stage fields (CVSS, EPSS, KEV, CWE, FixedVersions, AffectedSymbols, `Reachability`). The OSV matcher (repo `bomly-plugin-osv-matcher`, `plugin/response.go`) maps OSV responses directly to this shape; grype / depsdev / eol / scorecard and enabled external matchers write the equivalent records.
