# ADR-0020: Repository configuration requires explicit trust

- **Date:** 2026-07-25
- **Status:** Accepted

Bomly automatically loads the user-controlled `~/.bomly/config.yaml`, but it
never automatically loads `.bomly/config.yaml` from a scan target. A repository
configuration file may select a target, enable network-backed enrichment,
enable package-manager execution, configure plugins, or choose output paths.
Loading it merely because a user scans an untrusted checkout would let the
checkout grant itself those permissions.

Users can trust and load a repository configuration file with
`--config .bomly/config.yaml` or `BOMLY_CONFIG=.bomly/config.yaml`. When both are
set, the command-line flag selects the file. Environment values and other flags
continue to override values from the selected files. An explicitly selected
file must exist and must be a regular file so configuration mistakes fail
clearly instead of silently falling back.

Automatic finding-baseline discovery is separate. Baselines use a narrow,
versioned policy-status contract: they cannot change targets, start network or
package-manager activity, load plugins, or choose output paths. Their automatic
selection remains visible in logs and run statistics.
