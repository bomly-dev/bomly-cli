# Security Policy

Bomly is a security-sensitive tool: it scans dependency trees, evaluates policy, and
generates SBOMs that downstream systems rely on. We take vulnerabilities in Bomly
itself seriously and appreciate reports from the community.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's
[Private Vulnerability Reporting](https://github.com/bomly-dev/bomly-cli/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). If you cannot use
that channel, email <contact@bomly.dev> instead. This keeps the report confidential
while we investigate and prepare a fix.

When reporting, please include:

- A description of the vulnerability and its impact.
- Steps to reproduce (a minimal repro, command line, and affected input if possible).
- The Bomly version (`bomly version`) and your platform.
- Any suggested remediation, if you have one.

## What to Expect

- **Acknowledgement:** within 3 business days.
- **Initial assessment:** within 7 business days, including severity and a planned path.
- **Fix and disclosure:** we coordinate a release and a published advisory; we will
  credit reporters who wish to be named.

## Scope

In scope:

- The `bomly` CLI and its libraries in this repository.
- The release artifacts published from this repository.

Out of scope:

- Vulnerabilities in third-party dependencies (report those upstream; Bomly itself
  helps you find them).
- Findings produced *about your dependencies* by a Bomly scan — those describe your
  software, not a flaw in Bomly.
- Issues that require a compromised local machine or a malicious build of Bomly.

## Supported Versions

Bomly is pre-1.0 and ships frequently. Security fixes target the **latest released
version**. Please upgrade to the most recent release before reporting, in case the
issue is already fixed.
