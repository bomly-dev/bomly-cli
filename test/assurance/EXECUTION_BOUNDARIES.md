# Execution boundary assurance

These tests check the boundaries where Bomly can run another program or pass
data to code outside the main process.

## Managed plugins

Managed plugins are native programs. Enabling one gives it the same user
permissions as Bomly. Bomly limits what it sends to the plugin process:

- protocol identity and the selected plugin ID;
- only that plugin's configuration, in a temporary file;
- configured proxy and CA settings, or the standard proxy variables;
- no unrelated host variables such as cloud tokens or database credentials.

Tests also confirm that disabled plugins do not join runtime planning, enabled
plugins can run through the detector and matcher contracts, malformed runtime
descriptors are rejected, failures use the normal detector fallback path, and
older protocol-v1 plugins work without optional remediation capabilities.

## MCP tools

MCP scan, explain, and diff calls leave enrichment, auditing, and analysis off
unless the request enables them. Input containing path traversal text, control
characters, or unusual package and Git references must not panic or silently
enable those operations. Compact responses remain bounded by their configured
caps and report how much data was omitted.

MCP is not a sandbox. A requested local path, Git URL, image, plugin, or
package-manager operation has the same authority it has in the CLI.

## Remediation guidance

Canonical remediation is read-only enrichment. The central derivation code and
built-in detector hint implementations do not import network, process, cache,
or filesystem packages and do not call write methods.

Detector hints are untrusted evidence. Core passes cloned graph and registry
data, validates every occurrence and advertised strategy, bounds provider text,
and chooses the final status, version, and action itself. An enabled external
plugin is still native code and can use its process permissions independently;
the SDK's read-only provider contract is an architectural rule, not an operating
system sandbox.

## Subprocess logging

Debug logs for package-manager and analysis commands should identify the
executable, arguments, and working directory so the command can be reproduced.
Credential-bearing arguments and output must be redacted before logging.
Assurance for this rule is completed only when every command runner uses the
shared redaction boundary.
