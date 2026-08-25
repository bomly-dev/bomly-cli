# ADR-0026: Untrusted documents have input limits

- **Date:** 2026-07-27
- **Status:** Accepted

Bomly bounds large documents before decoding them. YAML configuration files are
limited to 4 MiB. Finding baselines are limited to 16 MiB and 10,000 entries.
Explicit SBOM inputs are limited to 256 MiB. Successful deps.dev batch responses
are limited to 16 MiB. OSV vulnerability and batch responses are limited to
4 MiB and 64 MiB. CISA KEV responses are limited to 32 MiB, and Scorecard
project responses are limited to 4 MiB. Failed matcher responses expose only
the HTTP status rather than including an upstream response body in errors or
logs.

The shared file reader checks both the size reported when the file is opened and
the bytes actually read. This keeps the limit in place if a file grows during
the read. Baseline duplicate checks use an index keyed by package finding
identity so validation remains linear as the document approaches its entry
limit.

Repository-controlled manifests, lockfiles, workspace metadata, and analyzer
source files use a shared 64 MiB per-file limit. Both whole-file and streaming
readers check the opened size and the bytes consumed, so a growing file cannot
bypass the limit. Parsers never receive a partial over-limit document.
Matcher and analyzer JSON cache entries have a separate 64 MiB read policy;
corrupt or oversized entries degrade to a cache miss.

Remote Git work uses a different boundary. Each remote materialization flow has
a 10-minute deadline. Bomly does not fetch submodules or Git LFS objects, and it
validates the completed checkout before discovery: at most 1,000,000 paths,
10 GiB of regular files, 256 path levels, and no symlink whose lexical target
escapes the checkout. Internal links remain intact. Git transfer bytes and
`.git` object storage cannot be reliably capped by portable Git options before
checkout, so those remain delegated to an operating-system quota when a hard
cap is needed.

The hidden maintainer benchmark uses its own shallow Git clone runner. It is
outside the customer CLI's remote-target materialization boundary and does not
inherit these checkout validation controls.
