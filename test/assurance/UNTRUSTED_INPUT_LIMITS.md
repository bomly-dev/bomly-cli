# Untrusted input limits

Bomly reads files and network responses that may come from an untrusted project
or service. These limits stop one input from consuming memory without a bound.

| Input | Limit | Check |
| --- | ---: | --- |
| YAML configuration | 4 MiB | Before YAML decoding |
| Finding baseline | 16 MiB and 10,000 entries | Before JSON decoding and validation |
| Explicit SBOM | 256 MiB | Before format detection and JSON decoding |
| Successful OSV vulnerability response | 4 MiB | Before JSON decoding |
| Successful OSV batch response | 64 MiB | Before JSON decoding |
| Successful CISA KEV response | 32 MiB | Before JSON decoding |
| Successful Scorecard project response | 4 MiB | Before JSON decoding |
| Successful deps.dev batch response | 16 MiB | Before JSON decoding |

Tests cover an input at the limit and an input over it. File-backed readers
check the size when the file is opened and also stop after reading one byte past
the limit. The second check matters when a file grows while Bomly reads it.
Failed matcher responses report the HTTP status but do not include the response
body in returned errors or logs.

## Known residual limits

- Matcher cache entries do not have a separate read limit. They are local files
  written by Bomly from bounded requests and responses. This is a lower-risk
  local resource concern and remains follow-up work.
- A remote Git scan does not cap the cloned repository size. The user must
  explicitly select a URL target, and Git owns the transfer. A fixed limit would
  reject valid large repositories, so this remains an explicit-operation
  resource risk.
