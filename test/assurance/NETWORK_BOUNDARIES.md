# Network boundary assurance

Bomly can connect to public services, private services, and proxies. These
tests make the trust boundary clear and check that the shared HTTP client
applies the selected settings consistently.

## What users authorize

`--enrich` allows enabled matchers to make their documented network calls. It
does not choose a custom destination by itself.

The built-in OSV and Scorecard endpoints can be replaced through the user
config, a file selected with `--config` or `BOMLY_CONFIG`, or their documented
environment variables. Repository config files are not loaded automatically.
Selecting a custom endpoint is an explicit trust decision. Private IP
addresses, internal hostnames, and plain HTTP endpoints are supported for
self-hosted services and local testing.

Proxy and CA settings follow the same config rules. Standard `HTTP_PROXY`,
`HTTPS_PROXY`, and `NO_PROXY` variables remain fallback inputs. A Bomly proxy
setting takes precedence over the standard variables.

## Behaviors under test

| Boundary | Expected behavior | Main coverage |
|---|---|---|
| Explicit proxy | Requests use the selected HTTP, HTTPS, or SOCKS5 proxy | `sdk/http_test.go`, `sdk/http_assurance_test.go` |
| Proxy bypass | Matching hosts, domains, IP ranges, and CIDRs connect directly | `sdk/http_assurance_test.go` |
| Additional CA | The configured PEM chain is added to the system trust roots | `sdk/http_assurance_test.go` |
| Custom endpoint | OSV and Scorecard use the selected base URL | matcher tests under `internal/matchers` |
| Private destination | Loopback and private destinations are allowed when selected | `sdk/http_assurance_test.go` |
| Redirect | Normal Go redirect rules apply; credentials are not forwarded to a different hostname | `sdk/http_assurance_test.go` |
| Error safety | Transport and config errors do not expose endpoint or proxy passwords | `sdk/http_test.go`, `sdk/http_assurance_test.go`, `internal/config/validate_test.go` |
| Shared transport | Built-in matchers and managed plugin operations reuse the configured proxy and CA behavior | `internal/registry/builder_test.go`, `internal/plugin/http_test.go` |

Run the focused suite with:

```sh
go test ./sdk ./internal/config ./internal/registry ./internal/plugin ./internal/matchers/...
```

## Intentional limits

Bomly does not block private-network destinations or cross-host redirects.
That would prevent self-hosted advisory services and enterprise proxies from
working. Use only endpoints, proxy servers, and CA files that you trust.

An additional CA expands trust for the current Bomly process. It does not
replace the operating system roots. Redirects use Go's standard limit of ten
requests. Native plugins remain trusted processes and can create their own
network clients; the shared SDK client is a supported convention, not a
sandbox.
