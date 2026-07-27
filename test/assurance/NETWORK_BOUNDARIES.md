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
| Explicit proxy | Requests use the selected HTTP, HTTPS, or SOCKS5 proxy | `TestHTTPClientRoutesRequestsThroughExplicitProxy`, `TestNewHTTPClientBuildsProxyFromHostPort` |
| Proxy bypass | Matching hosts, domains, IP ranges, and CIDRs connect directly | `TestHTTPClientBypassesExplicitProxyForNoProxyDestination`, `TestHTTPClientNoProxyMatchesHostsAndNetworks` |
| Additional CA | The configured PEM chain is added to the system trust roots | `TestHTTPClientTrustsConfiguredAdditionalCA`, `TestCommandContextInitialize_ExplicitConfigResolvesRelativeCAPathAndPrivateNetworkSettings` |
| Custom endpoint | OSV and Scorecard use the selected base URL | `TestMatcherMatchEnrichesRegistry`, `TestMatch_AttachesScorecardToPackages` |
| Private destination | Loopback and private destinations are allowed when selected | `TestHTTPClientFollowsRedirectToPrivateDestinationWithoutForwardingCredentials`, `TestCommandContextInitialize_ExplicitConfigResolvesRelativeCAPathAndPrivateNetworkSettings` |
| Redirect | Same-host credentials are preserved; credentials are removed when the hostname changes | `TestHTTPClientPreservesCredentialsOnSameHostRedirect`, `TestHTTPClientFollowsRedirectToPrivateDestinationWithoutForwardingCredentials` |
| Error safety | Transport and config errors do not expose endpoint or proxy passwords | `TestHTTPClientTransportErrorDoesNotExposeEndpointPassword`, `TestNewHTTPClientRedactsCredentialsInInvalidProxy`, `TestValidateRedactsCredentialsInInvalidHTTPProxy` |
| Shared transport | Built-in matchers and managed plugin operations reuse the configured proxy and CA behavior | `TestRegistryHTTPClientProviderReusesTransport`, `TestHTTPClientFromLaunchContextUsesSharedProvider` |

Run the focused suite with:

```sh
go test ./sdk ./internal/config ./internal/registry ./internal/plugin ./internal/matchers/...
```

## Intentional limits

Bomly does not block private-network destinations, cross-host redirects, or
redirects from HTTPS to HTTP. These behaviors support self-hosted advisory
services and enterprise proxies, but an HTTP redirect sends later requests
without transport encryption. Use only endpoints, proxy servers, and CA files
that you trust.

An additional CA expands trust for the current Bomly process. It does not
replace the operating system roots. Redirects use Go's standard limit of ten
requests. Native plugins remain trusted processes and can create their own
network clients; the shared SDK client is a supported convention, not a
sandbox.
