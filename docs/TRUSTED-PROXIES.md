# Trusted proxy identity

OpenWAF defaults to the direct TCP peer as client identity. Configure `-trusted-proxies` with explicit proxy egress CIDRs to enable the `xff-v1` profile. This process setting is visible in the System screen and authenticated status API.

```sh
waf-server -config /var/lib/openwaf/policy.json -trusted-proxies 192.0.2.10/32,2001:db8:10::10/128
```

For the packaged service, set `OPENWAF_TRUSTED_PROXIES` in `/etc/openwaf/openwaf.env` and restart. The empty default trusts no proxy. CIDRs must be canonical, unique and bounded to 32 entries. Universal `/0` prefixes and IPv4-mapped IPv6 prefixes are rejected. Use the narrow egress addresses of the actual proxy tier. A network that also contains ordinary clients gives those clients proxy authority.

## Header contract

Forwarded identity is consumed only when the connected TCP peer belongs to a configured network. That proxy must append the real incoming peer to `X-Forwarded-For`, or replace the field with an independently verified client address. It must overwrite `X-Forwarded-Proto` with the correct original scheme. Preserve the intended application Host when forwarding requests to OpenWAF. Network access controls must restrict who can originate connections from the configured proxy addresses.

The profile supports at most 16 forwarded addresses and 2,048 combined bytes, including comma separators. Multiple XFF header lines are combined in their received order. Each token must be a bare unicast IPv4 or IPv6 address, with optional ASCII space/tab around it. Mapped IPv4 addresses normalize to IPv4. Unknown/obfuscated values, addresses with ports, zone IDs, unspecified/multicast addresses, empty tokens and oversized chains are rejected. Parsing validates the complete supplied chain.

Starting at the connected peer, OpenWAF walks the supplied chain from right to left while the current address is trusted. The first untrusted address becomes the client. Entries farther left cannot replace it. If every address belongs to trusted networks, the leftmost supplied address is selected. This last case is why trusted networks must identify proxies precisely.

For example, with a trusted connected proxy and `X-Forwarded-For: 198.51.100.99, 203.0.113.7`, the selected client is `203.0.113.7` when that address is outside the trusted networks. The prefix `198.51.100.99` remains an untrusted claim. A validated trusted intermediate to the right is skipped during selection.

`X-Forwarded-Proto` is optional when XFF is present. If supplied, it must be exactly one `http` or `https` value. Missing proto uses the actual connection scheme. Proto without XFF, duplicate proto fields and proto lists are invalid. A configured proxy sending neither field uses its own direct connection identity. Forwarding headers from untrusted peers are ignored for identity selection, even when malformed.

Malformed trusted forwarding data returns 400 before body processing or upstream forwarding in every rule mode. Capacity exhaustion can return 503 first, with the malformed-header counter still identifying the observed input. Forwarding validation is independent of the Coraza engine mode.

## Inspection, forwarding and evidence

Coraza `REMOTE_ADDR` and the security event's `ip` use the selected client address. A forwarded security event also stores `peer_ip` as the connected proxy address. Security events produced with configured trusted networks include `proxy_config_sha256` to identify the effective startup trust profile, including after export or restart. Original request headers remain available to ordinary Coraza header inspection. Body and rule processing retain the existing policy behavior.

The upstream receives one normalized `X-Forwarded-For` address and `X-Real-IP` with that same selected client. `X-Forwarded-Proto` uses the selected scheme. `X-Forwarded-Host` uses the validated, canonical request authority, including its port when present. Schema-2 routing selects applications using an exact hostname allowlist and rejects unassigned hostnames; forwarded-host claims cannot select an application.

Schema-2 forwarding preserves that same validated authority in the upstream HTTP `Host` field. This supports virtual hosts and applications whose canonical redirects use raw HTTP Host, including the qualified PrestaShop workflow. The configured upstream URL still selects the dial address and TLS server name; client Host does not choose an arbitrary destination. Schema-1 legacy forwarding keeps its earlier target-address Host behavior and has no exact application-host allowlist; configure backend allowed-host checks or migrate to schema 2. Keep direct backend access restricted to the WAF's network path.

The upstream `Forwarded` field and unsupported identity aliases are removed. The aliases are `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`, `X-Client-IP`, `X-Original-Forwarded-For`, `X-Forwarded-Port`, `X-Forwarded-Server`, `X-Forwarded-Prefix`, `X-Forwarded-Ssl` and `Front-End-Https`. Backends must consume the documented normalized fields for client identity. Additional vendor-specific identity headers remain ordinary untrusted application data.

Overload summaries retain common effective and connected-peer addresses. A `*` peer marks a summary combining different peers. Event bounds, counted occurrences and durable export semantics continue to apply. Historical events without a `peer_ip` field remain readable.

`GET /api/v1/status` exposes `client_identity` with the profile, normalized trusted CIDRs, configuration SHA-256 and counters. The startup administration record stores that digest in its resource field. The digest covers `xff-v1`, a newline and the sorted canonical CIDRs joined by newlines. It excludes traffic counters. Metrics expose only the network count and process-local forwarded/invalid request totals, with fixed names and no address labels.

The metric names are `openwaf_trusted_proxy_networks`, `openwaf_forwarded_identity_requests_total` and `openwaf_invalid_proxy_headers_total`. Forwarded counts include requests later blocked by CRS or capacity limits. The System page shows the effective startup configuration and its digest.

## Recovery and supported scope

Trust configuration belongs to startup options and the service environment, alongside listener/resource settings. Preserve it with deployment settings when taking a checkpoint. A policy rollback changes rule policy while retaining the process trust profile. Offline candidate probes validate stored state independently of deployment flags. Check candidate command-line support and the intended service environment before cutover.

This profile handles XFF and the single original-scheme field. RFC Forwarded parsing, PROXY protocol, vendor-specific verified identities, automatic discovery of cloud proxy networks and runtime trust-policy editing remain separate integration work. Rate limits and multiple application routing are subsequent M3 controls.

Go's reverse proxy rewrites forwarding headers at the outbound boundary. Recursive proxy selection is also documented by NGINX's real-IP module. OpenWAF's stricter bounds, supported fields and failure behavior are defined above. [Go reverse proxy](https://pkg.go.dev/net/http/httputil#ProxyRequest.SetXForwarded) · [NGINX real-IP](https://nginx.org/en/docs/http/ngx_http_realip_module.html)

## Verification

`go test ./internal/gateway -run 'TestProxyTrust|TestForwardedIdentity|TestTrustedProxy|TestMalformedProxy|TestOverloadSummaryRetains' -v` covers configuration bounds, spoofed/untrusted chains, multiple header lines, IPv6/mapped addresses, malformed values, scheme handling, every engine mode, Coraza/backend agreement, overload aggregation and restart persistence. A dedicated fuzz target checks that an untrusted prefix cannot replace the rightmost untrusted boundary. Run it with `go test ./internal/gateway -run '^$' -fuzz=FuzzForwardedIdentityBoundary -fuzztime=5s -parallel=2`.

On 3 November 2026 the bounded fuzz run completed 7,539 executions without failure. The default-profile upstream CRS run passed all 5,193 cases with the existing documented platform expectations. Windows and Linux gateway checks and the packaged service drill cover the configured profile separately. Logs use the `artifacts/trusted-proxy-*` prefix, and the service drill writes `artifacts/linux-service-qualification.log`.
