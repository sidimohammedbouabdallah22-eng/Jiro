# Applications and hostname routing

Schema 2 groups up to eight applications in one versioned deployment. Each application has a stable ID, display name, exact hostnames, a primary HTTP(S) upstream with an optional bounded pool and an independent Coraza/CRS policy. Modes, paranoia, anomaly thresholds, request/response body limits, response inspection, exclusions, custom rules and scoped exceptions belong to that application.

Qualification results and remaining coverage are recorded separately. [Application validation](VALIDATION-APPLICATIONS.md)

## Migrating an existing installation

1. Stop the service and create a verified pre-migration checkpoint with the current binary. Preserve the deployment environment, administrator credential and TLS material through the existing recovery procedure.
2. Qualify the new binary against the checkpoint, install it and start the service. Existing schema-1 policies retain their recorded bytes, revision hashes and catch-all routing behavior.
3. In **Application**, enter every public hostname used by the existing application. With TLS enabled, first deploy a certificate covering every hostname. Include the startup `-tls-hostnames` identities in certificate renewals too.
4. Validate the policy, enter a change reason and save. The save explicitly creates schema 2. Test each hostname through the actual frontend path before adding applications.
5. Use **Add application** to enter a unique application ID, name, hostnames, upstream and reason. New applications start in detection mode. Review events and tune their policy before enabling enforcement.

The application selector chooses the application edited by the existing policy and exception forms. Save validates and compiles every application, then persists and publishes the complete deployment atomically. Another administrator's saved revision makes an older draft stale. In-flight requests retain their original policy and upstream.

There is no inferred hostname migration. A schema-1 application accepts arbitrary hostnames until the explicit schema-2 save. Ordinary saves cannot return schema 2 to legacy routing. A deliberate history rollback can restore a legacy revision, and the console requests confirmation because it replaces every current hostname binding with catch-all routing.

## Routing contract

Each application requires 1–16 canonical lowercase ASCII DNS names or IP literals. Names are unique across the deployment. Use ASCII IDNA names for internationalized domains. Configuration names omit ports and trailing dots. Request hostnames are case-insensitive, and one trailing dot and valid decimal port are normalized. IPv6 request authorities use brackets.

Schema 2 selects the application from HTTP Host or HTTP/2 authority. Forwarded-host headers cannot select an application. Unknown hosts return 421. Malformed authorities and absolute-form request targets return 400. These requests stop before backend forwarding and body-buffer admission. Matching still occurs when an application's rule mode is disabled.

On a TLS connection with nonempty SNI, its normalized hostname must equal the HTTP authority hostname. Mismatches return 421, including HTTP/2 connection reuse across different hostnames covered by one certificate. Clients and any upstream edge proxy must open connections using the intended application's SNI. Empty SNI uses the explicit HTTP hostname allowlist. This profile uses one externally renewed certificate bundle covering all configured application names. Adding an uncovered hostname is refused, and certificate reloads cannot drop a configured hostname. Separate per-application certificates and ACME issuance remain later work.

The connector sends the configured upstream authority as the backend Host and retains the normalized frontend authority in rebuilt forwarded-host metadata. Public hostnames therefore select a route independently of the backend's configured authority. Restrict direct backend access in the deployment network.

The configuration is bounded to 96 KiB of compact JSON. Applications now receive fixed equal concurrency and body-buffer shares, with optional lower application/client caps and token-bucket rate controls. Storage, export, audit, TCP connection admission and traffic counters cover the process. Local roles cover the whole deployment. Application-scoped authorization restricts assigned accounts and tokens. Pool configuration requires deployment-wide routing authority. [Traffic and access controls](TRAFFIC-AND-ACCESS.md)

## Upstream pools

Enable **Use an upstream pool** in the application editor. Configure one through eight uniquely named HTTP(S) backends, the consecutive-failure threshold from 1–10, circuit cooldown from 1–300 seconds and response-header timeout from 1–120 seconds. The first URL remains the application's primary `upstream`. An optional `tls_server_name` supplies the DNS name for HTTPS certificate verification and SNI. System trust roots and TLS 1.2 or newer are required.

Selection uses bounded round-robin state after request inspection. A transport error or HTTP 5xx counts as a failure while the total request context remains active. Client cancellation or expiry of the total request budget leaves the backend failure count unchanged, including a budget already exhausted by inspection. The backend's own response-header timeout still counts when the total context remains active. An opened circuit excludes the backend until cooldown expires, then permits one recovery trial. Earlier responses cannot clear a newer circuit failure. All unavailable backends produce HTTP 503. Individual failures are returned for that request. OpenWAF issues one application-level attempt per request. Standard transport connection recovery remains subject to Go's request replay rules.

Observed status starts `unknown`, records successful requests and reports degraded/open/trial states. It is passive health evidence. `GET /api/v1/upstreams` and the application editor expose it. Scoped accounts and tokens see only their assigned applications. Pool health resets when its policy runtime is rebuilt or the process restarts. Legacy single-upstream policies retain their existing transport behavior and report `unprobed_single_upstream`.

Each pool backend has a bounded transport with 64 maximum connections, two idle connections and a two-second idle timeout. The direct upstream transport uses the same idle timeout. This evicts connections before the observed five-second lab closure window; active requests retain their deadlines. Frequent idle reconnects can increase TLS/connection cost, and backend closure during a mutation still has an uncertain outcome. See [idle-reuse evidence and limits](M4-UPSTREAM-IDLE.md). Gateway admission and application shares bound admitted work; request deadlines bound upstream I/O. Synchronous regex inspection is not preempted by those deadlines. Retired runtimes close idle connections and release connections when response bodies close. WebSocket upgrades retain duplex behavior. [CPU-heavy measurements and operating limits](M4-CPU-QUALIFICATION.md)

Policy history and coordinated recovery retain pool configuration. Candidate capabilities require `upstream_pools` version 1 if any committed revision contains a pool, including a pool removed from the current policy. Use a compatible executable or a verified pre-feature recovery set.

## Events and monitoring

Inspected security events record `application_id`, canonical frontend `host` and deployment `policy_revision`. Exact `application` filtering on `/api/v1/events/search` remains usable after an application is deleted. IDs and revisions together distinguish changes over time. Reusing an application ID includes earlier events under that ID.

Unknown/malformed/misdirected requests use the `unrouted` action and an empty application ID. Rejection summaries count occurrences within bounded application/revision/action buckets. After 61 regular buckets, three reserved overflow buckets retain counts separately for capacity, routing and rate rejection. Overflow metadata uses `*` and revision 0 where attribution has been combined. Capacity, routing and rate totals remain separate.

A summary combining different rejection status codes records status 0 and an explicit mixed-status reason. Its occurrence count covers every combined rejection.

Prometheus adds `openwaf_applications` and `openwaf_unrouted_requests_total`. Series have fixed names without per-host or per-application labels. Health mode is `mixed` when application modes differ. `inspection_enabled` is true only when all applications have rule inspection enabled. Overview counters and charts describe the whole deployment.

## Backup and downgrade

The policy, complete committed history, sender events and administration journal form one recovery set. Policy history and rollback operate on the whole deployment. Removing an application preserves its retained events and historical policies.

Upgrade checks inspect schema requirements throughout committed history. A rollback to a schema-1 policy can still have schema-2 ancestors, so an older schema-1-only executable is refused for that state. Restoring a verified pre-migration checkpoint supplies a compatible path back to the older executable. Rehearse the exact candidate and checkpoint through `waf-admin upgrade-check` before cutover. [Recovery procedure](BACKUP-RESTORE-UPGRADES.md)

## Interface

The authenticated API adds the following routes. All mutations require the current deployment revision and a nonempty reason, with existing authentication, origin checks and durable audit intent gates.

| Method and route | Fields or result |
|---|---|
| `GET /api/v1/applications` | Schema, revision and full application definitions |
| `POST /api/v1/applications` | `revision`, `application_id`, `name`, `hosts`, `upstream`, `reason` |
| `POST /api/v1/applications/{id}/delete` | `revision`, `reason`. At least one application must remain |
| `POST /api/v1/config/validate` | Complete schema-2 document with `schema_version`, `revision`, `applications` |
| `POST /api/v1/config/apply` | Complete document inside `config`, with `reason` |

Each `applications` entry contains `application_id`, `name`, `hosts`, `upstream` and `policy`. `policy` contains `mode`, `paranoia`, `inbound_threshold`, `outbound_threshold`, `request_limit`, `response_limit`, `inspect_response`, `exclusions`, `custom_rules` and `scoped_exceptions`. Unknown fields are rejected.

The routing behavior is an explicit OpenWAF deployment profile. HTTP authority and 421 semantics are grounded in the HTTP standard. Event filtering uses SQLite's documented JSON functions. [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html), [SQLite JSON functions](https://www.sqlite.org/json1.html)
