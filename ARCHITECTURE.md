# OpenWAF foundation architecture

## Runtime

`cmd/waf-server` creates two listeners. The application listener runs only `internal/gateway.Gateway`. The management listener is loopback-only and runs the authenticated API plus embedded assets in `ui/`. The old prototype packages are archived and are not imported.

Each active schema-2 runtime holds an immutable deployment, exact-hostname lookup and separate application runtimes with their own compiled Coraza WAF and upstream URL. Schema 1 retains its legacy catch-all application. Policy updates are serialized. Every application is validated and compiled against the pinned embedded configuration and CRS before persistence. A successful whole-deployment save publishes one runtime pointer. Requests create their transaction while holding a short lifecycle read lock. Replacement closes retired WAF cached resources after transactions acquire their own references. Transaction logging and close run on every exit path. Certificate reload and policy activation share a manager lock to preserve hostname coverage across both operations. [Application model and migration](docs/APPLICATIONS.md)

## Rule loading

1. Embed Coraza's recommended configuration from `coraza-coreruleset/coraza/v3`.
2. Override engine mode, body limits, response access, and disable disk audit logging.
3. Set CRS blocking/detection paranoia levels and anomaly thresholds in a phase-one SecAction.
4. Include the CRS setup file.
5. Load generated scoped exceptions and administrator custom rules before CRS blocking decisions. Exceptions run in phase 2 after parsing, and remove only selected field targets when their path, method, source and expiry conditions match.
6. Include all CRS rule files from `coraza-coreruleset/crs/v4`.
7. Apply explicit CRS rule-ID removals.

There is no heuristic bypass or substitute regex detector. The custom editor intentionally supports only single-line SecRule/SecAction statements, not arbitrary Coraza configuration directives.

The exact Coraza source is locally pinned in `third_party/coraza`, with an
identified OpenWAF downstream character-presence guard for large ASCII regex
inputs. Necessary conditions can reject impossible matches; the original matcher
decides possible matches and captures. Unknown/Unicode cases fall back, with no
cross-request payload cache. The upstream experimental prefilter remains Off.
[Patch provenance and update discipline](third_party/coraza/OPENWAF-PATCHES.md),
[performance evidence and CPU isolation limits](docs/M4-CPU-QUALIFICATION.md).

## Request and response flow

The connector derives the client IP from `RemoteAddr`, rejects oversized request bodies, and preserves the complete accepted body. It feeds connection, URI, Host, headers, transfer encoding, and request-body data to a Coraza transaction, honoring interruptions before forwarding. JSON, XML, URL-encoded, and multipart parsing belong to Coraza and its recommended rules.

The reverse proxy rebuilds forwarded identity headers, verifies upstream TLS normally, and passes response headers through phase three. Explicit startup proxy CIDRs enable bounded right-to-left XFF selection. Coraza REMOTE_ADDR, event IP and normalized backend identity use the same result, with the connected peer retained in forwarded event metadata. See docs/TRUSTED-PROXIES.md. When enabled, supported response bodies are bounded and evaluated in phase four before delivery. Unsupported content types stream. Eligible over-limit or unexpectedly compressed responses fail closed. Phase five and transaction cleanup run after delivery or interruption.

Engine `DetectionOnly` and `Off` control rule behavior. Independent connector body limits remain active. Response inspection does not redact content; it permits rule-driven blocking.

## Administration and storage

Local accounts use `internal/accounts`, a bounded independently revisioned JSON store beside the policy. Password verifiers use standard-library PBKDF2-HMAC-SHA256 with fixed format-1 parameters. Server-side role checks guard each non-administrator capability, with current account-version validation on every request. Policy rollback and account revisions are independent. Offline recovery automatically preserves an existing account file and refuses candidates lacking the required account/traffic-control capabilities. [Traffic and access contract](docs/TRAFFIC-AND-ACCESS.md)

`OPENWAF_ADMIN_TOKEN` is required and must contain at least 32 characters. Bearer-token comparisons use SHA-256 digests and constant-time comparison. Browser login creates a random server-side session with an eight-hour lifetime and an HttpOnly, SameSite=Strict cookie. Sessions reset on restart. Token rotation currently requires a restart. A loopback console may be reached through an SSH tunnel.

All policy mutations use JSON with origin validation. Configuration decoding rejects unknown fields. Updates require the revision that was read by the client; stale revisions return 409. API input and custom rules have size limits. No secrets are stored in the policy file or browser local storage.

`config/policy.json` is written through a temporary file, flushed, closed, and renamed over the destination. It is the commit point for immutable snapshots in the adjacent `.history` directory. Only its parent chain is committed history; prepared orphan snapshots cannot be displayed or restored. No success response or live update occurs on a write/rename failure. A process-held file lease enforces a single writer. After initial import, out-of-band edits fail revision integrity verification rather than silently overwriting recorded history. Rollback compiles an earlier snapshot and creates a new revision. See docs/adr/0002-policy-history.md for failure semantics, limits and the later SQLite migration boundary.

Traffic counters and sixty one-minute buckets live in memory. Security events use bounded acknowledged SQLite group commits plus a 500-record recent view reloaded at startup. Capacity rejections are counted in bounded one-second summaries. A transactional outbox preserves pending exports independently of local-history retention; an idempotent reference collector commits before acknowledging. Informational nolog rule matches are excluded. Rule messages retain unexpanded templates to avoid capturing matched values. Request paths, IPs, field names and administrator rule text still require access control. Database queries support cursor pagination and literal search. Write retries, ingest timeouts and failures are observable. Abrupt crashes can lose a not-yet-committed event or the current in-memory overload summary window. See docs/EVENT-DELIVERY.md for reliable-delivery scope and finite spool limits. See docs/REGRESSION-AND-OPERATING-LIMITS.md for storage and capacity semantics.

## Boundaries and next work

This release establishes one protected application, one upstream, real inspection, durable policy/history, scoped exceptions, rollback, and an administration UI. Multi-application routing, bot defense, rate limiting, RBAC and cluster coordination remain roadmap work. The separate tools/edgecheck module compares the production connector with Caddy using identical rule files. See docs/SECURITY_CONTRACT.md for the evidence and remaining qualification.

Focused HTTP/2/streaming/WebSocket, shutdown, forced-crash and storage-fault checks are documented in docs/PROTOCOL-AND-RECOVERY.md. Acknowledged export, a durable reference collector and repeatable mixed-load/outage/restart soaks are implemented. Offline coordinated recovery sets, private-copy upgrade rehearsal and backup-based rollback are implemented in internal/operations and cmd/waf-admin. Process-held sender/receiver leases prevent concurrent maintenance.

The internal/adminaudit package writes a separate bounded, hash-chained administration journal with synchronous appends and a process lease. Management mutations and core policy activation require a durable intent. An interrupted operation can have a committed policy/certificate and an incomplete outcome, requiring reconciliation against recorded revision/digest or fingerprint. An optional independent exporter binds the exact destination in the journal and replays its canonical records through complete-batch acknowledgements. Stable source and record IDs permit receiver deduplication across process restart and checkpoint restore. Recovery sets preserve the journal and reject candidates lacking its format and export capabilities. Offline archive replay opens the source read-only under the exclusive lease. [Audit delivery contract](docs/AUDIT-EXPORT.md)

The internal/certificates package validates externally renewed PEM pairs and atomically replaces the certificate callback used for new TLS handshakes. It retains the previous pair on invalid replacement and reports reload failures and the earliest supplied-chain expiry. A systemd package provides a restricted single-node service and file-backed credentials. Host-routed application policies, bounded rate controls, local accounts and independent audit export are implemented. Multi-hour isolated sizing, physical power-interruption recovery and the native fresh-VM platform matrix remain qualification gates. Performance baselines and independent security review precede production-readiness claims. [Linux operations](docs/LINUX-OPERATIONS.md), [M2 qualification](docs/M2-QUALIFICATION.md)




