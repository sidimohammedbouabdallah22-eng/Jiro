# Security contract — first implementation slice

This document separates requirements, verified behavior and remaining qualification. It does not declare production readiness. See ROADMAP.md for the larger plan.

## Trust boundaries

Internet clients and their headers, bodies and identity claims are untrusted. The backend is a separate application that can return malformed, slow, sensitive or unexpectedly encoded responses. Administrators are trusted policy authors; their sessions still require authentication, origin checks and input validation. Policy files, revision snapshots and administrator credentials belong to the local operating-system trust boundary. Compromise of that host can alter them; content hashes are integrity checks, not signatures or tamper-proof audit storage.

Management and application listeners are separate. Management is loopback-only in this release. An application path named /api/v1/config is an upstream application path, not an administration bypass. Direct access to the backend must be restricted by the deployment; OpenWAF cannot enforce a network boundary around an independently exposed backend.

## Current operating scope

- Schema 2 supports up to eight exact-hostname applications with separate Coraza engines, policies and upstreams. Unknown hosts and TLS SNI/HTTP hostname mismatches return 421. Malformed authorities and absolute-form targets return 400. Existing schema-1 catch-all behavior changes only through explicit migration. Resource budgets and management authority are shared. See [application contract](APPLICATIONS.md).
- HTTP/1.1 and TLS HTTP/2 have real-listener checks, including multiplexed cancellation and admission. SSE flushing and HTTP/1.1 WebSocket handshakes/tunnelling have focused coverage. Request trailers and non-WebSocket upgrades are rejected. HTTP/3, gRPC semantics and WebSocket payload inspection are unsupported; exhaustive protocol qualification is pending. Go handles incoming framing.
- Coraza pinned upstream commit 08aa51147300 (development revision) and pinned CRS 4.30.0, including the recommended body processors.
- Connector request-body limits apply in enforcing, detection and disabled rule modes.
- Optional bounded response inspection for eligible MIME types; encoded eligible responses fail closed. Streaming compatibility and aggregate resource qualification remain incomplete.
- A single process owns each policy path, enforced by a process-held file lease. Do not share a policy/history path among data-plane nodes or run an older binary that does not honor this lease against it.

## Requirements and evidence

Traffic admission now partitions schema-2 concurrency and connector buffers into fixed equal application shares, with bounded optional application/client token buckets and per-client concurrency. Local roles enforce complete-deployment administrator, operator and viewer capabilities. Session versions are checked per request and updated accounts invalidate previous sessions. The bootstrap credential retains full recovery authority. [Detailed traffic and access contract](TRAFFIC-AND-ACCESS.md)

| Contract | Evidence | State |
|---|---|---|
| Attack decisions use the real rules | gateway_test.go and the local traffic runner | Verified for focused fixtures plus the full CRS corpus with documented platform adaptations |
| Hostnames select isolated application policies | applications_test.go, certificate manager tests and browser checks | Exact routing, separate rules/modes/body limits/exceptions/response inspection, SNI and HTTP/2 boundaries, atomic failure, migration and restart |
| Rejected requests do not reach the backend | Traffic runner backend accounting | Verified for its corpus |
| Accepted bodies retain their content | Integration, traffic and edge-comparison checks | Verified for focused ordinary/JSON fixtures |
| Malformed framing is rejected before the backend | TestRealListenerRejectsMalformedFraming | Verified for conflicting lengths, repeated transfer encoding and a malformed chunk |
| Untrusted forwarded headers cannot set client identity | TestForwardedIdentityComesFromConnection, TestForwardedIdentityBoundaryAndBounds, TestTrustedProxyCorazaAndBackendAgree | Default direct identity plus explicit bounded trusted-proxy profile |
| Cancellation reaches the backend | TestCancelledClientCancelsUpstream | Verified |
| In-flight transactions retain their policy | TestInFlightTransactionKeepsItsPolicyRevision | Verified across a response-rule change |
| Scoped exceptions do not leak to another method, path, field or source | policy_test.go and contract_test.go | Verified for the supported scope |
| Expired exceptions are not applied | TestScopedExceptionBoundaries | Verified with past/future expiry; checked per transaction by Coraza |
| A failed save cannot activate or expose a prepared snapshot | TestFailedActiveCommitLeavesPreparedSnapshotUnreachable | Verified with an injected commit failure and restart |
| Orphan snapshots cannot be used for rollback | TestOrphanSnapshotsAreNeverCommitted | Verified |
| Rollback creates a new revision and survives restart | TestHistoryRollbackAndRestart plus browser smoke check | Verified |
| Stale updates are rejected | API/core revision checks and rollback tests | Verified |
| Multiple processes cannot write the same policy | TestPolicyLeaseAndTamperedStartup | Verified for the local filesystem |
| Offline validation does not write or start listeners | TestOfflinePolicyCheckDoesNotWriteOrLock | Verified |
| Admission, body-copy reservations, event queue and disk quotas | limits_storage_test.go and eventstore/store_test.go | Implemented; total heap/CPU and sustained hostile-load qualification remain pending |
| Loss of control process leaves traffic running | Process separation work | Pending; current console and proxy share a process |
| Full CRS corpus | tools/crscheck | 5,193 cases; 16 explicit platform adaptations; raw report retains 15 differences and one fixture error |
| HTTP/2, streaming, WebSocket and crash/fault behavior | protocol_test.go, shutdown_test.go, recovery_test.go | Focused checks pass on Windows and Linux; see PROTOCOL-AND-RECOVERY.md; exhaustive qualification and pilots pending |

## Scoped exception semantics

The scope is the current application policy, one uppercase method, one exact decoded path, and one exact query/body parameter name as interpreted by Coraza. Paths do not use prefix matching or globbing. The first schema deliberately accepts a limited set of characters to prevent policy syntax injection. JSON fields use Coraza's flattened names, such as json.message.

The exception removes selected detection rule targets in phase 2, after body parsing and before CRS phase-2 evaluation. Earlier-phase matches are unaffected. It never removes a whole rule or the final blocking decision. The selected rule IDs must be detection IDs in 913000–948999. Owner and reason are mandatory; expiry is optional.

CRS often examines the aggregate ARGS collection. Therefore, a source-specific target exclusion also requires an aggregate target exclusion. To preserve source isolation, OpenWAF applies it only when the selected field exists in the selected source and that same name does not exist in the opposite source. If a query and body both contain the name, neither is exempted. This conservative behavior can leave a legitimate mixed-source request blocked; it prevents a narrower exception from becoming a broader bypass.

This does not authorize the content inside the application. An exception for a field accepting markup is appropriate only if the application handles that content safely.

Event match metadata includes the rule phase and up to 32 collection/field target names per match, without copying the matched values. Use those names when selecting a field and confirm that the rule runs in phase 2 before expecting a scoped exception to affect it.

## Policy persistence and recovery

The active JSON policy is the commit point. Immutable snapshots in policy.json.history contain the configuration, parent revision, content hash, actor, reason and rollback origin. Preparing a snapshot does not commit it. Only snapshots reachable through the active policy's parent chain are visible or eligible for rollback. Failed preparations reserve their revision numbers but remain unreachable. A rollback compiles the selected committed settings, then writes a new revision with the current revision as its parent.

File contents are flushed before replacement. The current checks model ordinary process interruption and write failures. Complete power-loss/filesystem qualification is pending. Policy history, the bounded durable SQLite security-event store and the separate administration journal have distinct consistency and recovery contracts. Local integrity hashes detect inconsistency within those contracts.

The initial supported bound is 1,000 snapshot files and 256 KiB per snapshot. Updates stop with an explicit error at the bound. Automated compaction/retention is pending. Do not manually prune referenced ancestors; doing so breaks the verifiable history chain.

On first upgrade, an existing unversioned JSON policy is read with schema-1 defaults and imported as the initial snapshot. Once history exists, out-of-band changes at the same revision fail verification. A missing policy with existing history does not silently boot defaults. Use the API for changes and preserve a backup of the active policy plus the entire history directory. For this development release, stop the service before taking/restoring a filesystem backup. Keep credentials private and separate from any support bundle.

An API identity is currently a shared administrator token or a pseudonymous session fingerprint, not an individual user account. Roles and per-person accountability remain future work.

## Known detection observation

The original Windows 3.8.1 engine run missed the fixture `; cat /etc/passwd` at PL1. The pinned upstream engine revision fixes path normalization; both OpenWAF and the Caddy comparison now block it at PL1. No sample-specific rule was added. The fixture remains in regression tests and is never executed by the mock backend.

## Next qualification work

The appliance operations increment adds a restricted Linux systemd package, credential files, externally renewed certificate validation/activation, expiry warnings and a separate administration journal. Administrative mutations require a synced intent before execution. Cross-file policy/certificate changes and audit outcomes have an explicit reconciliation window after interruption. Journal failure prevents new changes while the active traffic policy continues. The journal is bounded and operator-archived, with independent forwarding still pending. Certificate issuance remains with an external provider. See [Linux operations](LINUX-OPERATIONS.md).

The pinned full CRS corpus now runs through go-ftw. Extend raw framing and HTTP/2 conversion coverage; qualify sustained resource use and temporary-file cleanup; add real application benign workflows; and expand crash/power-loss coverage and Linux race testing. Focused Windows and Linux process-crash recovery checks now pass. The 48-case edge comparison and synthetic traffic corpus are focused checks, not substitutes for those gates.



## Event delivery qualification

Acknowledged group commits replace discard-on-full gateway enqueueing. Overload summaries preserve explicit occurrence counts with a bounded one-second crash window. Durable outbox and idempotent reference receiver tests cover local retention independence, pause/restart, lost acknowledgements, failed local checkpoints and forced sender termination. Finite outbox exhaustion fails visibly; indefinite outage/device-loss guarantees are not claimed. See [event delivery](EVENT-DELIVERY.md) and the retained Windows/Linux soak reports.


## Offline recovery and upgrade qualification

The operations tool acquires policy, sender and receiver maintenance leases, verifies a consistent stopped checkpoint, and publishes a new recovery directory using native no-replace operations. Verified restores preserve orphan revision reservations and pending delivery identity. Candidate startup/migration executes on private marked copies with listeners/export disabled. Schema-incompatible downgrades are refused; rollback restores a compatible pre-upgrade checkpoint. Full procedures, tested scope and exclusions are in [backup and restore](BACKUP-RESTORE-UPGRADES.md).

