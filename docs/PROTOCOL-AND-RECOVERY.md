# Protocol, failure and recovery qualification

This increment exercises the supported connector on Windows and Linux amd64. It does not establish production capacity or complete every protocol release gate.

## Supported behavior tested through real listeners

| Traffic | Evidence | Scope |
|---|---|---|
| TLS HTTP/2 | TestHTTP2InspectionAndBodyPreservation | Actual HTTP/2 negotiated; accepted JSON remains intact; XSS blocked before backend; oversized bodies rejected; response trailers retained after inspection |
| Concurrent HTTP/2 streams | TestHTTP2CancellationIsolatedPerStream, TestHTTP2AdmissionBoundsStreamsOnOneConnection | Cancel one stream without breaking another; one connection cannot bypass the process request gate |
| HTTP/1.1 framing | TestRealListenerRejectsMalformedFraming, TestHTTP1ChunkedFramingDoesNotDesynchronizePipeline | Conflicting lengths, repeated transfer encoding and malformed chunks rejected; Go normalizes Transfer-Encoding plus Content-Length to chunked and removes Content-Length; pipelined backend request boundaries remain correct |
| SSE and binary streams | TestStreamingFlushAndCancellation | First data arrives before stream completion; disconnect cancels backend; supported with optional response inspection enabled because these MIME types are outside its body-inspection list |
| Plain-text streaming | TestStreamingFlushAndCancellation | Flushes with response inspection disabled; eligible text is buffered when inspection is enabled |
| WebSocket | TestWebSocketHandshakeInspectionAndTunnelCleanup | Valid HTTP/1.1 upgrade and masked text-frame round trip; malicious handshake blocked before backend; gateway shutdown closes the tunnel |
| Truncated upstream responses | TestTruncatedResponseNeverLooksSuccessful | Inspected responses fail closed with 502 before partial content escapes; already-streamed responses terminate and record error, actual committed status, and delivery_incomplete=true |
| Upstream TLS | TestUpstreamTLSVerificationFailsClosed | An untrusted upstream certificate is rejected with 502 and an observable upstream error |
| Request trailers | TestRequestTrailersRejectedBeforeBackend | Rejected with 400 under HTTP/1.1 and HTTP/2, after body parsing and before forwarding; trailer fields are outside the supported request-header inspection phase |

Request-trailer rejection is an intentional compatibility restriction, including detection and disabled modes. Response trailers pass through and are not evaluated as response headers by Coraza; their values can become available only after that phase. The inspection contract does not cover application decisions based on response trailer fields.

SSE and WebSocket payloads are passed through, not inspected. Streams and upgraded connections consume an active request slot until they close. The request context deadline applies to their lifetime: 60 seconds by default, configurable up to ten minutes. Public listener write timeout is independently 120 seconds. This is a bounded foundation for ordinary streams, not support for indefinite connections. HTTP/2 extended CONNECT/WebSocket, h2c, HTTP/3, gRPC semantics and exhaustive HTTP/2 malformed-frame fuzzing remain unqualified.

## Shutdown and crash evidence

Shutdown stops listener admission while cancelling gateway transactions, including upgraded connections that http.Server.Shutdown does not own. Active requests finish logging before the event writer and policy lease are closed. A deadline-expired close retains the lease until remaining transactions drain; a later Close can wait for completion. The server closes remaining sockets on shutdown timeout and provides a separate bounded event flush window. TestShutdownDeadlineRetainsLeaseUntilTransactionsLog verifies the final event survives a timed-out close and immediate replacement cannot overlap an active old transaction.

The event worker closes its database handle after draining even when the original Close caller timed out; TestTimedOutCloseStillClosesDatabaseAfterDrain covers that case. The final flush has its own deadline rather than inheriting an already-expired request-drain deadline. Upload read deadlines use the earlier of the body timeout and request context deadline.

TestForcedCrashRollsBackHotJournal kills an isolated child after 50 committed events and additional uncommitted writes have produced a hot SQLite rollback journal. Reopening retains all 50 committed events and none of the unfinished transaction. TestForcedPolicyCrashKeepsCommittedRevision kills a child after a new policy snapshot is prepared but before the active file commits; restart preserves the old policy, hides the orphan and never reuses its revision number. These tests use real process termination and local temporary files. They do not simulate loss of power, failed storage firmware, all commit-boundary timings or network filesystems.

TestDatabaseFullReportsLossAndRecovers exhausts SQLite's physical page quota, observes failed writes and degraded health, frees space and verifies writing resumes. It does not fill the host disk. TestLockedEventDatabaseDoesNotDisableInspection holds a real SQLite exclusive lock while clean and malicious traffic continue to receive correct decisions; write failures remain observable and writing resumes after unlock. Queued events can be lost on abrupt termination or overload. These tests do not establish guaranteed log delivery.

## Repeatable bounded load probe

Run `go run ./cmd/waf-qualify`. For a longer run, use `go run ./cmd/waf-qualify -duration 10s -out artifacts/qualification-long.json`. Each phase sends at least 500 requests, or the selected `-requests` count (100–10,000). A duration extends each phase until that time elapses, with a hard ceiling of 100,000 requests per phase. Client timeout is five seconds. Do not treat this short probe as a long-duration soak.

The isolated fixture uses eight active slots, a 4 MiB buffer-admission budget, a 4 MiB event database, and 300 retained rows. It exercises steady clean traffic, saturated clean traffic, an attack flood and 256 KiB JSON buffer pressure. It records status counts, client errors, latency percentiles (also separated into accepted and overloaded requests), sampled heap/goroutine/active/reservation peaks, and process CPU time. Requests and backend run in the same process as the WAF; CPU includes all three. Heap is not RSS, peaks sampled every 20 ms can miss spikes, and aggregate throughput includes cheap 503 rejection. These values are evidence for this fixture, not production sizing.

The command fails on unexpected decisions, network/body errors, lost steady-clean requests, observed admission-budget violations, unsettled reservations or exceeded database/row quotas. The old Windows three-second probe exposed substantial queue loss. The gateway now uses acknowledged group commits and counted overload summaries; the probe fails on drops, persistence timeouts or mismatched occurrence accounting. A transactional export outbox and durable reference receiver are implemented. See [event delivery and longer soak qualification](EVENT-DELIVERY.md). Multi-hour/days-long and real-application qualification remain open.

CI runs the protocol/recovery tests, load probe and a short collector-outage/restart soak on Windows and Linux; Linux race detection is configured. Local Linux execution uses cross-built test binaries under WSL (native temporary files in /tmp). A local race run still requires an appropriate Go/C toolchain. Independent security review, representative application workflows, power-loss testing and production deployment qualification remain open.

