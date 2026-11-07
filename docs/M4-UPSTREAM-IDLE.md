# Upstream idle-reuse failure and mitigation

The correction is included in qualified lab candidate `7be7bc728f08`. M4 remains open.

The varied-file baseline reproduced a legitimate upload 502 on candidate
`7507723617cc`, before attack traffic. The retained trace run is
`artifacts/m4-business-abuse-314112a5`. Its independent metadata checker verifies
that the existing ERP relay connection was reused 5.104580 seconds after its
last response. The gateway wrote 102,400 TCP payload bytes of a roughly 956-KiB
request, then received a close 0.314 ms after the first write with no response
payload. The failed request returned 502. This establishes the observed reuse
and partial-write failure; it does not prove the backend's configured timer,
application commit state, or a cause for every older 502.

Packet capture is bounded, private lab evidence and can contain truncated data.
The checker emits only TCP counts/timing, never HTTP payload. It verifies the
capture hash and ties the failure to the recorded package/phase/client outcome.
The diagnostic run is excluded from capacity qualification.

Both the direct and pooled upstream transports now evict idle connections after
two seconds rather than ninety. This avoids keeping a connection through the
observed five-second closure window. Active requests are unaffected. A backend
can still close during any request; connection eviction is a mitigation, not a
delivery guarantee. Backends with shorter timers require separate qualification.
Frequent reconnects, particularly HTTPS handshakes, can cost more CPU and latency;
final-package TLS/endurance repeats remain required.

Mutation replay behavior is unchanged. Safe zero-byte reconnects remain allowed
by net/http's rules; a POST with an ambiguous write or lost response is not
replayed. Untrusted idempotency headers do not opt a mutation into transport
replay. The regression models a reused connection that accepts bytes while
closing: the previous ninety-second implementation fails with 502, zero backend
POSTs and one dial. With earlier eviction, the same test returns 200, exactly
one backend POST and two dials. Original lost-response and idempotency-header
regressions still pass. The old-behavior failure is retained under
`artifacts/m4-upstream-idle-20261106/old-behavior-regression.log`.

The first correction candidate is `4a145e37f9b5`. Both platform suites and
5,193 CRS cases each pass, as do focused Linux race checks. The latest combined
candidate `7be7bc728f08` additionally passes 27 real-business workflows and the
scoped thirty-minute directional/simultaneous abuse schedule. All 9,198 requests
verify with stable gateway identity and successful file workflows.
[Sustained results](M4-SUSTAINED-FAIRNESS.md).

The backend configuration inventory lists `KeepAlive On`,
`MaxKeepAliveRequests 100` and `KeepAliveTimeout 5` for both pinned containers.
The observed closure timing is consistent with that listed window. The source
captures the directives from enabled configuration files. Final-package deployed
TLS and recovery/rollback repetitions remain M4 gates.
