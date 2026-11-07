# Bounded admission waiting

Application `traffic_controls.admission_wait_ms` is optional and defaults to zero
(immediate admission or refusal). Values 1..1000 allow a short server-side wait
for an application/client concurrency or buffer share to become available.
Rate refusals never wait, and a reservation that cannot fit its application's
buffer share is refused immediately. Full body/CRS inspection still runs after
admission. This does not retry a request or replay an upstream mutation.

The queue has hard limits: eight waiters per process, four per application and
one per actual client address per application. Waiting requests allocate no WAF
transaction and no body-buffer reservation. Listener connection/header limits
still bound unread socket data. The processing context includes admission time.
An expired wait returns the original capacity refusal with Retry-After; excess
waiters are refused immediately. Cancellation, shutdown and policy activation
end waiting, with no handoff to an obsolete or closed runtime. A blocked client
cannot keep an otherwise eligible client at the head of a FIFO queue.

The dashboard exposes admission wait in milliseconds. Monitoring exposes current
pending admissions, hard queue caps, entered/admitted/expired/cancelled/policy-
changed/rate-refused counts and refusals caused by full waiting capacity.
Event duration includes the admission delay. Aggregated refusal records still
represent a counted group, not a per-request latency distribution.
Counters permit reconciling entered waits with outcomes and current pending
work. Waiting counts are separate from active inspection reservations.

The first bidirectional one-vCPU qualification showed why immediate refusal can
be too coarse: a legitimate download began while its upload was finishing, and
one-second storefront scheduling occasionally overlapped a roughly 1.3-second
response. The retained run is `artifacts/m4-business-abuse-90d92af7`; it is a
failed operating profile despite its acceptable aggregate p95. The new bounded
wait must be qualified on a distinct executable before claiming that finding
corrected in sustained operation.

This is brief backpressure, not a general client priority scheme, CPU-time
isolation or protection from arbitrary numbers of independent hostile clients.
Policy choices still require shared-NAT/browser-parallelism and deployment
qualification. Defaults preserve existing behavior. Zero is omitted from stored
JSON, preserving older policy encoding. Older binaries do not understand a
nonzero wait field; rollback requires the pre-change policy/checkpoint rather
than feeding that newer policy to an older executable.
