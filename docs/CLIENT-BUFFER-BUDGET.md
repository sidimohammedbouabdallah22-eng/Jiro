# Per-client outstanding buffer budget

Schema-2 application `traffic_controls.max_client_buffer_mib` is optional.
Zero disables this extra budget and is omitted from JSON, preserving old policy
encoding. Nonzero values are 1..8192 MiB. The dashboard exposes the setting.
The existing process/application budgets, client concurrency and token buckets
continue to apply atomically before a transaction or body buffer is allocated.

An admitted request reserves four times (its declared request bytes + 1),
conservatively using the policy limit for unknown-length bodies. Inspected
responses add three times (the response limit + 1). This is the existing
reservation model, not measured RSS or an enforceable CPU quota. The new budget
sums these reservations per actual client IP and application. A second large
body can be refused while a small read still fits, rather than treating them
as equivalent requests under a count limit.

Policy validation requires the budget to fit one full configured request and
its inspected response, including overhead. For example, a one-MiB request
limit with response inspection off fits in five MiB; four MiB is four bytes too
small under the reservation model. A two-MiB inspected response plus that request
requires eleven MiB. This validation is shared by policy preview/load/apply.

The budget is retained until real request/transaction cleanup, with no early
release to improve a benchmark. Releases reclaim the original client's state
across policy deletion/reuse. Already-tracked active requests remain charged
across configuration changes. As with other admission controls, previously
untracked work admitted under an older policy cannot be retroactively charged;
allow old work to drain when qualifying a changed policy.

A full client buffer share returns 503 with Retry-After. Optional admission
waiting can wait for release within its existing one-second/eight-waiter bounds.
A single reservation that can never fit does not enter the queue. Rate tokens
are not consumed by a buffer refusal. Per-client tracking retains the existing
1024-client/application cardinality cap and active-client eviction protection.
Zero preserves the previous behavior.

The qualified reference profile combines four application slots, three concurrent
requests/client, two requests/second with burst four, a five-MiB client budget,
a one-MiB request envelope and one-second admission wait. Four vCPUs/4 GiB host
both products and databases. The thirty-minute directional/simultaneous schedule
passes six five-minute windows and 93 file workflows in
`m4-business-abuse-ba78fad7`. The separate two-peer held-request case exhausts
all application slots and returns two legitimate 503s.
The burst allowance is separate from sustained rate; queued legitimate work
can bunch at admission. The byte budget limits concurrent large bodies without
reducing the allowed single upload. No CRS exclusions, engine changes, hidden
client retries or smaller files are part of this profile.

This is a bounded memory/admission control and an indirect mitigation for the
measured large-body workload. Small costly inputs, headers, multiple real
attacker addresses and shared NAT require their own qualification. It does not
establish hard CPU isolation or give every legitimate client priority.

Older executables reject a nonzero field. Rollback uses the saved prior policy
and package/checkpoint; do not feed a newer nonzero policy to an older binary.


The longer two-client attempt fails on one overlapping read and inadequate
sampler coverage. The three-client profile passes the recorded sustained schedule. Functional business repeats use their base
policies; those passes do not qualify this capacity policy for full browser
asset bursts or shared-NAT users. Those workloads remain a deployment gate.
