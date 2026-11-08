# Shared-NAT abuse and endurance

This qualification extends the four-user browser workload on candidate
`20031ed996b3`. Legitimate users share one real TCP source address. The five
profiles cover a baseline, ERP abuse, storefront abuse, simultaneous abuse and
simultaneous abuse from the legitimate users' shared address.

Each targeted application receives four independently paced workers, each
making at most one attempt per second. Their 900-KiB valid Unicode JSON bodies
exercise the conservative Coraza inspection path. ERP payloads omit the required
customer name, and storefront POSTs target a read-only product view. Native
customer/order hashes check business-state preservation. Spoofed forwarding
headers rotate while actual source addresses remain fixed.

Browser waves run four independent authenticated contexts every fifteen seconds.
Each phase begins with two parallel 700-KiB file round trips and repeats another
pair in each administrator session. Full asset responses, application identity,
warm-cache behavior, saved addresses and catalog navigation remain checked.

## Qualification gates

- Every browser workflow, resource request and file round trip succeeds.
- Navigation p95 stays within five seconds, and file p95 within ten seconds.
- Every file round trip stays within ten seconds and every wave within twenty.
- The scheduled browser workload completes within the abuse period plus five
  seconds. A late workload fails coverage because traffic after the workers stop
  cannot establish responsiveness under abuse.
- Phase and sixty-second resource windows retain the existing native sampling
  gates, including at least twenty samples and gaps below four seconds.
- Observed CPU stays within 80% in the phase and every sixty-second window.
- Process identity, executable hashes, native cgroups, memory/OOM counters,
  applied policy and actual source addresses verify.
- Security events reconcile to identical durable sender/receiver payloads with
  an empty outbox, zero queue loss and zero ingest acknowledgement timeouts.
- Native file probes verify exact committed bytes and absent refused uploads.
  Policy, application origins and the original one-vCPU allocation are restored.

An invalid resource interval is retained explicitly. The harness continues to
collect the remaining screens, while its measurement and qualification flags
remain failed. Failed phases preserve the active policy and completed file
manifest before draining, allowing cleanup-time file checks.

## Initial higher-limit profile

The starting profile has 32 application slots, no client concurrency cap,
30 requests/second with burst 96 per client, a twelve-MiB client buffer budget
and one-second bounded admission waiting. The gateway has 64 active slots,
128 connections, a 64-MiB global buffer budget and a 512-MiB service memory cap.
The lab has four vCPUs and four GiB RAM, shared with both applications and their
databases. Request envelopes remain one MiB, with the original enforcing CRS
policies and exclusions unchanged.

Run `m4-business-abuse-45f51193` passes the baseline and completes the ERP
browser workflows, but has a 9.396-second native sampling gap during ERP abuse.
The run fails before resource qualification. Its twenty file attempts are
retained for native rechecking.

Run `m4-business-abuse-14baf11b` shows why successful responses alone are
insufficient. ERP and storefront abuse complete browser workflows, but miss
their coverage or tail-latency gates. Their first-minute observed CPU reaches
84.2% and 81.6%. Simultaneous abuse misses latency/coverage and sampling gates.
Same-source abuse refuses four legitimate uploads because the twelve-MiB client
buffer share is occupied. Its fifty attempted files are recovered from the
browser reports into a separate manifest for native rechecking.

All 135 security occurrences reconcile into 122 identical sender/receiver
records, with an empty outbox. Two ingest acknowledgements time out, and the
storage health gate remains failed. The gate stops final drain. The failure
also contains one upstream 502. All captured evidence and the original partial
file manifest are retained. Boot stalls and recovery actions remain recorded
separately from application setup.

## CPU and buffer experiment

The next experiment applies a Linux service CPU quota of 200% with a 100-ms
period to the gateway and increases the shared-client buffer budget to 24 MiB.
The total guest allocation, global buffer budget, service memory cap, worker
counts, legitimate traffic schedule and request envelope stay as recorded above.
The quota bounds the whole gateway process. Native `cpu.max`, usage and
throttling counters are captured throughout the run.

The larger client share allows the current hostile workers and legitimate
parallel uploads to compete within the global memory budget. Qualification is
tied to the measured worker count, workload and hardware. Broader address/worker
counts and the final pilot host require their own checks.

```powershell
python scripts/qualify-browser-nat.py --package artifacts/rule-candidate-20031ed996b3/openwaf-rule-candidate-linux-amd64.tar.gz --disposable-vm --abuse-seconds 60 --gateway-cpu-quota 200 --nat-client-buffer-mib 24
```

Run `m4-business-abuse-3d1eae71` rejects this CPU/buffer experiment. Its ERP
file p95 reaches 21.89 seconds and navigation p95 11.26 seconds. Pressure also
produces upstream failures and an ingest acknowledgement timeout. Native
rechecking resolves two 502 upload responses into one committed exact file and
one absent file. Their original response reports are retained. The harness now
classifies ambiguous server/transport failures explicitly and performs native
file reconciliation, without replaying mutations.

## Body-byte admission guard

Candidate `32d099011bde` adds optional per-client/application request-body byte
budgets. The new bucket shares the existing admission lock and bounded identity
table. Refused requests consume no credit, and bodyless asset bursts consume
zero body bytes. Unknown-length requests reserve the complete supported
envelope before reading. Existing policies default to disabled. The console
exposes the controls. [Configuration and semantics](CLIENT-BODY-RATE.md).

Both Windows and Linux full pipelines pass, including all 5,193 CRS cases each.
Focused Linux race checks and real-console save/reload/disable checks pass.
CRS policies, exclusions and the one-MiB request envelope are preserved.

The first guarded screen, `m4-business-abuse-6baead9b`, uses 160 KiB/s with a
four-MiB body burst, the original twelve-MiB client buffer share and the original
uncapped gateway CPU allocation. All 4,096 requests and 864 occurrences reconcile
to 310 identical receiver records. Forty-two committed files verify, totaling
30,105,600 bytes, and eight refused files are absent. Twenty-four fabricated
proofs are rejected. Storage/export remain healthy with no ingest timeouts.

The baseline and individual ERP/storefront abuse screens pass latency,
coverage, CPU and native sampling gates. ERP file p95 is 6.36 seconds and
navigation p95 2.30 seconds. Storefront-abuse file p95 is 5.27 seconds and
navigation p95 2.12 seconds. Combined abuse completes browser workflows but
fails startup file latency, schedule coverage and sampling gates. Its slowest
initial file takes 12.70 seconds, and the browser workload lasts 73.67 seconds.
Same-source abuse remains failed because clients share body/buffer credit.

The extended experiment reduces the body burst to three MiB while preserving
the rate, request envelope, browser schedule and attack workers. It runs a
one-minute baseline, five minutes against ERP, five against the storefront,
five against both and a separate one-minute same-source boundary. Every
sixty-second window is checked. These results determine qualification.

```powershell
python scripts/qualify-browser-nat.py --package artifacts/rule-candidate-32d099011bde/openwaf-rule-candidate-linux-amd64.tar.gz --disposable-vm --abuse-seconds 300 --shared-abuse-seconds 60 --nat-body-rate-kib 160 --nat-body-burst-kib 3072
```

External-source and same-source outcomes have distinct qualification flags.
Completing an endurance run establishes support only when its browser,
responsiveness, coverage, native-resource and durable-evidence gates pass.
The verifier recomputes all sixty-second windows. M4 remains open.

## Completed three-MiB-burst endurance

Run `m4-business-abuse-ca2019be` completed the recorded one-minute baseline,
three five-minute external-abuse phases and one-minute shared-source boundary.
Independent verification reconciles 14,683 requests, 272 browser sessions,
15,438 cache hits, 136 committed files totaling 97,484,800 bytes, and 3,760
security occurrences in 1,188 identical sender/receiver records. Ten refused
files are absent. The outbox is empty and ingest timeouts are zero. Twenty-four
false proofs are rejected.

| Phase | Browser workflows | Response budgets | Schedule coverage | Native resource evidence |
|---|---|---|---|---|
| Baseline | Pass | Pass | Pass | Pass |
| ERP abuse | Pass | Fail | Fail | Fail |
| Storefront abuse | Pass | Pass | Pass | Fail |
| Both applications | Pass | Pass | Fail | Pass |
| Shared-source abuse | Fail | Fail | Pass | Pass |

ERP abuse takes 318.87 seconds of browser work for its 300-second phase and
includes a 31.52-second wave. Simultaneous abuse takes 307.23 seconds, exceeding
the existing five-second coverage allowance. Native sampling gaps of 16.718
seconds during ERP abuse and 4.137 seconds during storefront abuse invalidate
their resource claims. The earlier host heartbeat starts after those gaps, so
their host-versus-guest cause remains unresolved. Successful file delivery and
event reconciliation establish those properties within this run. The workload
and resource profile remains unqualified.

## Browser timing and host diagnostics

The next harness revision anchors browser waves to a single monotonic schedule,
including initial upload time. A slow wave retains its recorded start delay.
Later fast waves can recover schedule drift without dropping workflows. Exact
scheduled/actual starts and total work duration are retained and independently
checked. Timer wakeups are checked again against the deadline. Two deterministic
scheduling regressions cover recovery after a slow wave and persistent overload.
Existing latency, coverage, resource and delivery gates continue to apply.

Abuse qualification now requires its no-abuse baseline to pass browser,
integrity, latency, schedule and resource budgets before starting hostile work.
Invalidated measurements carry `measurement-invalid.json`, which the independent
checker rejects before reading qualification claims.

Run `m4-business-abuse-c99f7a69` is retained as diagnostic evidence only. A brief
timer-rounding edit occurred after the baseline started and was restored to the
captured bytes. The invalidation marker prevents its use for qualification.
Host measurement also observed approximately 95% CPU usage with substantial
competition from another host process. Its no-abuse browser baseline takes
116.53 seconds for a 60-second schedule. After ERP pressure, the drain health
gate fails with two ingest acknowledgement timeouts, despite an empty outbox
and zero failed writes or dropped queue entries in the captured status.
All twenty committed files verify, totaling 14,336,000 bytes. Captured databases
and host/native samples are retained for diagnosis. Cleanup restored policy,
stopped the source relays, powered off the VM and restored its one-vCPU setting.

This diagnostic run uses the earlier `32d099011bde` package to isolate measurement
changes. The next qualifying run requires the finalized harness, a passing
baseline and the selected package identity. M4 remains open.

## Frozen-schedule repeat and two-MiB screen, 8 November 2026

Run `m4-business-abuse-c3ec075d` uses the finalized schedule and a three-MiB
burst. All five phases have valid native resource evidence and pass their CPU
budgets. Baseline and the individual ERP/storefront phases pass all workload
gates. Simultaneous abuse completes the browser workflows but takes 78.30
seconds for a 60-second phase, with file p95 11.26 seconds. The shared-source
boundary again refuses legitimate uploads and fails its workload gates.

Independent evidence reconciles 3,983 requests, eighty sessions, forty committed
files totaling 28,672,000 bytes, ten absent refused files, and 756 occurrences in
282 identical sender/receiver records. The outbox is empty, ingest timeouts are
zero, and twenty-nine false claims are rejected, including fabricated browser
timestamps and baseline qualification. Cleanup succeeds and the host heartbeat
observes VM exit. This is a short screen. Extended endurance remains open.

The next experiment uses a two-MiB body burst. Two unknown-length requests each
reserve the one-MiB envelope and fit this burst. This tests a smaller initial
inspection burst while retaining the supported envelope and the 160-KiB/s rate.

Run `m4-business-abuse-245e1ef5` correctly stops before hostile work because its
baseline takes 67.14 seconds and its slowest wave takes 20.53 seconds. Its 632
requests include ten exact committed files totaling 7,168,000 bytes, with zero
ingest timeouts. The two-MiB abuse profile remains untested. Original failed
results are preserved. Policy restoration succeeds, but graceful shutdown and
an ACPI request leave the hypervisor reporting the VM as running. Explicit
poweroff completes cleanup and restores one vCPU, recorded separately in
`cleanup-recovery.json`.

The cleanup helper now falls back to powering off its owned VM after a stalled
graceful shutdown, records `shutdown_forced` and fails the run. The browser
evidence checker rejects forced-shutdown results. Unit regressions exercise
the fallback and rejection. Continue with a passing baseline on the selected
host before another abuse/endurance run or final-package repetition.

## Export recovery and two-MiB rejection, 8 November 2026

Run `m4-business-abuse-fdb1ae81` stalls during Linux boot before SSH or traffic
setup. One owned-VM reset recovers boot, with console and host evidence retained.
Its subsequent browser work completes in 62.15 seconds with ten exact files,
but a transient empty-outbox database read timeout leaves export health failed.
Successful empty reads do not clear that error in the earlier binary. The run
stops before abuse, and cleanup succeeds. A clean-boot repeat remains required.

The exporter now clears a recovered local read failure after a successful empty
durable-outbox read and published zero pending rows. It preserves cumulative
failures and the previous receiver-contact timestamp. The regression holds the
sole database connection until the exporter times out, then releases it and
requires healthy recovery with zero collector requests, acknowledgements or
receiver-success timestamp. It fails before the fix and passes three consecutive
times afterward. Event-store and gateway suites and vet pass locally.

The new Jiro candidate archive SHA-256 is
`d382caa1fd25f747611c292fa51b57f498c49e02c34488e79509b2944bd99c13`.
Its Linux server SHA-256 is
`70d3e58d0ca98c1d104c719fb2beca0c535955dae3d8ad621528db2b9490f56b`.
These measurements identify this binary separately from `32d099011bde`.

Two clean-boot two-MiB screens reject the profile before abuse. Run `aa20236e`
completes every workflow and ten exact files, but its slowest wave takes 20.77
seconds and its outer browser duration is 65.79 seconds. Run `0ab61703` meets
schedule coverage but refuses one of ten legitimate uploads with HTTP 429.
Nine committed files verify exactly and the refused file is absent. All 632
and 629 requests respectively reconcile, with healthy storage, zero ingest
timeouts and empty outboxes. The latter run's one security occurrence matches
its identical sender/receiver record. Both runs restore policy, power off the
VM and restore one vCPU. The two-MiB profile is rejected for this workload.
Its hostile phases have not run.

## Longer Jiro-candidate endurance attempt

Run `m4-business-abuse-6b27c051` restores the three-MiB burst at 160 KiB/s.
Its clean-boot baseline passes every workload and resource gate in 57.97 seconds.
The intended sequence is a one-minute baseline and four five-minute abuse phases.
The first five-minute ERP phase completes all twenty browser waves and forty-two
file round trips, but browser work takes 322.44 seconds and its slowest wave
takes 21.96 seconds. One ingest acknowledgement times out and the health-aware
drain gate stops the sequence. Storefront, simultaneous and shared-source phases
have not started. This is a failed endurance attempt.

Independent reconciliation covers all 4,502 requests, fifty-two exact files
totaling 37,273,600 bytes, and 659 security occurrences in 250 identical
sender/receiver records. The outbox is empty, queue loss and failed writes are
zero, and export recovers after five transient failures. The ingest-timeout
counter remains one. The maximum observed writer operation takes 3.83 seconds.
Exact delivery does not satisfy the acknowledgement-latency gate.

Native sampling gaps of 4.97 and 8.07 seconds invalidate the first and last
minute. The three valid middle minutes observe 66.06%, 63.03% and 67.29% CPU.
Overlapping Windows samples continue without a four-second gap and show about
51% and 61% host utilization around the native gaps. These samples alone do not
attribute the delay to host scheduling, guest scheduling, disk or collector work.
Two overlapping host monitors cover the intended long sequence without changing
qualification sources. Cleanup succeeds, the host monitor observes VM exit and
one vCPU is restored.

M4 remains open. Resolve the acknowledgement and native-sampling tail on the
selected host before repeating the complete sequence. Retain rejected profiles,
failed evidence and exact binary identities in the qualification ledger.

## Local WSL2 qualification profile

The maintainer reported gaming during earlier host measurements and requested
continued testing on this PC. A later idle preflight measures 3.46% Windows CPU.
The original VM still develops a 102.49-second native sampling gap during ERP
abuse. Overlapping host utilization is about 22%, the VM process consumes 215
CPU seconds, and gateway CPU advances 0.88 seconds during that interval. The
earlier host-load explanation remains insufficient to attribute all delays.

Run `318d207d` also exposes a secondary diagnostic failure. Reading HTML from a
page still navigating throws before the file-write catch and aborts remaining
browser work. Failure-artifact collection now catches screenshot and HTML errors
independently, redacts errors and bounds screenshot collection. Completed upload
manifests are retained before checking runner exit. Focused regressions verify
both paths. All forty-six recovered files verify natively in a subsequent run.

With `GOMAXPROCS=2`, run `c85dbcf2` completes ERP and storefront workflows with
healthy acknowledgement status, then records 21 ingest timeouts during combined
pressure. All twenty combined-phase browser waves are retained. Reconciliation
covers 12,493 responses, 132 exact files, four absent refused files and 2,201
occurrences in 707 identical sender/receiver records, with an empty outbox. The
sequence stops before shared-source abuse. This configuration is unqualified.

The local alternative uses a dedicated WSL2 distribution, the same packaged
server and a checksum-verified cold copy of the owned Docker/business fixtures.
The source VM is powered off with its original settings. The WSL2 host kernel is
`6.18.33.2-microsoft-standard-WSL2`. Its service slice enforces four allocated
CPUs through quota and cpuset, plus four GiB aggregate memory. Gateway,
collector, Docker/containerd, application containers, relays, SSH and monitor
share that slice. Native counters measure the aggregate allocation. Twelve
host CPUs are recorded separately. WSL2 shares the host subsystem's kernel and
network environment. These results describe this service-slice profile.

The backend requires its ownership marker and an exclusive OS-released lease.
Cleanup flushes its Docker services and stops only the dedicated distribution.
Forced cleanup fails qualification. Windows localhost forwarding carries the
existing browser/source-lane traffic. Docker-managed filtering enables the
restored internal bridges, and application containers publish no ports. An
initial failed bridge-network preflight is retained separately.

Short run `44496138` passes baseline, ERP, storefront and simultaneous abuse
across all workload and resource gates. Independent evidence verifies 4,265
requests, eighty sessions, forty exact files totaling 28,672,000 bytes, and
1,043 occurrences in 352 identical sender/receiver records. The outbox is empty,
ingest timeouts, queue loss and failed writes are zero, and the maximum native
sampling gap is 1.005 seconds. Maximum observed phase CPU is 66.66%. Thirty-two
false proofs are rejected, including a forged VirtualBox-profile claim and
false allocation/cleanup metadata. All 178 earlier committed files verify and
four refused files remain absent after migration.

Shared-source abuse still refuses legitimate uploads and fails its workload
gates, while retaining valid resource and delivery evidence. M4 remains open
for that operating boundary, deployment-sensitive review and
the business pilot. The evidence reader preserves the earlier VirtualBox report
format and independently verifies historical run `c3ec075d` after these changes.

## Completed local WSL2 endurance

Run `8167d19b` completes the full sequence on the same server and WSL2 allocation.
Its baseline lasts one minute, followed by five minutes each against ERP,
storefront, both applications and the shared source. Independent verification
reconciles 19,087 requests, 336 browser sessions, 19,065 cache hits, 136 exact
files totaling 97,484,800 bytes, and 5,625 security occurrences in 1,792 identical
sender/receiver records. Forty-two refused files are absent. Thirty-two false
proofs are rejected. Policy and application settings are restored, the dedicated
distribution stops after flushing Docker services, and the source VM remains
powered off with one vCPU and its original settings.

| Phase | Browser workflows | Response budgets | Schedule coverage | Native evidence and CPU |
|---|---|---|---|---|
| Baseline | Pass | Pass | Pass | Pass |
| ERP abuse | Pass | Pass | Pass | Pass |
| Storefront abuse | Pass | Pass | Pass | Pass |
| Both applications | Pass | Pass | Pass | Pass |
| Shared-source abuse | Fail | Fail | Pass | Pass |

ERP, storefront and simultaneous browser work completes in 293.66, 293.27 and
293.47 seconds respectively, within the existing 305-second allowance. Every
one-minute resource window passes. Maximum native sampling gap is 1.019 seconds,
maximum phase CPU is 62.92% and maximum one-minute CPU is 70.18%, within the 80%
budget. Peak allocation memory is 1.41 GiB. Ingest timeouts, queue loss, failed
writes and export failures are zero, and the durable outbox is empty. Maximum
observed writer duration is 351.34 ms. The earlier VirtualBox delay remains
unresolved within that profile.

The external-source endurance profile qualifies within these recorded bounds.
The shared-source profile refuses all forty-two attempted uploads and remains
unqualified. M4 stays open for that boundary, selected deployment qualification,
independent review and the business pilot.

The prepared local fixture is consumed through `--wsl-fixture` and the same
qualification entry point. The manifest remains private with its SSH key and
business-fixture snapshot. Resource and cleanup checks reject an unowned
distribution, overlapping runs, unbounded allocation and a forged VM-profile
claim. A cleanup regression also prevents a UTF-16 byte-order mark from hiding
a still-running distribution. Failed shutdowns retain their failed state on disk.

## Upload-route reservation qualification

The earlier shared-source failure comes from the per-IP/application body bucket.
An optional exact-method/path reservation now partitions that bucket, with both
partitions also charging its aggregate ceiling under the admission lock. Client identity
follows the configured proxy trust profile and CRS inspection applies to both
partitions. Unknown-length
bodies still reserve the maximum envelope before reading. The console supports
manual editing, save/reload and empty-path disable. [Semantics](CLIENT-BODY-RATE.md).

Two rejected profiles establish the required credit. Run `c6c2adac`, with a
4 MiB total burst and a 128 KiB/s, 3 MiB reservation, refuses one baseline upload.
Nine committed files and the absent refused file verify, with one identical
sender/receiver record and no lost accounting. Run `469aefdc` increases total
burst to 5 MiB and reservation to 4 MiB. Its baseline passes, but 128 KiB/s drains
across repeated phase-start uploads. It reconciles 4,386 requests, forty-four
files and 1,170 occurrences in 348 identical receiver records. Thirty-four false
proofs are rejected. These failures retain their original outcomes.

The selected profile uses 192 KiB/s aggregate rate and 5 MiB burst for each
application/client. ERP reserves 160 KiB/s and 4 MiB for POST
/api/index.php/documents/upload, leaving 32 KiB/s and 1 MiB for other bodies.
The aggregate rate increases 20% from the earlier 160 KiB/s profile. Request
size, CRS policy, exclusions, four-CPU/four-GiB allocation, client buffer budget,
browser workload and all CPU/latency/native/delivery gates remain fixed.
Each phase's initial upload pair is included in its demand calculation.

Short run `da17b38e` passes all five phases. It verifies 4,352 requests, eighty
sessions, fifty exact files and 1,128 occurrences in 338 identical receiver
records. Thirty-four false claims are rejected. The subsequent full run
`37d22b7a` completes a one-minute baseline and four five-minute abuse phases.
All five phases pass every workload, coverage, native-resource and integrity
gate, including the previously failing shared-source phase.

Independent verification covers 19,503 requests, 336 sessions, 19,042 cache hits,
178 exact uploaded files totaling 127,590,400 bytes, and 6,029 occurrences in
1,805 identical sender/receiver records. Every attempted upload commits. The
native probe additionally verifies 239 prior files and forty-nine prior refused
files remain absent. Ingest timeouts, queue loss, failed writes and export
failures are zero. The outbox is empty. Maximum sampling gap is 1.019835
seconds, maximum phase CPU 51.30%, maximum one-minute CPU 64.30%, peak
allocation memory 1,682,612,224 bytes and maximum writer duration 360.601 ms.

| Phase | Navigation p95 ms | File p95 ms | All gates |
| --- | ---: | ---: | --- |
| nat-baseline | 1218.101 | 3324.536 | Pass |
| nat-erp-abuse | 1056.668 | 3431.682 | Pass |
| nat-shop-abuse | 1113.893 | 4179.689 | Pass |
| nat-both-abuse | 1117.262 | 4055.419 | Pass |
| nat-shared-abuse | 1103.145 | 4869.915 | Pass |

Thirty-four fabricated qualification claims are rejected for each accepted run.

The selected package and server identities are recorded in the current candidate
ledger. Frozen harness source, native samples, request hashes, exact-file probes
and both delivery databases are retained locally. The source VM stays off with
its original settings and the dedicated WSL2 lab stops cleanly. Only its owned
distribution is terminated. WSL2 remains a four-CPU/four-GiB service-slice
qualification, with twelve host CPUs reported separately.

The reservation isolates cross-route consumption. An attacker targeting that
same route shares its credit and can cause legitimate refusals. Authentication
and authorization remain application responsibilities. The allocation defaults
to disabled. Selected-host/TLS/identity qualification, independent review and
the business pilot remain open. M4 remains open, with pilot preparation awaiting deployment qualification and review.
