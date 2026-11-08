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
