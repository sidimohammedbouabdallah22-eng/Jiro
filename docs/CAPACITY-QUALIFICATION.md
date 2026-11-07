# M4 deployment capacity qualification

Status on 4 November 2026: the first native application reference run passed at five mixed requests/second on the colocated one-vCPU/4-GiB profile, including separate large-body, concurrency, backend-fault and durable-delivery checks. Ten and 25 requests/second encountered admission refusals under that configuration and remain unqualified. [Measured results and retained failures](M4-CAPACITY-RESULTS.md) Existing M3 gateway-only sizing remains recorded in `M3-COMPLETION.md`. These workload-specific observations do not establish customer deployment capacity without declared application budgets and headroom.

## Record the target before measuring

Record artifact/server and rule checksums, OS/kernel, VM/hypervisor, vCPUs, RAM, disk, networking/TLS, trusted proxy topology, application placement, pool settings, policy/body limits, response inspection, rate/admission shares, storage/export bounds and collector destination. Pin application images and the sanitized workload. Identify which components share resources. Measure the generator separately and record its limits.

The application owner must supply expected peak rate/concurrency, representative request/response sizes, workflow mix, acceptable latency/error rates and required operating headroom. A lab staircase can discover saturation before those decisions; it cannot select an acceptable business latency budget. Keep DVWA on the isolated qualification network.

## Workload matrix

| Dimension | Required observations |
|---|---|
| Normal application traffic | Read/search, authenticated publish/update/delete, valid media upload/download and relevant API/webhook workflows; verify application outcome as well as status |
| Attack mix | Paired proven DVWA attacks and ordinary CRS probes; maintain a fixed seed/mix and expected verdict per case |
| Body sizes | Small inputs, valid 64-KiB/256-KiB bodies, near the configured request limit, and deliberate over-limit cases; record expected application/WAF rejection separately |
| Concurrency | One application alone, both applications together, sustained concurrency and bursts; verify that an abusive application cannot consume another's configured admission share |
| Backend behavior | Healthy baseline, controlled delay, header deadline and unavailable backend; verify bounded occupancy and recovery without retrying non-idempotent application operations |
| Evidence delivery | Healthy independent collector, temporary outage, backlog drain and acknowledgement reconciliation; inspect local event/audit health throughout |
| Policy | Actual intended paranoia/body/response-inspection settings; compare direct application baseline with inspected traffic under otherwise identical conditions |

Use benign direct requests to establish backend latency before WAF comparison. Establish each attack's direct baseline in the vulnerable fixture. Do not send executable-upload or command-injection probes to customer applications.

## Run order and stop criteria

1. Warm the products and verify all functional cases at low load. Record baseline counters and independent receiver positions.
2. Run a bounded offered-rate staircase, initially 5, 10 and 25 requests/second for the one-vCPU lab; attempt higher rates only while occupancy, latency, storage and backend health permit. These are measurement points, not promised capacity. Start with short screening phases, then retain at least five minutes of steady-state evidence at each proposed operating point.
3. Exercise the body-size, burst/fairness and delayed-backend cases independently so failures remain attributable. Repeat the representative combined workload at the proposed operating point for at least ten minutes.
4. Measure collector interruption and backlog recovery separately. Stop scheduling when storage/export or resource limits require it. Let in-flight requests and acknowledged evidence settle, then reconcile records and counted occurrences.
5. Retest a failed case after correction and retain the original result. Run longer endurance at the selected deployment profile before admitting it to the pilot; the reviewed 30-day observation remains a separate gate.

Bound total scheduled requests, outstanding requests, retained latency observations and execution time. Count missed scheduling deadlines and generator-side queue refusals explicitly. Use offered-load scheduling and latency measured from the scheduled request time to expose queuing; report service-time latency separately where available. A generator that silently slows down with the server cannot support an overload capacity claim.

Stop a phase for unexplained benign verdicts, unexpected network/application errors, evidence-loss indicators, unbounded queues/memory, failed export reconciliation or resource exhaustion. Intentional overload responses and configured application rate refusals remain counted results; distinguish them from the healthy operating envelope. Customer traffic must never be used to discover destructive limits.

## Required report

Report intended/offered/completed rates, scheduling misses, per-workflow expected/unexpected statuses, timeouts, p50/p95/p99/max latency, CPU utilization with its vCPU basis, gateway RSS/peak, host/application resource usage, active connections/requests and configured budgets. Record policy revision and health/counter changes. Counter resets must be explained by recorded process lifecycle changes.

Record persistence errors, queue drops, ingestion timeouts, write failures, overload summaries, export pending/acknowledged records and counted occurrences. Reconcile the independent receiver after drain. A successful HTTP response cannot substitute for acknowledged evidence accounting.

State the highest tested operating point that meets the predeclared workflow and resource budgets, the first observed limiting component and measured spare capacity. If no operator budgets exist, publish observations and limitations with **deployment capacity gate open**. Keep hardware, workload and inspection settings beside every throughput claim. Review these results before starting the [pilot](PILOT.md).

The [large-body CPU study](M4-CPU-QUALIFICATION.md) adds a separate competition protocol: legitimate offered-rate traffic alongside bounded closed-loop heavy workers, including an input that falls back to the original matcher. Report heavy refusals and timeouts separately from legitimate traffic. Concurrency shares and HTTP deadlines do not establish preemptive CPU isolation. Archive the exact driver sources, wait for inspection/export drain and independently compare stopped databases before accepting delivery results.
