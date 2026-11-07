# M4 qualification findings

These are scoped qualification findings, not a list of confirmed vulnerabilities. Retain adverse evidence and review operating requirements before accepting a finding for a pilot.

| ID | Finding and evidence | Required follow-up | Status |
|---|---|---|---|
| M4-PERF-001 | Regex scans dominate the isolated near-limit JSON benchmark. A conservative downstream ASCII guard reduces the native 900-KiB sample from 5.23 s to 0.82 s; full CRS and real-product regressions pass. Unicode/varied input can retain the original cost. [CPU evidence and patch contract](M4-CPU-QUALIFICATION.md) | Independently review the downstream algorithm and maintenance plan. Qualify actual body formats, Unicode, latency and memory budgets on the chosen deployment; retain size-specific limits. | Targeted correction implemented and measured; customer large-body capacity remains open |
| M4-CAP-002 | With eight WordPress admission slots, 25 requests/second caused counted refusals. Longer ten-request/second schedules also encountered a refusal. Five-request/second five/ten-minute schedules passed. Event delivery reconciled in both adverse and successful runs. [Retained results](M4-CAPACITY-RESULTS.md) | Test the selected deployment's application placement, CPU, connection pattern and explicit concurrency allocation. Keep refusals visible; changing resource settings creates a new measured profile. | Five-request reference established; higher-rate/customer points remain unqualified |
| M4-ISO-003 | Four CPU-heavy 900-KiB inspections preserve the lab's legitimate WordPress latency budget but cause heavy-client timeouts on the Unicode fallback path. A one-slot application policy eliminates those observed timeouts by refusing excess work; shared CPU remains saturated. [Contention evidence](M4-CPU-QUALIFICATION.md) | Select body/admission budgets or separated CPU/process allocations against the actual abuse requirements; run deployment endurance. HTTP deadlines do not preempt synchronous regex evaluation. | Scoped competition and mitigation tested; hard CPU isolation and customer abuse profile remain unqualified |
| M4-REL-005 | An exhausted total request budget could incorrectly degrade a backend circuit, including before transport began. CPU-heavy inspection exposed this attribution error. [Regression and corrected-candidate evidence](M4-CPU-QUALIFICATION.md) | Preserve paired pre-transport/in-flight deadline regressions and genuine backend header-timeout checks. Keep total request budgets separate from backend health attribution. | Corrected in the connector; included in candidate qualification |
| M4-DEPLOY-004 | The representative lab cohort is selected: DVWA, PrestaShop and Dolibarr, followed by ERPNext. Actual pilot workload, continuously available host, named reviewer and traffic/latency/headroom budgets remain unspecified. The isolated lab is not a business pilot. | Qualify the [business-application matrix](M4-BUSINESS-APPLICATIONS.md); complete the [pilot entry gates](PILOT.md), actual TLS/identity/factor recovery configuration, alert delivery and deployed recovery/rollback drills; arrange independent security review. | Open; M4 and customer capacity gates remain open |
| M4-COMPAT-006 | Schema-2 forwarding rewrote HTTP Host to the upstream address, causing PrestaShop canonical redirect loops. | Preserve the validated application authority while keeping the configured dial/TLS target; retain unknown-host and spoofed-forwarded-header regressions. Review schema-2 backends that depended on target-address Host before upgrade. Repeat deployment qualification on the new binary. [Evidence](M4-BUSINESS-RESULTS.md) | Corrected; unit/integration, CRS and first business workflows pass on the new candidate. Wider deployment qualification remains open |


M4-ISO-003 extension on 6 November 2026: real ERP/storefront qualification
reproduces eight large-Unicode client timeouts with eight admission slots.
All timeout events are durably exported and the failed run is retained. One
ERP slot eliminates the observed timeouts and preserves the storefront budget,
but CPU remains saturated; a temporary 64-KiB body cap plus one request/second
reduces observed CPU to about 37–51% in the measured screens. That stricter
profile rejects the larger legitimate upload workflow. No general CPU-time
isolation, arbitrary deadline preemption or actual customer abuse qualification
is claimed. A separate normal-load thirty-minute joint profile passes all six
five-minute windows. [Exact evidence and tradeoffs](M4-JOINT-ENDURANCE-ABUSE.md)

The five-request/second sustained reference qualification passed with independently verified database evidence. It provides evidence for that exact profile; it does not close the findings above or certify a company-size capacity claim. [Measurement protocol](CAPACITY-QUALIFICATION.md)

The corrected binary additionally passes a 30-minute mixed schedule and separate
verified-TLS HTTP/1.1/HTTP/2 application workloads. Strict resource/coverage gates
and captured security-status counts are now independently verified. The initial
test CA lacked a key-usage extension and was correctly rejected; its fixture is
retained as failed, and the corrected issuer passes with verification enabled.
Deployment-specific limits, hostile-workload endurance and independent review
remain open. [New evidence and scope](M4-ENDURANCE-TRANSPORTS.md)
