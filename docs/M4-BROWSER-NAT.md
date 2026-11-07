# Browser and shared-NAT qualification

## Workload and measurement

The browser harness uses installed Chrome through Playwright against the owned
Dolibarr and PrestaShop fixtures. Two ERP users and two storefront customers
authenticate in separate browser contexts. It checks ERP account IDs and
storefront account email, customer lists, saved addresses, product pages and
warm-cache requests. Canonical-origin resource errors, failed requests and
HTTP 429 responses fail the workload. Cookie values are retained only as
SHA-256 fingerprints in public reports. Credentials stay in private fixtures.

Two parallel 700-KiB mixed CSV files are uploaded and downloaded through the
Playwright API client before each profile and after each ERP administrator
session. These exercise the authenticated API alongside browser navigation.
They use the existing synthetic invoice. Native file probes check exact bytes
and hashes and require refused uploads to be absent. Business probes compare
ERP customer rows and storefront orders before and after the test. Each run
retains its newly created synthetic customer and files.

Four loopback-only HTTP measurement proxies forward to source-bound guest
relays. Separate-user profiles use four actual TCP peers. Shared-NAT profiles
send all contexts through `127.0.0.2`. The measurement proxy buffers responses
up to eight MiB and adds transport overhead. It permits only the two lab
authorities, including HTTP CONNECT used by Playwright's API client.
External browser background requests are refused locally and recorded by host.
This harness covers HTTP on one Linux amd64 VM. Browser timing includes the
measurement transport.

## Compared configurations

The test temporarily allocates four vCPUs with four GiB RAM and restores the
original one-vCPU allocation after shutdown. Its gateway has 64 active slots,
128 connections and the existing 64-MiB global buffer budget. The service
memory limit stays 512 MiB. Each source relay permits 64 children with a
128-MiB service memory limit. The resource sampler includes those relay
cgroups. These are explicit experimental allocations.

| Profile | Application slots | Client slots | Client rate/burst | Client buffer | Users |
|---|---|---|---|---|---|
| Reference | 32 | Disabled | Disabled | Global budget | Sequential, separate peers |
| Strict separate | 4 | 3 | 2/s, burst 4 | 5 MiB | Concurrent, separate peers |
| Strict shared | 4 | 3 | 2/s, burst 4 | 5 MiB | Concurrent, shared peer |
| NAT candidate | 32 | Disabled | 30/s, burst 96 | 12 MiB | Concurrent, shared peer |

All profiles keep one-second bounded admission waiting, the full one-MiB
request envelope and the original enforcing CRS policies. Configuration is
restored after the experiment. The NAT candidate is a workload hypothesis.
Its higher limits require their own abuse qualification before adoption.
The previous sustained-abuse evidence applies to its recorded stricter limits.

Each profile has at least thirty seconds of resource observation. Reports
separate active workload time from minimum observation time, since padding a
short workload can lower phase-average CPU readings. This screen establishes
neither customer sizing nor endurance.

## Findings during harness development

The first run, `m4-business-abuse-924b20c5`, exposed Playwright's HTTP CONNECT
behavior. The proxy now parses the allowlisted HTTP requests carried inside
that connection. A regression test also checks HEAD lengths, bodyless 304
responses and rejection of external CONNECT targets.

The second run, `m4-business-abuse-b5e68c9a`, authenticated all four accounts
and completed the file round trips, but failed on thirty storefront image
404s and stale localhost module-image URLs. Product images were present.
The temporary domain helper had left the native Apache image rewrite rules
and Smarty cache bound to the original host. The helper now invokes native
rewrite generation and cache clearing after switching domains. The storefront
menu module separately caches absolute URLs outside Smarty, so its native
cache-invalidation hook is also invoked. Browser checks follow a category link
and require its authority to match the canonical shop. The helper snapshots
and restores the original `.htaccess` bytes alongside the original shop URLs.
The stricter browser oracle retains these failures.

Run `m4-business-abuse-1f82ea4e` removed the image failures but exposed an
ambiguous account-email selector in the harness. The selector now targets the
account field. This run also records a pre-setup initramfs stall, an unresponsive
ACPI request, a cold restart and recovery after pause/resume of the second boot.
The underlying boot issue remains unresolved.

Run `m4-business-abuse-f9a27560` records two upstream 502s during the initial
upload pair and a 28.747-second native sampling gap. Playwright times out before
the gateway replies. This run fails qualification and is retained. Its policy
and original hardware allocation were restored. No successful capacity claim
is derived from that run.

Run `m4-business-abuse-a2701efd` exposes a production deadline defect. A
storefront login gets HTTP 200 with an empty body. Its matching gateway event
records cancellation at 15,003.885 ms, while the backend access log records a
nonempty response. The gateway left its downstream request-body read deadline
armed during upstream processing. The server's background disconnect read
could consequently cancel a completed-body request at that deadline.

The fix clears the downstream read deadline after successful full-body reading
and framing checks. The existing request context still bounds the entire
operation. Real HTTP-socket GET and POST regression cases use a one-second
body deadline, a five-second overall deadline and a 1.5-second backend delay.
The previous frozen candidate reproduces the empty GET 200 in
`m4-body-deadline-before-3907623d`; the fixed source passes both cases and the
existing slow-body/overall-timeout check. Qualification of the new package is
tracked separately from the earlier sustained-abuse package.

The fixed package's first complete comparison, `m4-business-abuse-4369dd65`,
verifies 1,214 requests, 28 browser sessions, 18 files totaling 12,902,400 bytes
and 349 occurrences in eighteen identical sender/receiver records. Twelve
fabricated evidence claims are rejected. The reference passes. Strict separate
peers produce 203 rate refusals and eight capacity refusals, and strict shared
NAT produces 136 rate refusals and two capacity refusals. The earlier API abuse
profile therefore rejects normal full-browser asset bursts even with distinct
user addresses.

All 636 gateway responses in the four-wave NAT candidate are successful, but
Chrome reports one local `ERR_PROXY_CONNECTION_FAILED`. That profile fails the
browser oracle. The measurement server's default accept backlog of five is
increased to 128 for the repetition. Its request concurrency semaphore stays
64. The failed result and its independent verification are retained.

## Verified repetition

Run `m4-business-abuse-68207648` passes the reference and all four NAT-candidate
waves on `20031ed996b3`. Its 1,201 total requests, 28 browser sessions, 1,180
cache hits, seventeen committed files totaling 12,185,600 bytes and three absent
refused uploads verify. All 339 security occurrences reconcile to seventeen
identical sender/receiver records with an empty durable outbox. Twelve false
evidence claims are rejected. Protected customer/order state and original
configuration verify after the run. The VM ends off with one vCPU restored.

| Profile | Gateway requests | 429 | 503 | Browser outcome |
|---|---|---|---|---|
| Reference | 164 | 0 | 0 | Pass |
| Strict separate | 243 | 198 | 2 | Fail |
| Strict shared | 159 | 138 | 1 | Fail |
| NAT candidate | 634 | 0 | 0 | Pass |

The remaining request is the parent invoice preflight. The NAT phase contains
sixteen authenticated browser sessions and ten exact large-file API round
trips, with no resource errors or failed browser requests. Its active workload
takes 57.90 seconds. Phase-observed CPU is 27.38% and peak gateway RSS is
164,292 KiB. These are short-screen observations. The strict phases include
minimum-observation padding, as recorded in their raw reports.

The repetition also verifies the preceding run's eighteen retained files and
four absent refused files. Earlier failed baseline manifests verify in that
preceding run. The two ambiguous timed-out uploads from `f9a27560` are checked
separately and both are absent, with both captured error payloads identical at
the sender and receiver. The failed runs remain available.

The higher-limit NAT profile still needs combined authenticated/browser and
CPU-abuse endurance in each direction and simultaneously, including shared
source contention. Final-package operational repetitions, selected-host
sizing, independent review and the pilot remain M4 gates. The earlier
thirty-minute abuse result belongs to `7be7bc728f08` and its stricter controls.

Passing comparison proof (private lab artifact),
negative evidence checks (private lab artifact),
preceding failed transport screen (private lab artifact).

## Execution

```powershell
python scripts/qualify-browser-nat.py --package artifacts/rule-candidate-7be7bc728f08/openwaf-rule-candidate-linux-amd64.tar.gz --disposable-vm --waves 4
```

After a completed run, independently recompute its claims.

```powershell
python scripts/check-browser-nat-evidence.py artifacts/<run>/result.json --package artifacts/rule-candidate-7be7bc728f08/openwaf-rule-candidate-linux-amd64.tar.gz
python scripts/reject-browser-nat-mutations.py artifacts/<run>/result.json --package artifacts/rule-candidate-7be7bc728f08/openwaf-rule-candidate-linux-amd64.tar.gz
```

The checker compares archived candidate and harness hashes, native resource
samples, browser outcomes, real source lanes, applied limits, durable event
payloads and receiver totals. It distinguishes valid measurement of a failed
profile from an accepted browser workload. M4 remains open.
