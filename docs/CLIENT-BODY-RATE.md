# Client request-body byte budgets

Candidate `32d099011bde` adds two optional schema-2 traffic controls.

```json
{
  "client_body_kib_per_second": 160,
  "client_body_burst_kib": 4096
}
```

Both fields default to zero and are omitted when disabled. Existing policies
retain their previous behavior. The console exposes both fields under Security
policy, alongside request-rate, concurrency and buffer controls. Save, reload
and disable operations are checked in real Chrome.

Each application/client identity has a bounded token bucket measured in KiB.
A known body length is rounded upward to the next KiB. Bodyless asset requests
consume zero body credit. Unknown-length bodies reserve the complete configured
request envelope before reading, preventing chunked framing from bypassing the
budget. Oversized declared bodies are charged up to that envelope and remain
subject to the existing hard body limit. Partial or cancelled uploads retain
the admitted charge. Credits refill with elapsed time.

Application request rate, client request rate, body credit and buffer/concurrency
admission are checked under the same lock. An admission refusal consumes no token
from any bucket. A body-budget refusal returns HTTP 429 and `Retry-After`, with
the fixed reason `Client request body rate exceeded`. It occurs before body
buffering, transaction creation and upstream forwarding. Existing rate-refusal
event accounting and export apply.

The burst must fit one maximum configured request. Rate and burst must both be
positive or both zero, with at most ten minutes of accumulated credit. The rate
is bounded at 1,048,576 KiB/s and burst at 8,388,608 KiB. State reuses the existing
bounded table of 1,024 client identities per application, including its eviction
and policy-change behavior.

The charged amount is the HTTP body, including JSON/base64 overhead. For the
lab's 700-KiB file, the JSON upload is about 934 charged KiB. Two such uploads
every fifteen seconds need about 125 KiB/s, with additional credit required for
phase-start upload pairs and other forms. The experiment uses 160 KiB/s and a
four-MiB burst for the first screen. Endurance repeats with a three-MiB burst
to reduce simultaneous inspection pressure at startup. These are
workload-specific values undergoing qualification.

The identity is the gateway's resolved network identity under its configured
proxy trust profile. Users behind one NAT share the budget. An abusive sender
on that same identity can compete with legitimate uploads. That boundary is
tested separately from an external attacker targeting shared-NAT users.

Regression checks cover refill/retry values, application/client isolation,
bodyless traffic, atomic capacity refusals, configuration validation and
unknown-length rejection before body reading. Full platform, CRS and race
results are recorded in the current candidate ledger. The request envelope,
CRS policy and inspection behavior remain independently configured.
