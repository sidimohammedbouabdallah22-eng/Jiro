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

## Optional reservation for an upload route

A client budget can reserve a partition for one exact method and path. The
administrator console exposes method, path, rate and burst fields. An empty
path disables the reservation. The API accepts the following optional object
inside the application's traffic controls.

```json
{
  "client_body_kib_per_second": 192,
  "client_body_burst_kib": 5120,
  "client_body_reservation": {
    "method": "POST",
    "path": "/api/index.php/documents/upload",
    "kib_per_second": 160,
    "burst_kib": 4096
  }
}
```

The reserved route receives 160 KiB/s and 4 MiB burst. Other bodies receive the
remaining 32 KiB/s and 1 MiB burst. Both partitions also consume the aggregate
192 KiB/s, 5 MiB bucket atomically. A refusal spends no credit. All request-rate,
concurrency, buffer, unknown-length envelope and CRS checks continue to apply.
Unused partition credits remain in that partition. Bodyless traffic costs zero.
Both partitions must fit one maximum request. Existing configurations without
the object retain their original behavior and bounded client identity table.

Matching uses the exact case-sensitive method and escaped path. Query parameters
do not select a different partition. Configuration accepts POST, PUT or PATCH
and a canonical unescaped path, with no wildcard, query or fragment. Aliases,
encoded paths and trailing slashes use the general partition unless they match
the configured literal. Operators must verify application routing conventions.

This is a route allocation. Requests aimed at the reserved route share its
credit, including malicious requests. Cookies, API-key headers and user-supplied
forwarded addresses grant no extra credit. The application still authenticates
and authorizes uploads. The M4 shared-source profile tests cross-route abuse,
and same-route exhaustion remains an explicit boundary. No pilot claim follows
from this synthetic profile.

Older binaries reject the new configuration field. Upgrade or rollback checks
must use the complete policy history and a compatible checkpoint. Clearing the
active reservation leaves historical snapshots that still require a compatible
reader.
