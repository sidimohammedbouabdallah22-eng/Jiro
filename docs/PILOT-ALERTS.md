# Pilot fault detection and webhook delivery

`scripts/pilot_alerts.py` runs independently of pilot sampling. It reads the
manifest-pinned pilot evidence database and durably queues failure/recovery
transitions. It detects failed samples, evidence unavailable to its account,
samples older than 180 seconds, invalid sample timing, watchdog clock reversal
and an evidence-reading backlog. It does not change samples or daily reviews.

The current lab qualification passes. No business pilot or real operator
notification path has been qualified. The webhook receiver in that qualification
is an isolated local test service, not a mail, chat or incident-management system.

## Deploy the watchdog

Complete `config/pilot-alerts.example.json` alongside the reviewed pilot manifest.
Choose a concrete deployment identifier, absolute manifest/evidence/token paths
and an approved webhook endpoint. Store the distinct webhook bearer token in a
0600 file owned by the watchdog account; restrict Windows ACLs when applicable.
The monitoring token stays in the pilot manifest's separate restricted file.

Install `pilot.py` and `pilot_alerts.py` together at `/opt/openwaf-pilot`. The
example `deploy/linux/openwaf-pilot-alerts.service` and `.timer` use the existing
`openwaf-pilot` account, with read-only access to `/var/lib/openwaf-pilot` and a
separate writable 0700 `/var/lib/openwaf-pilot-alerts` directory. Install the
completed config at `/etc/openwaf-pilot/alerts.json`. The service has no dependency
on the sampler or WAF being up. The timer runs independently each minute.

Run the service manually and inspect a healthy result before enabling the timer.
Use absolute deployed paths for a direct invocation:

```sh
python3 /opt/openwaf-pilot/pilot_alerts.py \
  --config /etc/openwaf-pilot/alerts.json \
  --state /var/lib/openwaf-pilot-alerts/outbox.db
```

The state file is created exclusively on first use. Config identity is pinned;
changing the config requires a new state path. Drain/preserve an existing outbox
before replacing it. Token contents can rotate without changing the config.
Exit 0 means no active condition and no pending delivery; 1 means an active
condition or pending delivery; 2 means watchdog configuration/storage failure.
Monitor nonzero service results and missing watchdog executions independently.

## Receiver contract and bounds

The watchdog POSTs JSON to the configured endpoint with a bearer credential.
Remote endpoints require verified HTTPS. HTTP is permitted only on loopback.
Proxy environment variables are ignored; redirects are rejected. Notifications
contain only schema, event ID, deployment identifier, `firing`/`resolved`, a fixed
reason, safe failed-check names and observation time. They exclude probe bodies,
URLs, credentials, cookies, application logs and raw exception messages.

The receiver must durably commit and deduplicate `event_id` **before** replying
HTTP 200 with:

```json
{"accepted": true, "event_id": "the-exact-received-event-id"}
```

An arbitrary successful status or mismatched ID is not acknowledgement. Delivery
is at least once: an uncertain acknowledgement can cause retry of the same ID.
Receivers must tolerate that replay with identical payload bytes. Firing and
resolution use distinct event IDs; group conditions by deployment, reason and
failed-check names. Receiver acknowledgement proves receipt, not human review
or notification delivery by a downstream integration.

SQLite FULL synchronization preserves pending transitions across watchdog
restarts. Each invocation reads at most 256 new samples and attempts at most
eight deliveries with a 20-second batch budget. Each network worker is bounded
to five seconds; response bodies are limited to 4 KiB. A failed delivery stops
the batch and retries at the next invocation. Pending rows are never evicted.
The outbox allows 1,024 pending transitions and a 32-MiB main database, retaining
a bounded recent acknowledged history. Exhaustion is an explicit failure, not
silent pruning. Allow space for SQLite journals as well as the main database.

This watchdog is a local component. A full filesystem shared by its outbox,
host power loss, a dead timer or a broken notification service needs independent
supervision. Put its storage/receiver in a separate failure domain where the
deployment requires that guarantee. Do not treat a same-host webhook or a
timer's presence as a complete operator alert path.

## Deployed qualification, 5 November 2026

`artifacts/m4-alerts-bdf3989b/result.json` and `verification.json` pass on the
owned Ubuntu 24.04 amd64 VM with packaged server SHA-256
`cef0916699fa8adef803c46e74d2a73f995156b15a550f5304283a0d3216794f`.
The Go runtime and rule bundle did not change. The test renders the sampler and
watchdog service templates with isolated paths/accounts and invokes the real
systemd oneshots. Timer templates are supplied; automatic scheduling and the
actual recipient's downstream integration still require deployment qualification.

Fourteen cases cover:

- Healthy scoped monitoring and a verified-TLS, exact-body application canary.
- Rejected invalid certificate/key reload while the previous certificate and
  enforcing traffic continue; healthy reload recovery.
- Alert receiver unavailable, then an incorrect acknowledgement, then retry
  from a new watchdog process. The same event ID is received twice and stored
  once before its exact acknowledgement drains the outbox.
- Unresponsive security/audit receivers, degraded health, durable pending
  delivery and recovery. Receivers are suspended/resumed: explicitly stopping a
  required systemd dependency would also stop the WAF and test another failure.
- Actual event-storage ENOSPC in a dedicated **16-MiB tmpfs**, without filling
  the VM's root filesystem. The attack stays blocked, one event write is
  explicitly unacknowledged, and health remains degraded after freeing padding.
  Controlled restart, replay and subsequent delivery pass. Restarting resets
  process-lifetime health counters; it does not recover the missing event.
- A real 182-second sampling pause, acknowledged missing-sample alert, resumed
  sampling and recovery. No clocks or evidence timestamps are changed.
- Evidence made unreadable to the unprivileged watchdog, then restored;
  the independent watchdog emits failure/recovery without modifying the record.

Twelve alert/recovery transitions are acknowledged, with one replayed identity
deduplicated. Three committed security events and all 33 final audit records
match their independent receiver bytes. The deliberately failed disk-full write
is recorded separately; it is not counted as committed or recovered evidence.
Private captured databases contain no monitoring/webhook bearer secrets.
The checker rejects seven invalid proof mutations.

Six watchdog tests pass on Windows and Linux; eight existing pilot tests pass
on Windows. These are synthetic collector tests, not pilot days. Failed lab
fixtures `m4-alerts-325abb6c` and `m4-alerts-73aa0d2a` remain retained: they exposed
staged-script traversal and overly broad template substitution errors, corrected
before the passing run. Captured sources identify the exact measurement version;
the runner subsequently also restricts retained SQL excerpt files to mode 0600.
The VM ends powered off and all evidence remains retained.

Recheck the recorded databases with:

```powershell
python scripts/check-alert-evidence.py `
  artifacts/m4-alerts-bdf3989b/result.json `
  --package artifacts/rule-candidate-5777d82f469c/openwaf-rule-candidate-linux-amd64.tar.gz
```

The archives include private lab credentials and must not be published. The
actual business host, recipient acknowledgement/notification, supervisor alerts,
capacity, independent review and 30 reviewed pilot days remain open.
