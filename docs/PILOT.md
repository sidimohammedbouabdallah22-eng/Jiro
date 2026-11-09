# Preparing the 30-day pilot

The pilot is 30 consecutive days of observed, reviewed operation on an agreed continuously available host. It does not require a chat or an engineer to run continuously. A local collector samples health and approved application canaries; an accountable operator reviews the evidence daily and responds to incidents. No business pilot has started. The isolated DVWA/WordPress/Keycloak lab is qualification evidence only.

## Entry gates

The selected package now passes controlled-backend fresh-OS restore on a new
Ubuntu 24.04 VM, including application TLS and enrolled administrator factors.
Its deployed alert rehearsal also verifies the shipped systemd schedules and
watchdog notification while the sampler is stopped. Dolibarr, PrestaShop and
Jiro also pass coordinated recovery on a separately provisioned Ubuntu OS.
These local proofs leave the actual business host, deployment DNS/TLS chain,
provider recovery, real recipient notification and watchdog supervision for
deployment qualification. [Business recovery](M4-BUSINESS-RECOVERY.md),
[fresh-host evidence](M4-FRESH-HOST-RECOVERY.md),
[alert evidence](PILOT-ALERTS.md).

Choose a named operator, a continuously available host, a protected business application, an identity provider and a maintenance/recovery window. Review the supported protocols, backend bypass prevention, TLS, capacity/headroom, application workflows, monitoring and backup destination. Establish an independent alert path and a way to stop or roll back the pilot. Keep administration on loopback through a managed tunnel when necessary.

Record the exact package and engine patch identity in the reviewed qualification
evidence. The current downstream regex guard requires independent review and
explicit patch-maintenance ownership. Size the actual body/Unicode distribution
and CPU-heavy competing traffic, not only short benign requests. Choose body and
admission limits or separate CPU/process allocations to meet the agreed latency
and spare-capacity budgets, then qualify endurance at that profile. The shared
lab's short competition checks do not establish hard CPU isolation.
[CPU evidence and remaining limits](M4-CPU-QUALIFICATION.md)

Record representative authenticated workflows: sign-in/out, search, publishing or transactions, uploads, API methods, errors and any webhooks. Replay sanitized inputs in staging. Review false blocks against recorded rule IDs and tune the narrowest application/route/field scope, with paired attack tests. DVWA's intentional vulnerabilities support controlled attack tests; it must remain isolated from the business deployment. WAF filtering cannot establish application authorization or repair application vulnerabilities.

Start in an agreed observation/tuning phase if necessary. The qualifying window requires all protected policies to enforce and all required probes to pass. An observation-only period does not satisfy that window.

The local coordinated business recovery rehearsal now passes for the selected
candidate. It covers upstream databases/filesystems alongside WAF state in
replacement containers on the same WSL2 host. Qualify the actual deployment's
application backup, restore destination, credentials and downtime procedure
before pilot entry. [Reference drill and remaining boundaries](M4-BUSINESS-RECOVERY.md).

## Evidence collector

`scripts/pilot.py` uses Python's standard library. Copy and complete `config/pilot.example.json`; placeholders are rejected. Reference reviewed qualification and sizing evidence, and define 1–8 read-only canaries with explicit success status and reviewed SHA-256 response-body digests. Choose stable, meaningful application responses. Dynamic pages need a dedicated stable canary; hashing changing pages creates failures. The collector sends no application credentials and supports no redirect following. Authenticated business workflows require separate controlled probes and daily evidence references.

Issue an expiring automation token with **only `monitoring:read`**, owned by a dedicated enabled account with no application restrictions. Store it in an absolute file path readable only by the collector owner (0600 on Linux; restrict its Windows ACL). Bootstrap credentials and broader tokens fail the credential check. Plan renewal before token expiry; changing the token file contents permits rotation without changing the pinned manifest. Account changes can revoke tokens. Never put bearer secrets, login data or personal payloads in a manifest, review note or command line.

Run these commands as the evidence directory's owner, supplying absolute deployed paths:

```sh
python3 /opt/openwaf-pilot/pilot.py start --manifest /etc/openwaf-pilot/manifest.json --database /var/lib/openwaf-pilot/evidence.db
python3 /opt/openwaf-pilot/pilot.py sample --manifest /etc/openwaf-pilot/manifest.json --database /var/lib/openwaf-pilot/evidence.db
python3 /opt/openwaf-pilot/pilot.py status --manifest /etc/openwaf-pilot/manifest.json --database /var/lib/openwaf-pilot/evidence.db
```

`start` exclusively creates a new database and records the first sample. It cannot overwrite an earlier window. `sample` stores failed observations as well as successful ones, and exits 1 when unhealthy. Configuration/storage failures exit 2. Do not discard failed runs. A changed manifest requires a new evidence database; retain the previous one and record why the deployment changed.

Samples check the scoped identity, gateway health in enforcing mode, selected numeric metrics, exact canary responses and optional OIDC discovery issuer. Requests use verified HTTPS remotely, permit HTTP only on loopback, ignore proxy environment variables, reject redirects, apply three-second socket timeouts and read at most 1 MiB each. A supervised worker bounds the complete probe sequence to 45 seconds, including stalled DNS or trickled responses; timeout records a failed sample. Samples persist check outcomes/timings, numeric counters and policy revision. They omit response bodies, error pages, URLs, bearer tokens, cookies and raw exception messages. An origin in the manifest is still operational information: protect the manifest and database.

SQLite transactions use FULL synchronization and a 512-MiB page quota; overlapping samples serialize. A failed write is a collector failure and must alert. The collector never trims old evidence to keep a window looking complete. Monitor host free space and back up/export this database independently of the gateway. It is local operator evidence, with no tamper-resistant signature or remote availability guarantee.

The example systemd service and timer in `deploy/linux/openwaf-pilot.*` run once per minute. They are deployment templates and are not automatically installed by the gateway package. Before enabling them:

1. Create a dedicated `openwaf-pilot` system account, a 0700 `/var/lib/openwaf-pilot` directory it owns, and a restricted `/etc/openwaf-pilot` directory.
2. Install the script at `/opt/openwaf-pilot/pilot.py`, the completed manifest at `/etc/openwaf-pilot/manifest.json`, and the 0600 monitoring token owned by that account. Grant the account read access to the manifest.
3. Run `start` as that account. Verify one healthy sample and inspect the canary responses yourself.
4. Install the service/timer, run `systemctl daemon-reload`, then `systemctl enable --now openwaf-pilot.timer`.
5. Deploy and qualify the independent [alert watchdog](PILOT-ALERTS.md), or integrate equivalent monitoring. Its separate timer, durable outbox and exact-ID webhook acknowledgement now have deployed lab fault evidence. Monitor watchdog failure/missing executions externally too. Verify actual recipient notification by an agreed harmless probe failure and restore the probe; a timer or local receiver receipt alone does not prove that delivery.

No timer is currently enabled for a business pilot. Sleeping laptops, blackouts, expired credentials and stopped tunnels interrupt coverage.

## Daily review and exit

Record a named review for the current or previous UTC day:

```sh
python3 /opt/openwaf-pilot/pilot.py review --manifest /etc/openwaf-pilot/manifest.json --database /var/lib/openwaf-pilot/evidence.db --day YYYY-MM-DD --reviewer 'Operator name' --evidence 'Restricted review record reference' --clear
```

Use `--clear` only after reviewing business workflow results, false positives, unexplained passes/blocks, security events, gateway/storage/export health, load/headroom and any authentication or policy changes. Omit it for an unresolved blocking finding. Reviews append; the latest recorded decision for that day applies. Historical review backfill beyond yesterday is unavailable. A busy sample stream cannot replace human review.

`status` reports **observation_ready_for_review** only after at least 30 elapsed days in the current continuous healthy window, fresh evidence within 180 seconds, and clear reviews for every UTC date touched by that window. Failed samples, samples lasting over 60 seconds or inter-sample coverage gaps over 180 seconds restart the continuous healthy interval. Backward clock movement rejects samples; detected wall-clock jumps during probes fail the observation. Keep host time synchronized and investigate time changes. All failed samples and gaps remain counted. This is a conservative local gate, not independent attestation that traffic or the host was uncompromised.

Before M4 exit, additionally record a successful backup restore and actual upgrade/rollback drill for the deployed artifact and configuration; demonstrate alert delivery and incident response; review measured capacity against actual traffic; and resolve release-blocking findings from independent security review. Review application errors and false positives with the application owner. A short lab run, a synthetic month in unit tests or `observation_ready_for_review` alone cannot close M4 or justify a business-ready claim.
