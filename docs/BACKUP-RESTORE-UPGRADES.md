# Offline backup, upgrade and rollback

The 5 November business-qualification candidate changes schema-2 forwarding to
preserve the validated application HTTP Host; schema 1 keeps target-address Host.
Review schema-2 backends that expected an internal target hostname before
upgrading. Their virtual-host/allowed-host configuration must accept the intended
public application authority. Keep canonical/allowed-host checks enabled. The
offline upgrade check cannot prove HTTP workflow compatibility; run the deployed
application checks as well. [Compatibility finding and evidence](M4-BUSINESS-RESULTS.md)

The `waf-admin` tool creates verified recovery sets, restores them into **new** directories, and rehearses a trusted candidate on disposable copies. It never overwrites an existing restore destination or switches a running service. Recovery sets include the entire application deployment and policy history, sender database, administration journal, and optionally a dedicated reference collector database. A sender-only backup can explicitly retain an existing external collector instead.

The current tool automatically includes the default `<policy path>.audit.jsonl` when present. Supply `-audit-file` for a custom journal. Recovery sets made before journaling remain readable. Restored journals use `state/policy.json.audit.jsonl`. Upgrade rehearsal requires audit-format support when a journal is present and verifies that records remain unchanged. Use the current recovery tool for checkpoints containing a journal. Service packaging, certificate renewal and stopped-service journal archival are described in [Linux operations](LINUX-OPERATIONS.md).

An audit-export-bound journal additionally requires candidate audit-export capability 1. Rehearsal preserves its destination binding and keeps delivery paused. The independent audit receiver is outside this recovery set. Preserve its current durable deduplication receipts separately, including when restoring an older sender checkpoint. Keep one active source copy and retain the failed original offline. `waf-admin audit-export` can replay a stopped archive read-only. [Audit receiver and replay contract](AUDIT-EXPORT.md)

Build from the project root:

```powershell
go build -o bin/waf-admin.exe ./cmd/waf-admin
go build -o bin/openwaf-next.exe ./cmd/waf-server
```

On Linux, use the same Go commands with executable names without `.exe`. Use absolute paths in service configuration when selecting a restored state directory.

## Prepare a checkpoint

1. Record the exact service commands/options, environment-secret sources, certificate/key locations and receiver address. Preserve trusted previous executables. The recovery set does not automatically discover startup options, TLS keys, environment credentials, service-manager configuration or firewall rules.
2. Stop the WAF first, allowing final event writes and overload summaries to flush. Then stop its reference collector and wait for its active commits to finish. Do not kill a healthy service to take an ordinary backup.
3. Choose a private local destination that does not exist. New trees use private file modes on Unix and a protected current-user/SYSTEM DACL on Windows. Backups contain plaintext policy and security metadata; `-admin-token-file` explicitly includes plaintext administrator credentials. Use encrypted storage and separately protected off-site copies as appropriate. Checksums detect inconsistency, not an attacker who can replace both data and manifest.

For a local deployment without export:

```powershell
./bin/waf-admin.exe backup `
  -config config/policy.json `
  -event-db config/policy.json.events.db `
  -binary bin/openwaf.exe `
  -admin-token-file config/admin-token.txt `
  -out backups/before-upgrade
```

The binary and administrator file are optional explicit inputs. If export uses a dedicated reference collector, add its database:

```powershell
./bin/waf-admin.exe backup `
  -config config/policy.json `
  -event-db config/policy.json.events.db `
  -collector-db data/collector.db `
  -binary bin/openwaf.exe `
  -out backups/coordinated-before-upgrade
```

Preserve the matching collector executable and its credentials/settings separately. This tool's bundled executable option is for the WAF. Recovery checks use the candidate WAF's compiled-in reference-collector implementation to qualify the supported receiver database format; they do not independently certify an unrelated collector executable.

An export-bound sender requires either `-collector-db` or **explicit** `-external-collector`. The latter means only sender state is captured: the existing external receiver must keep its current durable deduplication receipts. The tool cannot verify or restore that external receiver. Its totals can remain ahead of a restored sender's earlier counters because post-checkpoint history is intentionally retained there. Do not independently restore an old receiver backup under that scope.

Use `-policy-only` only when deliberately omitting security evidence, for example before a first startup when no event database exists. A missing database is otherwise an error, not an implicit empty backup.

## What is verified

```powershell
./bin/waf-admin.exe verify -backup backups/before-upgrade
./bin/waf-admin.exe inspect -config config/policy.json -event-db config/policy.json.events.db
```

Backup/inspect take nonblocking maintenance leases on the policy and each included database. The gateway, sender and reference collector now hold matching process leases. Presence of a `.lock` file is not evidence of a live process; do not delete lock files to bypass a refusal. Stop older binaries as well: programs that do not implement the new database lease cannot be identified by that lease alone.

SQLite sources are opened read-only and held in shared read transactions during copying. Only clean DELETE-journal databases with 4096-byte pages are supported. Nonempty rollback/WAL/SHM sidecars, unknown/newer schemas, failed integrity checks or unsupported sizes are refused. After a crash, recover using the known-compatible service on a protected copy or the established recovery procedure, then cleanly stop it. Do not delete a journal to make verification pass. This is an offline facility, not an online or filesystem-volume snapshot. SQLite describes the [shared-lock copy procedure](https://www.sqlite.org/backup.html) and [risks of inconsistent database/journal copies](https://www.sqlite.org/howtocorrupt.html).

The manifest records format version, coverage, private-data classification, per-file SHA-256/size and logical checkpoint digests. Verification checks active policy compilation, the entire committed history chain, orphan revision reservations, database integrity and export accounting. Candidate rehearsal additionally compiles every restorable historical policy. Unreachable partial snapshot files remain byte-for-byte preserved so their revision numbers are not reused.

For a coordinated reference receiver, every receipt is either acknowledged by the sender or matches a still-pending outbox entry. Counts, occurrence totals and pending payloads must reconcile. A receiver missing an already-acknowledged event is refused. A receiver shared with other source IDs is refused because a coordinated rollback requires all its senders. This tool handles one sender deployment per recovery set. Preserve a shared external receiver independently.

Bundles are bounded directories, not executable archives: policy/snapshots at most 256 KiB each, at most 1,000 snapshots, each database at most 1 GiB, optional Go executable at most 256 MiB, optional administrator credential at most 4 KiB, and total content at most 3 GiB. Sender/outbox inspection is bounded to 100,000 rows each and receiver inspection to 2,000,000 rows. Symlinks, unknown members, unsafe paths, missing files, invalid scope and changed hashes are rejected. Filesystem ACLs/ownership/timestamps/alternate streams are not preserved; restored access is assigned to the current operator. Network filesystems and power-loss publication are unqualified.

Files are copied to a private staging tree, flushed and verified before the final directory rename. Failed operations leave no published checkpoint. A process kill can leave a private `.openwaf-recovery-*` staging tree without a valid published manifest; keep it private, investigate it and remove it manually when safe. A retry uses a new staging tree and does not reuse incomplete content.

## Rehearse an upgrade

```powershell
./bin/waf-admin.exe upgrade-check `
  -backup backups/before-upgrade `
  -candidate bin/openwaf-next.exe
```

This verifies the checkpoint, queries the candidate's `-capabilities-json` interface, checks its policy/database ranges, and restores a temporary working copy. A guarded `-upgrade-probe` performs real startup/migration on that copy, with no listeners and export paused. It must preserve policy/history, event records, pending deliveries, receipt data and delivery counters. The tool independently reinspects the result and records the executable's SHA-256, before/after schemas and changes. Original state and the immutable checkpoint are unchanged. A marked disposable copy is required; invoking the probe directly on an ordinary state path is rejected.

Rehearsals use the largest supported retention/size bounds to avoid normal retention obscuring upgrade data preservation. This does **not** prove that the production startup limits, ports, certificates, credentials or application traffic will work. Restore the recorded production settings separately and run the deployment's health/traffic checks. A candidate that purges records, changes policy, damages history or cannot support the saved schema fails rehearsal. Operation deadlines default to five minutes (`-timeout`, 1 second–30 minutes); compiler work checks cancellation between bounded policy compilations.

Only use trusted executables. Rehearsal is not a sandbox. The child runs in a temporary working directory with a minimal environment that excludes administrator, export and cloud credentials; it retains the operator's OS access. Candidate output is bounded and its process is terminated on timeout/output overflow. Unknown older binaries without the capability/probe interface are refused for automatic qualification. No compatibility is inferred from a filename or an unversioned module label.

If the rehearsal passes, deploy using the normal service-management procedure: keep the checkpoint and previous binary, update the configured executable, start the receiver with its correct state, then start the WAF with the correct policy/event paths, credentials and export settings. Verify the active policy revision, clean traffic, an isolated attack fixture, storage health and export backlog. The tool does not perform this live cutover.

## Restore and prepare rollback

```powershell
./bin/waf-admin.exe restore `
  -backup backups/before-upgrade `
  -out recovery/restored-checkpoint
```

The output layout is `state/policy.json`, matching `.history`, `state/events.db`, optional `state/collector.db`, optional `private/admin-token.txt` and optional `bin/waf-server[.exe]`, plus the checkpoint manifest. `restore` and `verify` do not execute the bundled binary. Restoring into an existing directory is always refused. Once the restored state has been started and changed, inspect/back it up as a new state rather than expecting it to remain identical to its original manifest.

On Linux, root-run restore intentionally creates a root-private parent. Before
service activation, assign the active state to the **target host's** service
UID/GID and grant service-group traversal on its parent directories. Keep state
directories/files restricted and grant access only along the paths used by the
service. If running the restored executable directly, its parent directories
must also be traversable. Keep the immutable backup and private credentials
root-private; do not recursively make the recovery bundle world-readable.
Check policy, TLS key and authentication configuration readability as the actual
unprivileged service account before starting. Systemd `LoadCredential` can keep
source credential files root-only. Re-render service paths for the new host.
The [fresh-host drill](M4-FRESH-HOST-RECOVERY.md) exercises these assignments,
replacement of the fresh installer credential and current-receiver migration.

To qualify a trusted rollback executable and prepare its state in one operation:

```powershell
./bin/waf-admin.exe rollback `
  -backup backups/before-upgrade `
  -out recovery/rollback-ready `
  -candidate path/to/trusted-previous-waf.exe
```

Without `-candidate`, rollback executes the WAF binary explicitly bundled in that trusted checkpoint. It first rehearses that binary, then restores the original checkpoint into the new directory. `prepared: true` means the recovery set is prepared, not activated. It does not switch services, replace current files or roll a database schema backward in place.

Before switching, stop both affected processes again and optionally preserve a fresh post-failure checkpoint for investigation. For a coordinated recovery, point **both** services at the databases from the same restored set. Start the matching receiver with its original token/TLS/listener settings, then the WAF. A typical sender invocation is:

```powershell
# Restore secrets from the established secret source, not from reports.
# If explicitly backed up, read the private administrator file into OPENWAF_ADMIN_TOKEN.
$env:OPENWAF_ADMIN_TOKEN = (Get-Content recovery/rollback-ready/private/admin-token.txt -Raw).Trim()
./recovery/rollback-ready/bin/waf-server.exe `
  -config recovery/rollback-ready/state/policy.json `
  -event-db recovery/rollback-ready/state/events.db
```

Add the original `-event-export-url`, environment export token and all nondefault resource/retention/TLS settings when applicable. A pending outbox retains its original source and destination binding; do not silently redirect it to a new receiver. For external-current-collector scope, keep the receiver's current receipt store. Verify policy, events, health and deduplicated replay after switching. Restoring a checkpoint deliberately chooses its recovery point and can discard newer local changes; there is no automatic merge of two timelines.

## Qualification and remaining limits

An existing `policy.json.accounts.json` is automatically included, including policy-only checkpoints. Recovery metadata preserves its format, revision, account count and file hash. Candidate checks require account format 1 when present and traffic-control format 1 when any committed policy uses it. A checkpoint restore restores its account/password state. Policy-only history rollback preserves the current account store. Reconcile later account revocations after a full checkpoint restore. [Traffic and access contract](TRAFFIC-AND-ACCESS.md)

Policy schema 2 is separate from sender database schema 2. Candidate checks require support for every policy schema in committed history, including schema-2 ancestors after a legacy policy rollback. Preserve a pre-migration checkpoint for a schema-1-only policy executable. The multi-application recovery test rehearses the preserved previous Windows executable against that earlier checkpoint and refuses it against migrated state. [Application migration](APPLICATIONS.md), [Validation](VALIDATION-APPLICATIONS.md)

Windows and Linux tests exercise the CLI workflow and an actual current server executable, including capability checks, private-copy migration, restore, bundled-binary rehearsal, tamper/traversal/missing-state rejection, live policy/sender/collector leases, pending-export replay and refusal of a stale acknowledged receiver. A forced-kill test interrupts backup after its first copied member and proves that no partial final checkpoint appears; the original state stays intact and retry succeeds.

The schema-1→2→restored-schema-1 drill also uses `tools/recoverycheck`, a **test-only** strict schema-1 executable. It is not a historical released WAF and compiles policy using the current pinned engine. This proves the storage/rollback procedure and downgrade guard; it does not qualify arbitrary historic engine releases. A real prior binary must pass its own supported rehearsal or a separately recorded isolated qualification before deployment. Unknown future database versions are refused without modifying the source.

These recovery tools cover the present format and local filesystem. Native Ubuntu 24.04 qualification includes actual r5/r6 service-manager cutover, live rollback and three abrupt guest poweroffs recovering acknowledged state in 42–43 seconds. The exact build hashes and workload are recorded in [M2 qualification](M2-QUALIFICATION.md). Online backups, authenticated/encrypted bundle formats, all-sender shared-receiver snapshots, secret-manager export, arbitrary historical binary compatibility, physical host/controller power failure and production deployment RTO/RPO measurements remain separate work. SHA-256 and SQLite checks do not protect a checkpoint against a host attacker who can rewrite it.
