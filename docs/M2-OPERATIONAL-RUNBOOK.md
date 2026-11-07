# Linux amd64 operational qualification

This workflow uses an owned disposable VirtualBox guest created by `scripts/qualify-virtualbox.py`. It changes only that guest's qualification services and state. The host driver, `scripts/qualify-m2-operational.py`, sends TLS traffic from the workstation through loopback-bound SSH forwards. The gateway, mock backend and two reference receivers are separate guest processes. RSS, CPU, descriptors and thread counts are read from the gateway PID in `/proc`.

## Reproduce the reference profile

First complete the fresh-VM workflow and retain its passing VM directory. Keep a trusted previous and current package with their SHA-256 sidecars. The driver verifies both sidecars before starting the guest.

```powershell
python scripts/qualify-m2-operational.py `
  --vm-dir artifacts/m2-vms/<passing-amd64-vm-directory> `
  --current artifacts/openwaf-m2-20261103-r6-linux-amd64.tar.gz `
  --previous artifacts/openwaf-m2-20261103-r5-linux-amd64.tar.gz `
  --disposable-vm
```

`--smoke` substitutes ten-second ramp phases and a twenty-second steady phase, followed by one hard reset and the complete upgrade/rollback procedure. A smoke result verifies harness operation. M2's reference sizing gate requires the full two-hour steady phase and three hard resets.

Use `--smoke --functional-only` for supplementary distribution compatibility. This runs response, interruption and actual binary upgrade/rollback checks without a sizing claim. Fixture binaries, helper files, service units and boot links are synchronized before services start. No global sync runs between acknowledged workload mutations and a power cut.

The reference configuration uses one vCPU, 2 GiB VM RAM, two hostname-routed PL1 enforcing applications and 1-MiB request/response policy limits. Packaged admission defaults are 64 concurrent requests, 256 connections and a 256-MiB buffer budget. The fixture sets a ten-second request deadline and retains the five-second local commit deadline. The sender uses its default 64-MiB database and 10,000-row retention ceiling. The dedicated event and audit receivers have 512-MiB and 128-MiB physical quotas. All three services retain FULL-synchronous storage.

Eight external client workers maintain TLS connections with certificate verification and the correct application SNI/Host. The mixed workload has 30% harmless XSS detection fixtures, 10% benign 16-KiB JSON submissions and ordinary query requests. Payloads are never executed. The pacing loop runs independently from the SSH sampler. Short 25/50/100-request-per-second probes precede the two-hour 25-request-per-second profile. Short higher-rate probes are exploratory. Their failure cannot establish the server's universal maximum because the client, SSH transport, VM CPU and reference storage all influence achieved throughput.

The required profile has zero incorrect responses or network errors, p95 below one second, gateway peak RSS below 512 MiB, at least 90% of the scheduled request rate, one unchanged gateway PID/start identity and healthy final storage/export. The report records gateway CPU seconds and average one-vCPU utilization. Gateway RSS includes its own startup/ramp high-water mark. Client, backend and receiver RSS/CPU are excluded from that process measurement. The VM's CPU and physical host/storage remain shared resources.

## Abrupt interruption

Before each cut, the driver activates an acknowledged policy change, sends blocked test requests and saves a synced acknowledgement snapshot on the host. It records event payload hashes, the administration prefix, policy revision and account-store hash. The independent receivers must already contain those snapshot records.

The guest helper arms a test-only SQLite trigger that holds an insertion transaction. The driver requires a dirty sender rollback journal and an in-flight request, then invokes VirtualBox `controlvm poweroff`. It restarts the guest, removes the trigger and verifies the acknowledged snapshot against the local store and durable receiver copies. The interrupted request is unacknowledged and may roll back. Recovery must complete within 180 seconds.

The test qualifies abrupt guest power removal on the declared virtual storage stack. Physical host/controller failure, faulty flush implementations and unrelated hardware remain outside that result.

## Concrete upgrade and rollback

The procedure executes the actual packaged r5 server against the fixture, verifies a local viewer login, stops the sender and its dedicated event receiver, and creates a coordinated checkpoint containing the r5 executable. The current r6 administration tool verifies and rehearses the actual r6 candidate on a private restored copy. The fixture then switches its service to the r6 executable and verifies checkpoint records and login through the running service.

After a distinct post-checkpoint mutation, the procedure preserves a separate post-upgrade recovery set. `waf-admin rollback` prepares the original checkpoint using its bundled r5 executable. The running sender and coordinated event receiver switch to the restored state. The procedure verifies r5's actual `/proc/<pid>/exe` hash, checkpoint event/audit/account state, the original policy revision and viewer login. The original checkpoint manifest hash must remain unchanged.

The independent administration receiver retains its current receipt history throughout rollback. Selecting an earlier checkpoint deliberately creates a different active timeline. Preserve the newer source state and identify the chosen checkpoint and administration terminal hashes in operator records. The receiver's immutable record IDs retain evidence from later timelines. R5 retains its previously documented writer limitations, while r6 is the reference operating build. This procedure qualifies that specific local-build pair.

## Evidence and cleanup

Each run writes `artifacts/m2-operational-<id>/result.json`, command diagnostics and host-side acknowledged snapshots. Full reports contain bounded process/status samples, binary hashes, phase distributions, reset recovery times and upgrade/rollback outcomes. Failed attempts remain evidence.

The fixture archives an earlier owned qualification override and disables only that fixture's generated backend/receiver units before creating a new run. It preserves their state and checkpoints. The driver stops its services and powers off its owned guest when finished. VM disks, synthetic secrets and host SSH keys remain private under ignored artifacts, subject to the existing cleanup-policy restriction. Retain only redacted evidence when publishing results.
