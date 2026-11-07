# Recovery qualification — 2 November 2026

The recovery tools were tested on Windows amd64 and Linux amd64 under WSL using native temporary directories. All drills used synthetic, isolated state. The existing project's active policy also compiles with the new binary; no production backup, migration or cutover was performed during development.

| Check | Evidence |
|---|---|
| Offline private checkpoint, checksum verification and restore | Backup/verify/restore API and executable CLI tests |
| Running policy, sender or receiver cannot be copied | Process/maintenance lease tests |
| All committed history and orphan reservations survive | An unreachable partial revision 99 remains preserved; the first post-restore policy update allocates revision 100 |
| Pending exports survive local retention and coordinated restore | Four committed-but-unacknowledged receipts, one retained local event; restore/replay produces exactly four receiver records/occurrences |
| Stale acknowledged receiver is refused | Removing an acknowledged receipt and adjusting receiver totals still fails the sender/receiver checkpoint reconciliation |
| Actual current candidate migrates only a copy | Rehearsal with the compiled waf-server moves schema 1 to 2 without changing event payloads or the original backup |
| Downgrades require the earlier checkpoint | A strict executable schema-1 reader refuses schema 2; restoring the pre-upgrade snapshot makes schema 1 readable again |
| Bundled-binary and explicit-candidate rollback preparation | Executable CLI and API drills prepare a new state directory after successful rehearsal |
| Interrupted backup cannot publish a partial final checkpoint | A child process is killed after its first copied file; the source is unchanged, final destination is absent, and retry verifies successfully |
| Competing restores cannot replace each other | Four concurrent restores yield exactly one successful, independently verified destination using native no-replace publication |
| Corruption, unsafe members and unsupported state are refused | Changed hash, unlisted/traversal member, unknown schema, recovery sidecar and symlink cases |
| A probe cannot directly migrate an ordinary state path | A matching private-copy marker is required before startup/migration |

Windows cannot create test symlinks on this host, so that construction case is skipped there; Linux executes and passes it. Subprocess helper entry points are intentionally skipped in ordinary parent discovery and are executed by their corresponding forced-kill tests. Executable integration cases require the candidate/admin/legacy fixture paths; CI builds and supplies them on both platforms.

The legacy executable in `tools/recoverycheck` is deliberately a **schema-1 compatibility fixture**, not an old released WAF. It uses the current pinned engine to compile policy and has no serving mode. These tests qualify the storage recovery procedure and incompatibility guard. They do not establish compatibility with arbitrary historical engine binaries. Older real builds lacking the new capability interface require separately recorded qualification and are refused by automatic rehearsal.

Evidence is retained in `artifacts/recovery-tooling-tests.log`, `artifacts/recovery-tooling-linux-tests.log` and `artifacts/operations-all-tests.log`. Browser checks pass, and the post-change collector-outage/restart smoke soak (`artifacts/soak-recovery-leases.json`) reconciled all 409 security occurrences with zero drops or invariant failures. The previous ten-minute delivery runs remain separate evidence; they were not rerun as ten-minute tests for this operations increment.

Go tests and vet pass. Race instrumentation remains configured in Linux CI; this desktop/WSL environment does not provide the required local C toolchain. No power-loss, network-filesystem, online-backup, secret-manager export or live service cutover qualification is claimed. See the [recovery runbook](BACKUP-RESTORE-UPGRADES.md) for exact commands, coverage, privacy and restore limitations.
