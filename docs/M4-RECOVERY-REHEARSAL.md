# Corrected-build recovery rehearsal

## Exact upgrade and rollback pair

The 4 November 2026 functional operational run passed on the owned Ubuntu 24.04
amd64 VirtualBox guest, with one vCPU and 4 GiB RAM:

- Current server SHA-256: `3f67d19f2d793a3afa8eca340f14e0bc7d998e4c3affa636dd41924ccc84fa81`.
- Previous M3 r7 server SHA-256: `40ec989918bb8976a4d464ee31220e7e92f46aeadb94b5c5d72e3249104421ae`.
- Current archive: `artifacts/rule-candidate-71b7c654bab5/openwaf-rule-candidate-linux-amd64.tar.gz`.
- Evidence: `artifacts/m2-operational-e622d9f8/result.json`.

The runner checks archive checksum sidecars before use. This is a functional
recovery run, not a repeat capacity measurement. The runner now records CPU and
memory from VirtualBox metadata; its previous hardcoded 2-GiB label was stale.

Three abrupt guest poweroffs interrupted an active SQLite journaled request.
Recovery took 47.70, 45.38 and 47.11 seconds. Each interruption verifies the
previously acknowledged event payloads, policy/account state, audit records and
independent receiver receipts. The respective event/audit record counts were
6/87, 9/100 and 12/113. Four passkey/MFA assertions and scoped-token/application
assignment checks passed across activation and recovery.

The actual previous-to-current upgrade passed, including the immutable backup
and private-copy upgrade check. Login passed before upgrade, after upgrade and
after rollback. A later revision 7 timeline was preserved separately before
coordinated rollback to the checkpoint's revision 2. This intentionally switches
recovery points; it does not promise zero loss of changes after that checkpoint.
The independent audit receiver retains its newer receipts. The baseline
checkpoint precedes attack traffic and contains zero security events; event
preservation under interruption is covered by the later acknowledged snapshots.

## Replacement deployment scope

The corrected replacement run passed:
`artifacts/m2-operational-5a851e12/result.json`. It verified six security events,
96 audit records and revision 4 after restore, all six deployment assets, six
service/environment definitions, and a real post-restore passkey/MFA proof with
scoped-token/application isolation. Subsequent rollback also passed. Its single
additional interruption is a short functional repetition; the separate first
run supplies the three-interruption evidence. The independent checker
`scripts/check-m4-recovery-evidence.py` accepts the two successful reports and
their archived harness hashes. The VM returned to `poweroff`; evidence remains.

`scripts/qualify-m4-recovery.py` adds a separate drill using new state, binary
and deployment-asset directories on the same VM. It preserves TLS certificate
and key, administrator/export credentials, authentication configuration and
service/environment definitions. It verifies byte hashes, uses the recovery
tool's restored executable, and checks state/receipts and real authentication
after activation. Private deployment files and command logs are retained in the
owned fixture and must not be published.

The first replacement attempt, `artifacts/m2-operational-706906b5`, is retained
as failed. It passed its interruption check, then stopped because the harness
assumed the base unit lived in `/etc/systemd/system`. The corrected helper
queries systemd's `FragmentPath` and requires the returned file to exist; it
does not silently omit service-manager configuration from recovery evidence.

This is not a fresh-host restore: the base operating system, installed packaged
unit, network environment, application backend and independent audit receiver
remain available. Recreating those dependencies on a fresh host, real operator
alert delivery, deployed storage/certificate fault drills, independent review
and the 30-day business pilot remain open. See [recovery boundaries](BACKUP-RESTORE-UPGRADES.md).

## Host-preservation candidate, 5 November

The current candidate repeats the complete functional rehearsal in one combined
run: `artifacts/m2-operational-d3cee4f8/result.json`. This contains all three
interrupted writes and the replacement-directory restore; the independent
checker accepts that same report as both its full and replacement inputs.

- Current server: `cef0916699fa8adef803c46e74d2a73f995156b15a550f5304283a0d3216794f`.
- Previous server: `3f67d19f2d793a3afa8eca340f14e0bc7d998e4c3affa636dd41924ccc84fa81`.
- Actual upgrade and rollback, previous/current/rollback login, and all three
  interrupted-write recoveries pass. Recovery times: 43.66, 43.42 and 43.07 s.
- Current-build replacement verifies 12 security events, 122 audit records and
  revision 6, including independent receipts and the copied TLS, credential and
  authentication assets. Five passkey/MFA/scoped-authorization proofs pass
  across activation, interruptions and current-build restoration.
- The post-checkpoint revision 7 timeline is preserved before rollback to
  revision 2. This restores the earlier account/factor/revocation state too;
  reconcile later security changes before exposing a restored deployment.

The two selected archives have identical filenames. The runner now gives each
an independent nonce-scoped guest path and compares its extracted executable
hash against the host-selected archive before running checks. A same-filename
copy must not silently turn an upgrade rehearsal into a same-binary restart.
Earlier rehearsals with differently named archives remain scoped to their
recorded identities.

Verification: `artifacts/m4-host-preservation-recovery-verification-20261105.json`.
The verifier source is preserved as
`artifacts/m4-host-preservation-recovery-verifier-20261105.py`. Collision,
identity, interruption, asset-permission, event and login proof mutations were
rejected. This is still replacement-directory recovery on the same VM, not a
fresh-host restore. A later separate clean-OS drill now passes for this candidate:
[fresh-host evidence](M4-FRESH-HOST-RECOVERY.md). That drill restores WAF and
receiver state with controlled backends; business-database recovery, deployed
alert routing and independent review remain open.
